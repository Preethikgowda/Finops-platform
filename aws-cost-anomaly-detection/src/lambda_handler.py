"""AWS Lambda Handler for Cost Anomaly Detection.

Orchestrates the full pipeline: fetch AWS costs → analyze for anomalies →
invoke Bedrock for root-cause analysis → query Elasticsearch for context →
send Slack alert. Implements DynamoDB-based idempotency so repeated
invocations on the same day are safe and do not re-send duplicate alerts.
"""

import json
import logging
import os
import time
import uuid
from dataclasses import asdict
from datetime import date, timezone, datetime
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

from bedrock_agent import BedrockAnalysisResult, invoke_bedrock_analysis
from cost_analyzer import AWSException, CostDataError, run_cost_analysis
from elasticsearch_client import (
    ElasticsearchException,
    build_client,
    extract_cost_values,
    health_check,
    query_deployment_events,
    query_historical_costs,
    query_infrastructure_changes,
)
from slack_notifier import SlackException, send_anomaly_alert

# ---------------------------------------------------------------------------
# Logging — structured JSON for CloudWatch Insights
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": %(message)s}',
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

load_dotenv()  # No-op in Lambda; useful for local development


def _require_env(name: str) -> str:
    """Return an environment variable value or raise on missing.

    Args:
        name: Environment variable name.

    Returns:
        String value of the environment variable.

    Raises:
        EnvironmentError: When the variable is absent or empty.
    """
    value = os.environ.get(name, "").strip()
    if not value:
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set. "
            "Set it in the Lambda configuration or .env file."
        )
    return value


def _get_env(name: str, default: str = "") -> str:
    """Return an environment variable value with a fallback default.

    Args:
        name: Environment variable name.
        default: Value to return if the variable is absent.

    Returns:
        String value of the environment variable or ``default``.
    """
    return os.environ.get(name, default).strip()


class Config:
    """Validated configuration loaded from environment variables."""

    def __init__(self) -> None:
        self.aws_region: str = _get_env("AWS_REGION", "us-east-1")
        self.es_host: str = _require_env("ES_HOST")
        self.es_port: int = int(_get_env("ES_PORT", "9200"))
        self.es_scheme: str = _get_env("ES_SCHEME", "https")
        self.es_username: str = _get_env("ES_USERNAME", "")
        self.es_password: str = _get_env("ES_PASSWORD", "")
        self.es_api_key: str = _get_env("ES_API_KEY", "")
        self.es_ca_certs: str = _get_env("ES_CA_CERTS", "")
        self.es_index_prefix: str = _get_env("ES_INDEX_PREFIX", "aws-costs")
        self.es_deploy_index: str = _get_env("ES_DEPLOY_INDEX_PREFIX", "deployment-logs")
        self.es_infra_index: str = _get_env("ES_INFRA_INDEX_PREFIX", "infra-events")
        self.es_verify_certs: bool = _get_env("ES_VERIFY_CERTS", "true").lower() != "false"
        self.slack_webhook_url: str = _require_env("SLACK_WEBHOOK_URL")
        self.bedrock_model_id: str = _get_env(
            "BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0"
        )
        self.cost_threshold_pct: float = float(_get_env("COST_THRESHOLD_PCT", "15.0"))
        self.dashboard_url: str = _get_env("COST_DASHBOARD_URL", "")
        self.dynamodb_table: str = _get_env("DYNAMODB_TABLE", "cost-anomaly-idempotency")
        self.rolling_window_days: int = int(_get_env("ROLLING_WINDOW_DAYS", "7"))
        self.es_historical_days: int = int(_get_env("ES_HISTORICAL_DAYS", "30"))

    def log_summary(self) -> None:
        """Log non-secret configuration values for audit trail."""
        logger.info(
            "Configuration loaded",
            extra={
                "aws_region": self.aws_region,
                "es_host": self.es_host,
                "es_port": self.es_port,
                "es_index_prefix": self.es_index_prefix,
                "bedrock_model_id": self.bedrock_model_id,
                "cost_threshold_pct": self.cost_threshold_pct,
                "rolling_window_days": self.rolling_window_days,
                "dynamodb_table": self.dynamodb_table,
            },
        )


# ---------------------------------------------------------------------------
# DynamoDB idempotency
# ---------------------------------------------------------------------------

def _check_idempotency(table_name: str, execution_date: str, region: str) -> bool:
    """Check whether today's analysis has already been completed.

    Args:
        table_name: DynamoDB table name for idempotency records.
        execution_date: Date string (YYYY-MM-DD) used as the partition key.
        region: AWS region for DynamoDB client.

    Returns:
        ``True`` if a record already exists (analysis already ran today).
    """
    try:
        dynamodb = boto3.resource("dynamodb", region_name=region)
        table = dynamodb.Table(table_name)
        response = table.get_item(Key={"execution_date": execution_date})
        exists = "Item" in response
        if exists:
            logger.info(
                "Idempotency check: analysis already completed for %s", execution_date
            )
        return exists
    except (ClientError, BotoCoreError) as exc:
        logger.warning(
            "Could not check idempotency table (proceeding anyway): %s", exc
        )
        return False


def _record_execution(
    table_name: str,
    execution_date: str,
    analysis_id: str,
    region: str,
    result_summary: dict[str, Any],
) -> None:
    """Persist an idempotency record to DynamoDB.

    Args:
        table_name: DynamoDB table name.
        execution_date: Date string (YYYY-MM-DD) used as the partition key.
        analysis_id: Unique ID for this execution.
        region: AWS region for DynamoDB client.
        result_summary: Summary of analysis results to store alongside the key.
    """
    try:
        dynamodb = boto3.resource("dynamodb", region_name=region)
        table = dynamodb.Table(table_name)
        table.put_item(
            Item={
                "execution_date": execution_date,
                "analysis_id": analysis_id,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "ttl": int(time.time()) + (90 * 24 * 3600),  # 90-day TTL
                **result_summary,
            }
        )
        logger.info(
            "Idempotency record saved",
            extra={"execution_date": execution_date, "analysis_id": analysis_id},
        )
    except (ClientError, BotoCoreError) as exc:
        logger.warning(
            "Could not write idempotency record (non-fatal): %s", exc
        )


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

def _stage_fetch_historical_costs(cfg: Config) -> list[float]:
    """Fetch and extract historical daily costs from Elasticsearch.

    Returns an empty list (safe fallback) when Elasticsearch is unavailable.

    Args:
        cfg: Validated configuration object.

    Returns:
        List of daily cost values (USD) over the rolling window.
    """
    t0 = time.monotonic()
    try:
        es = build_client(
            host=cfg.es_host,
            port=cfg.es_port,
            scheme=cfg.es_scheme,
            username=cfg.es_username or None,
            password=cfg.es_password or None,
            api_key=cfg.es_api_key or None,
            ca_certs=cfg.es_ca_certs or None,
            verify_certs=cfg.es_verify_certs,
        )
        health_check(es)
        docs = query_historical_costs(
            client=es,
            index_prefix=cfg.es_index_prefix,
            days=cfg.es_historical_days,
            max_results=cfg.rolling_window_days,
        )
        costs = extract_cost_values(docs)
        logger.info(
            "Historical costs fetched from ES",
            extra={
                "num_days": len(costs),
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
            },
        )
        return costs
    except ElasticsearchException as exc:
        logger.warning(
            "Could not fetch historical costs from ES (will use empty list): %s", exc
        )
        return []


def _stage_fetch_deployment_context(
    cfg: Config,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch deployment events and infrastructure changes from Elasticsearch.

    Returns empty lists on failure so the pipeline continues without ES.

    Args:
        cfg: Validated configuration object.

    Returns:
        Tuple of (deployment_events, infra_changes).
    """
    t0 = time.monotonic()
    try:
        es = build_client(
            host=cfg.es_host,
            port=cfg.es_port,
            scheme=cfg.es_scheme,
            username=cfg.es_username or None,
            password=cfg.es_password or None,
            api_key=cfg.es_api_key or None,
            ca_certs=cfg.es_ca_certs or None,
            verify_certs=cfg.es_verify_certs,
        )
        health_check(es)
        deployments = query_deployment_events(
            client=es, index_prefix=cfg.es_deploy_index
        )
        infra = query_infrastructure_changes(
            client=es, index_prefix=cfg.es_infra_index
        )
        logger.info(
            "Deployment context fetched from ES",
            extra={
                "deployment_events": len(deployments),
                "infra_changes": len(infra),
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
            },
        )
        return deployments, infra
    except ElasticsearchException as exc:
        logger.warning(
            "Could not fetch deployment context from ES (continuing without): %s", exc
        )
        return [], []


def _stage_bedrock_analysis(
    cfg: Config,
    cost_data: dict[str, Any],
    deployment_logs: list[dict[str, Any]],
) -> BedrockAnalysisResult:
    """Run Bedrock cost analysis, returning a fallback on failure.

    Args:
        cfg: Validated configuration object.
        cost_data: Cost metrics dictionary.
        deployment_logs: Recent deployment events.

    Returns:
        :class:`BedrockAnalysisResult` (may be a fallback response).
    """
    t0 = time.monotonic()
    result = invoke_bedrock_analysis(
        cost_data=cost_data,
        deployment_logs=deployment_logs,
        model_id=cfg.bedrock_model_id,
        region=cfg.aws_region,
    )
    logger.info(
        "Bedrock analysis complete",
        extra={
            "severity": result.anomaly_severity,
            "is_fallback": result.is_fallback,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "elapsed_ms": int((time.monotonic() - t0) * 1000),
        },
    )
    return result


def _stage_send_alert(
    cfg: Config,
    analysis_date: str,
    cost_result: Any,
    bedrock_result: BedrockAnalysisResult,
    deployment_events: list[dict[str, Any]],
    analysis_id: str,
) -> bool:
    """Send the Slack alert, returning False on failure (non-fatal).

    Args:
        cfg: Validated configuration object.
        analysis_date: Date string for the anomaly.
        cost_result: CostAnalysisResult object.
        bedrock_result: BedrockAnalysisResult object.
        deployment_events: List of deployment event dicts.
        analysis_id: Unique tracking ID.

    Returns:
        ``True`` if the alert was sent successfully.
    """
    t0 = time.monotonic()
    try:
        sent = send_anomaly_alert(
            webhook_url=cfg.slack_webhook_url,
            analysis_date=analysis_date,
            yesterday_cost=cost_result.yesterday_cost,
            baseline_cost=cost_result.baseline_cost,
            cost_delta=cost_result.cost_delta,
            percentage_increase=cost_result.percentage_increase,
            severity=bedrock_result.anomaly_severity,
            root_causes=bedrock_result.probable_root_causes,
            explanation=bedrock_result.explanation,
            recommendations=bedrock_result.recommendations,
            deployment_events=deployment_events,
            dashboard_url=cfg.dashboard_url,
            analysis_id=analysis_id,
        )
        logger.info(
            "Slack alert stage complete",
            extra={"sent": sent, "elapsed_ms": int((time.monotonic() - t0) * 1000)},
        )
        return sent
    except SlackException as exc:
        logger.error("Slack alert failed (non-fatal): %s", exc)
        return False


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------

def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda handler — cost anomaly detection pipeline entry point.

    Orchestration order:
    1. Validate configuration.
    2. Idempotency check via DynamoDB.
    3. Fetch yesterday's cost via Cost Explorer.
    4. Fetch historical costs from Elasticsearch for baseline.
    5. Run anomaly detection.
    6. If anomaly detected: fetch deployment context, run Bedrock, send Slack.
    7. Record execution in DynamoDB.
    8. Return CloudWatch-friendly response.

    Args:
        event: Lambda event payload (unused; triggered by EventBridge schedule).
        context: Lambda context object (provides request ID for tracing).

    Returns:
        Dict with ``statusCode``, ``body`` (JSON string), and ``executionTime``.
    """
    pipeline_start = time.monotonic()
    request_id = getattr(context, "aws_request_id", str(uuid.uuid4()))
    analysis_id = str(uuid.uuid4())[:8]
    execution_date = date.today().isoformat()

    logger.info(
        "Lambda handler started",
        extra={
            "request_id": request_id,
            "analysis_id": analysis_id,
            "execution_date": execution_date,
        },
    )

    metrics: dict[str, Any] = {
        "request_id": request_id,
        "analysis_id": analysis_id,
        "execution_date": execution_date,
    }

    # ------------------------------------------------------------------
    # 1. Load and validate configuration
    # ------------------------------------------------------------------
    try:
        cfg = Config()
        cfg.log_summary()
    except EnvironmentError as exc:
        logger.error("Configuration validation failed: %s", exc)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(exc), "request_id": request_id}),
            "executionTime": int((time.monotonic() - pipeline_start) * 1000),
        }

    # ------------------------------------------------------------------
    # 2. Idempotency check
    # ------------------------------------------------------------------
    if _check_idempotency(cfg.dynamodb_table, execution_date, cfg.aws_region):
        logger.info(
            "Analysis already completed for %s — skipping (idempotent run)",
            execution_date,
        )
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": f"Analysis already completed for {execution_date}. Skipping.",
                    "request_id": request_id,
                    "execution_date": execution_date,
                }
            ),
            "executionTime": int((time.monotonic() - pipeline_start) * 1000),
        }

    # ------------------------------------------------------------------
    # 3. Fetch historical costs from Elasticsearch
    # ------------------------------------------------------------------
    t0 = time.monotonic()
    historical_costs = _stage_fetch_historical_costs(cfg)
    metrics["es_historical_fetch_ms"] = int((time.monotonic() - t0) * 1000)

    # ------------------------------------------------------------------
    # 4 & 5. Fetch yesterday's cost and detect anomaly
    # ------------------------------------------------------------------
    t0 = time.monotonic()
    try:
        cost_result = run_cost_analysis(
            historical_costs=historical_costs,
            region=cfg.aws_region,
            threshold_pct=cfg.cost_threshold_pct,
        )
    except (AWSException, CostDataError) as exc:
        logger.error(
            "Cost analysis failed — cannot proceed: %s",
            exc,
            extra={"request_id": request_id},
        )
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(exc), "request_id": request_id}),
            "executionTime": int((time.monotonic() - pipeline_start) * 1000),
        }

    metrics["cost_fetch_ms"] = int((time.monotonic() - t0) * 1000)
    metrics.update(
        {
            "anomaly_detected": cost_result.anomaly_detected,
            "yesterday_cost_usd": cost_result.yesterday_cost,
            "baseline_cost_usd": cost_result.baseline_cost,
            "cost_delta_usd": cost_result.cost_delta,
            "percentage_increase": cost_result.percentage_increase,
        }
    )

    if not cost_result.anomaly_detected:
        logger.info(
            "No cost anomaly detected for %s (%.1f%% vs %.1f%% threshold)",
            cost_result.analysis_date,
            cost_result.percentage_increase,
            cfg.cost_threshold_pct,
        )
        _record_execution(
            cfg.dynamodb_table,
            execution_date,
            analysis_id,
            cfg.aws_region,
            {"anomaly_detected": False},
        )
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "No anomaly detected.",
                    "analysis_date": cost_result.analysis_date,
                    "yesterday_cost_usd": cost_result.yesterday_cost,
                    "baseline_cost_usd": cost_result.baseline_cost,
                    "percentage_increase": cost_result.percentage_increase,
                    "request_id": request_id,
                }
            ),
            "executionTime": int((time.monotonic() - pipeline_start) * 1000),
        }

    logger.info(
        "Anomaly detected! Cost %.1f%% above baseline. Proceeding with full analysis.",
        cost_result.percentage_increase,
    )

    # ------------------------------------------------------------------
    # 6. Fetch deployment context from Elasticsearch
    # ------------------------------------------------------------------
    t0 = time.monotonic()
    deployment_events, infra_changes = _stage_fetch_deployment_context(cfg)
    metrics["es_deployment_fetch_ms"] = int((time.monotonic() - t0) * 1000)
    metrics["deployment_events_count"] = len(deployment_events)
    metrics["infra_changes_count"] = len(infra_changes)

    # Combine deployment and infrastructure events for Bedrock
    all_events = deployment_events + infra_changes

    # ------------------------------------------------------------------
    # 7. Bedrock analysis
    # ------------------------------------------------------------------
    t0 = time.monotonic()
    cost_dict = {
        "yesterday_cost": cost_result.yesterday_cost,
        "baseline_cost": cost_result.baseline_cost,
        "cost_delta": cost_result.cost_delta,
        "percentage_increase": cost_result.percentage_increase,
        "analysis_date": cost_result.analysis_date,
    }
    bedrock_result = _stage_bedrock_analysis(cfg, cost_dict, all_events)
    metrics["bedrock_latency_ms"] = int((time.monotonic() - t0) * 1000)
    metrics["bedrock_severity"] = bedrock_result.anomaly_severity
    metrics["bedrock_is_fallback"] = bedrock_result.is_fallback
    metrics["bedrock_input_tokens"] = bedrock_result.input_tokens
    metrics["bedrock_output_tokens"] = bedrock_result.output_tokens

    # ------------------------------------------------------------------
    # 8. Send Slack alert
    # ------------------------------------------------------------------
    t0 = time.monotonic()
    slack_sent = _stage_send_alert(
        cfg=cfg,
        analysis_date=cost_result.analysis_date,
        cost_result=cost_result,
        bedrock_result=bedrock_result,
        deployment_events=deployment_events,
        analysis_id=analysis_id,
    )
    metrics["slack_alert_sent"] = slack_sent
    metrics["slack_latency_ms"] = int((time.monotonic() - t0) * 1000)

    # ------------------------------------------------------------------
    # 9. Record execution for idempotency
    # ------------------------------------------------------------------
    _record_execution(
        cfg.dynamodb_table,
        execution_date,
        analysis_id,
        cfg.aws_region,
        {
            "anomaly_detected": True,
            "severity": bedrock_result.anomaly_severity,
            "yesterday_cost_usd": str(cost_result.yesterday_cost),
            "percentage_increase": str(cost_result.percentage_increase),
            "slack_sent": slack_sent,
        },
    )

    execution_time_ms = int((time.monotonic() - pipeline_start) * 1000)
    metrics["total_execution_ms"] = execution_time_ms

    logger.info("Lambda pipeline complete", extra=metrics)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "message": "Cost anomaly detected and alert sent.",
                "anomaly_detected": True,
                "analysis_date": cost_result.analysis_date,
                "yesterday_cost_usd": cost_result.yesterday_cost,
                "baseline_cost_usd": cost_result.baseline_cost,
                "cost_delta_usd": cost_result.cost_delta,
                "percentage_increase": cost_result.percentage_increase,
                "severity": bedrock_result.anomaly_severity,
                "slack_alert_sent": slack_sent,
                "bedrock_is_fallback": bedrock_result.is_fallback,
                "analysis_id": analysis_id,
                "request_id": request_id,
                "metrics": metrics,
            }
        ),
        "executionTime": execution_time_ms,
    }
