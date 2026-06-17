"""AWS Lambda Handler for FinOps Cost Anomaly Detection.

Orchestrates the full pipeline:
1. Check DynamoDB for today's execution (idempotency)
2. Fetch yesterday's cost (Cost Explorer)
3. Get 7-day baseline from DynamoDB
4. Detect anomaly
5. If anomaly detected:
   a. Query CloudTrail for resource changes (via cloudtrail_client + Athena)
   b. Get Compute Optimizer recommendations
   c. Call Bedrock Amazon Nova Pro with all context
   d. Store results in DynamoDB
   e. Post to Slack with findings
6. Store baseline for next run
7. Return success/failure response
"""

import json
import logging
import os
import time
import uuid
from dataclasses import asdict
from datetime import date, timezone, datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

from bedrock_agent import BedrockAnalysisResult, invoke_bedrock_analysis
from cloudtrail_client import format_changes_for_prompt, get_resource_changes_summary
from compute_optimizer_client import (
    format_recommendations_for_prompt,
    get_all_recommendations,
)
from cost_analyzer import AWSException, CostDataError, run_cost_analysis
from dynamodb_store import (
    check_idempotency,
    get_baseline_costs,
    record_idempotency,
    store_anomaly_result,
    store_cost_baseline,
)
from slack_notifier import SlackException, send_anomaly_alert
from utils import get_7day_baseline_dates

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
        self.aws_region: str = _get_env("AWS_REGION", "ap-south-1")
        self.slack_webhook_url: str = _require_env("SLACK_WEBHOOK_URL")
        self.bedrock_model_id: str = _get_env(
            "BEDROCK_MODEL_ID", "amazon.nova-pro-v1:0"
        )
        self.cost_threshold_pct: float = float(_get_env("COST_THRESHOLD_PCT", "15.0"))
        self.dashboard_url: str = _get_env("COST_DASHBOARD_URL", "")
        self.dynamodb_table: str = _get_env(
            "DYNAMODB_TABLE_NAME", "finops-cost-baselines"
        )
        self.rolling_window_days: int = int(_get_env("ROLLING_WINDOW_DAYS", "7"))
        self.cloudtrail_s3_bucket: str = _get_env("CLOUDTRAIL_S3_BUCKET", "")
        self.cloudtrail_s3_prefix: str = _get_env("CLOUDTRAIL_S3_PREFIX", "AWSLogs/")
        self.athena_results_bucket: str = _get_env("ATHENA_RESULTS_BUCKET", "")
        self.athena_database: str = _get_env("ATHENA_DATABASE", "cloudtrail_logs")
        self.athena_table: str = _get_env("ATHENA_TABLE", "cloudtrail")

        # Normalise results_bucket to s3:// URI
        if self.athena_results_bucket and not self.athena_results_bucket.startswith("s3://"):
            self.athena_results_bucket = f"s3://{self.athena_results_bucket}"

    def log_summary(self) -> None:
        """Log non-secret configuration values for audit trail."""
        logger.info(
            "Configuration loaded",
            extra={
                "aws_region": self.aws_region,
                "bedrock_model_id": self.bedrock_model_id,
                "cost_threshold_pct": self.cost_threshold_pct,
                "rolling_window_days": self.rolling_window_days,
                "dynamodb_table": self.dynamodb_table,
                "cloudtrail_s3_bucket": self.cloudtrail_s3_bucket,
                "athena_database": self.athena_database,
            },
        )


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

def _stage_fetch_baseline_costs(cfg: Config, reference_date: date) -> list[float]:
    """Fetch 7-day cost baselines from DynamoDB.

    Falls back to an empty list when DynamoDB data is unavailable so the
    pipeline continues gracefully.

    Args:
        cfg: Validated configuration object.
        reference_date: Reference date (today).

    Returns:
        List of daily cost values (USD) over the rolling window.
    """
    t0 = time.monotonic()
    start_date, end_date = get_7day_baseline_dates(reference_date)
    try:
        costs = get_baseline_costs(
            table_name=cfg.dynamodb_table,
            start_date=start_date,
            end_date=end_date,
            region=cfg.aws_region,
        )
        logger.info(
            "Baseline costs fetched from DynamoDB",
            extra={
                "num_days": len(costs),
                "start": start_date,
                "end": end_date,
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
            },
        )
        return costs
    except Exception as exc:
        logger.warning(
            "Could not fetch baseline costs from DynamoDB (will use empty list): %s", exc
        )
        return []


def _stage_fetch_cloudtrail_changes(cfg: Config) -> dict[str, Any]:
    """Query CloudTrail via Athena for resource changes in the last 24 hours.

    Returns an empty summary on failure so the pipeline continues without
    CloudTrail data.

    Args:
        cfg: Validated configuration object.

    Returns:
        CloudTrail resource changes summary dict.
    """
    if not cfg.cloudtrail_s3_bucket or not cfg.athena_results_bucket:
        logger.info(
            "CloudTrail/Athena not configured — skipping resource change query. "
            "Set CLOUDTRAIL_S3_BUCKET and ATHENA_RESULTS_BUCKET to enable."
        )
        return {
            "ec2_launches": [],
            "autoscaling_changes": [],
            "rds_changes": [],
            "iam_changes": [],
            "total_events": 0,
            "query_window_hours": 24,
        }

    t0 = time.monotonic()
    try:
        summary = get_resource_changes_summary(
            region=cfg.aws_region,
            cloudtrail_database=cfg.athena_database,
            cloudtrail_table=cfg.athena_table,
            results_bucket=cfg.athena_results_bucket,
            hours=24,
        )
        logger.info(
            "CloudTrail changes fetched",
            extra={
                "total_events": summary.get("total_events", 0),
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
            },
        )
        return summary
    except Exception as exc:
        logger.warning(
            "Could not fetch CloudTrail changes (continuing without): %s", exc
        )
        return {
            "ec2_launches": [],
            "autoscaling_changes": [],
            "rds_changes": [],
            "iam_changes": [],
            "total_events": 0,
            "query_window_hours": 24,
        }


def _stage_fetch_compute_optimizer(cfg: Config) -> dict[str, Any]:
    """Fetch AWS Compute Optimizer recommendations.

    Returns an empty result on failure.

    Args:
        cfg: Validated configuration object.

    Returns:
        Compute Optimizer recommendations dict.
    """
    t0 = time.monotonic()
    try:
        recs = get_all_recommendations(region=cfg.aws_region)
        logger.info(
            "Compute Optimizer recommendations fetched",
            extra={
                "total": recs.get("total_recommendations", 0),
                "total_savings_usd": recs.get("total_savings_usd", 0),
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
            },
        )
        return recs
    except Exception as exc:
        logger.warning(
            "Could not fetch Compute Optimizer recommendations (continuing without): %s",
            exc,
        )
        return {"ec2": [], "lambda": [], "ebs": [], "total_savings_usd": 0.0, "total_recommendations": 0}


def _stage_bedrock_analysis(
    cfg: Config,
    cost_data: dict[str, Any],
    cloudtrail_summary: dict[str, Any],
    compute_optimizer_recs: dict[str, Any],
) -> BedrockAnalysisResult:
    """Run Bedrock Nova Pro cost analysis, returning a fallback on failure.

    Args:
        cfg: Validated configuration object.
        cost_data: Cost metrics dictionary.
        cloudtrail_summary: CloudTrail resource changes summary.
        compute_optimizer_recs: Compute Optimizer recommendations.

    Returns:
        :class:`BedrockAnalysisResult` (may be a fallback response).
    """
    t0 = time.monotonic()
    cloudtrail_prompt = format_changes_for_prompt(cloudtrail_summary)
    optimizer_prompt = format_recommendations_for_prompt(compute_optimizer_recs)

    result = invoke_bedrock_analysis(
        cost_data=cost_data,
        cloudtrail_summary=cloudtrail_prompt,
        compute_optimizer_summary=optimizer_prompt,
        model_id=cfg.bedrock_model_id,
        region=cfg.aws_region,
    )
    logger.info(
        "Bedrock Nova Pro analysis complete",
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
    cloudtrail_summary: dict[str, Any],
    compute_optimizer_recs: dict[str, Any],
    analysis_id: str,
) -> bool:
    """Send the Slack alert, returning False on failure (non-fatal).

    Args:
        cfg: Validated configuration object.
        analysis_date: Date string for the anomaly.
        cost_result: CostAnalysisResult object.
        bedrock_result: BedrockAnalysisResult object.
        cloudtrail_summary: CloudTrail resource changes summary.
        compute_optimizer_recs: Compute Optimizer recommendations.
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
            cloudtrail_summary=cloudtrail_summary,
            compute_optimizer_savings_usd=compute_optimizer_recs.get("total_savings_usd", 0.0),
            dashboard_url=cfg.dashboard_url,
            analysis_id=analysis_id,
            model_id=cfg.bedrock_model_id,
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
    """AWS Lambda handler — FinOps cost anomaly detection pipeline entry point.

    Orchestration order:
    1. Validate configuration.
    2. Idempotency check via DynamoDB.
    3. Fetch 7-day baseline costs from DynamoDB.
    4. Fetch yesterday's cost via Cost Explorer and detect anomaly.
    5. Store yesterday's cost as a new baseline in DynamoDB.
    6. If anomaly detected:
       a. Query CloudTrail for resource changes (via Athena).
       b. Get Compute Optimizer recommendations.
       c. Invoke Bedrock Nova Pro for root-cause analysis.
       d. Store anomaly result in DynamoDB.
       e. Send Slack alert.
    7. Record execution for idempotency.
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
    today = date.today()
    execution_date = today.isoformat()
    analysis_date = (today - timedelta(days=1)).isoformat()

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
    if check_idempotency(cfg.dynamodb_table, execution_date, cfg.aws_region):
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
    # 3. Fetch 7-day baseline costs from DynamoDB
    # ------------------------------------------------------------------
    t0 = time.monotonic()
    historical_costs = _stage_fetch_baseline_costs(cfg, today)
    metrics["dynamodb_baseline_fetch_ms"] = int((time.monotonic() - t0) * 1000)
    metrics["historical_cost_days"] = len(historical_costs)

    # ------------------------------------------------------------------
    # 4. Fetch yesterday's cost and detect anomaly
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

    # ------------------------------------------------------------------
    # 5. Store yesterday's cost as baseline for future runs
    # ------------------------------------------------------------------
    try:
        store_cost_baseline(
            table_name=cfg.dynamodb_table,
            execution_date=analysis_date,
            cost_usd=cost_result.yesterday_cost,
            region=cfg.aws_region,
        )
    except Exception as exc:
        logger.warning("Could not persist cost baseline (non-fatal): %s", exc)

    if not cost_result.anomaly_detected:
        logger.info(
            "No cost anomaly detected for %s (%.1f%% vs %.1f%% threshold)",
            cost_result.analysis_date,
            cost_result.percentage_increase,
            cfg.cost_threshold_pct,
        )
        record_idempotency(
            cfg.dynamodb_table,
            execution_date,
            analysis_id,
            {"anomaly_detected": False},
            cfg.aws_region,
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
    # 6a. Query CloudTrail for resource changes
    # ------------------------------------------------------------------
    t0 = time.monotonic()
    cloudtrail_summary = _stage_fetch_cloudtrail_changes(cfg)
    metrics["cloudtrail_fetch_ms"] = int((time.monotonic() - t0) * 1000)
    metrics["cloudtrail_events_count"] = cloudtrail_summary.get("total_events", 0)

    # ------------------------------------------------------------------
    # 6b. Get Compute Optimizer recommendations
    # ------------------------------------------------------------------
    t0 = time.monotonic()
    compute_optimizer_recs = _stage_fetch_compute_optimizer(cfg)
    metrics["compute_optimizer_fetch_ms"] = int((time.monotonic() - t0) * 1000)
    metrics["compute_optimizer_recommendations"] = compute_optimizer_recs.get("total_recommendations", 0)
    metrics["compute_optimizer_savings_usd"] = compute_optimizer_recs.get("total_savings_usd", 0.0)

    # ------------------------------------------------------------------
    # 6c. Bedrock Nova Pro analysis
    # ------------------------------------------------------------------
    t0 = time.monotonic()
    cost_dict = {
        "yesterday_cost": cost_result.yesterday_cost,
        "baseline_cost": cost_result.baseline_cost,
        "cost_delta": cost_result.cost_delta,
        "percentage_increase": cost_result.percentage_increase,
        "analysis_date": cost_result.analysis_date,
    }
    bedrock_result = _stage_bedrock_analysis(
        cfg, cost_dict, cloudtrail_summary, compute_optimizer_recs
    )
    metrics["bedrock_latency_ms"] = int((time.monotonic() - t0) * 1000)
    metrics["bedrock_severity"] = bedrock_result.anomaly_severity
    metrics["bedrock_is_fallback"] = bedrock_result.is_fallback
    metrics["bedrock_input_tokens"] = bedrock_result.input_tokens
    metrics["bedrock_output_tokens"] = bedrock_result.output_tokens

    # ------------------------------------------------------------------
    # 6d. Store anomaly result in DynamoDB
    # ------------------------------------------------------------------
    try:
        store_anomaly_result(
            table_name=cfg.dynamodb_table,
            execution_date=execution_date,
            analysis_id=analysis_id,
            anomaly_data={
                "severity": bedrock_result.anomaly_severity,
                "yesterday_cost_usd": str(cost_result.yesterday_cost),
                "percentage_increase": str(cost_result.percentage_increase),
                "cloudtrail_events": str(cloudtrail_summary.get("total_events", 0)),
                "model_id": cfg.bedrock_model_id,
            },
            region=cfg.aws_region,
        )
    except Exception as exc:
        logger.warning("Could not store anomaly result (non-fatal): %s", exc)

    # ------------------------------------------------------------------
    # 6e. Send Slack alert
    # ------------------------------------------------------------------
    t0 = time.monotonic()
    slack_sent = _stage_send_alert(
        cfg=cfg,
        analysis_date=cost_result.analysis_date,
        cost_result=cost_result,
        bedrock_result=bedrock_result,
        cloudtrail_summary=cloudtrail_summary,
        compute_optimizer_recs=compute_optimizer_recs,
        analysis_id=analysis_id,
    )
    metrics["slack_alert_sent"] = slack_sent
    metrics["slack_latency_ms"] = int((time.monotonic() - t0) * 1000)

    # ------------------------------------------------------------------
    # 7. Record execution for idempotency
    # ------------------------------------------------------------------
    record_idempotency(
        cfg.dynamodb_table,
        execution_date,
        analysis_id,
        {
            "anomaly_detected": True,
            "severity": bedrock_result.anomaly_severity,
            "yesterday_cost_usd": str(cost_result.yesterday_cost),
            "percentage_increase": str(cost_result.percentage_increase),
            "slack_sent": slack_sent,
        },
        cfg.aws_region,
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
                "cloudtrail_events": cloudtrail_summary.get("total_events", 0),
                "compute_optimizer_savings_usd": compute_optimizer_recs.get("total_savings_usd", 0.0),
                "analysis_id": analysis_id,
                "request_id": request_id,
                "model_id": cfg.bedrock_model_id,
                "metrics": metrics,
            }
        ),
        "executionTime": execution_time_ms,
    }
