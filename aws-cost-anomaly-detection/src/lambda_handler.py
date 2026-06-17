"""AWS Lambda Handler for FinOps Cost Anomaly Detection (CS-07 Extended).

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

CS-07 extensions (always executed after the above):
- Utilization analysis (EC2 + RDS) — daily, results cached 24 h
- Auto-generate Terraform PRs for significant right-sizing recommendations
- S3 lifecycle analysis — weekly (Fridays)
- Tag compliance scan — daily
- Weekly cost digest replacing daily alert on Fridays
"""

import json
import logging
import os
import time
import uuid
from dataclasses import asdict
from datetime import date, timezone, datetime, timedelta
from typing import Any, Optional

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

# CS-07 extension modules
import utilization_analyzer
import savings_optimizer
import s3_lifecycle_optimizer
import tag_compliance_engine
import weekly_digest_generator
try:
    import terraform_pr_generator
    _TF_PR_AVAILABLE = True
except ImportError:
    _TF_PR_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging — structured JSON for CloudWatch Insights
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": %(message)s}',
)
logger = logging.getLogger(__name__)

if not _TF_PR_AVAILABLE:
    logger.warning(
        "PyGithub not installed — Terraform PR generation is disabled. "
        "Install with: pip install 'PyGithub>=2.1.0'"
    )

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

        # CS-07 extended configuration
        self.github_token: str = _get_env("GITHUB_TOKEN", "")
        self.github_repo: str = _get_env("GITHUB_REPO", "")
        self.github_branch_main: str = _get_env("GITHUB_BRANCH_MAIN", "main")
        self.weekly_digest_enabled: bool = _get_env("WEEKLY_DIGEST_ENABLED", "true").lower() != "false"
        self.weekly_digest_day: int = int(_get_env("WEEKLY_DIGEST_DAY", "4"))  # 4 = Friday
        self.cost_center_tag_name: str = _get_env("COST_CENTER_TAG_NAME", "CostCenter")
        self.required_tag_list: list[str] = [
            t.strip()
            for t in _get_env(
                "REQUIRED_TAG_LIST", "CostCenter,Project,Environment,Owner"
            ).split(",")
            if t.strip()
        ]
        self.tf_pr_min_recommendations: int = int(_get_env("TF_PR_MIN_RECOMMENDATIONS", "1"))
        self.tf_pr_reviewers: list[str] = [
            r.strip()
            for r in _get_env("TF_PR_REVIEWERS", "").split(",")
            if r.strip()
        ]

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
                "weekly_digest_enabled": self.weekly_digest_enabled,
                "weekly_digest_day": self.weekly_digest_day,
                "github_repo": self.github_repo or "(not configured)",
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
# CS-07 pipeline stages
# ---------------------------------------------------------------------------

def _stage_utilization_analysis(cfg: Config) -> dict[str, Any]:
    """Run EC2 and RDS utilization analysis; store results for weekly digest.

    Args:
        cfg: Validated configuration object.

    Returns:
        Dict with ``ec2`` and ``rds`` underutilised instance lists.
    """
    t0 = time.monotonic()
    try:
        ec2_under = utilization_analyzer.get_underutilized_ec2_instances(
            region=cfg.aws_region,
            table_name=cfg.dynamodb_table,
        )
        rds_under = utilization_analyzer.get_underutilized_rds_instances(
            region=cfg.aws_region,
            table_name=cfg.dynamodb_table,
        )
        logger.info(
            "Utilization analysis complete",
            extra={
                "underutilized_ec2": len(ec2_under),
                "underutilized_rds": len(rds_under),
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
            },
        )
        return {"ec2": ec2_under, "rds": rds_under}
    except Exception as exc:
        logger.warning("Utilization analysis failed (non-fatal): %s", exc)
        return {"ec2": [], "rds": []}


def _stage_terraform_pr(
    cfg: Config,
    ec2_recommendations: list[dict[str, Any]],
    rds_recommendations: list[dict[str, Any]],
) -> Optional[str]:
    """Auto-generate Terraform PR if significant recommendations exist.

    Args:
        cfg: Validated configuration object.
        ec2_recommendations: EC2 right-sizing recommendations.
        rds_recommendations: RDS right-sizing recommendations.

    Returns:
        PR URL string if created, ``None`` otherwise.
    """
    if not _TF_PR_AVAILABLE:
        logger.debug("Terraform PR generation skipped — PyGithub not available")
        return None

    if not cfg.github_token or not cfg.github_repo:
        logger.info(
            "Terraform PR generation skipped — GITHUB_TOKEN or GITHUB_REPO not configured"
        )
        return None

    all_recs = ec2_recommendations + rds_recommendations
    if len(all_recs) < cfg.tf_pr_min_recommendations:
        logger.info(
            "Fewer than %d recommendations (%d) — skipping Terraform PR creation",
            cfg.tf_pr_min_recommendations,
            len(all_recs),
        )
        return None

    t0 = time.monotonic()
    try:
        today = date.today().isoformat()
        tf_changes: dict[str, str] = {}

        if ec2_recommendations:
            tf_changes[f"terraform/auto-generated/ec2-rightsizing-{today}.tf"] = (
                terraform_pr_generator.generate_ec2_downsizing_terraform(ec2_recommendations)
            )
        if rds_recommendations:
            tf_changes[f"terraform/auto-generated/rds-rightsizing-{today}.tf"] = (
                terraform_pr_generator.generate_rds_downsizing_terraform(rds_recommendations)
            )

        total_ec2_savings = sum(r.get("estimated_savings", 0) for r in ec2_recommendations)
        total_rds_savings = sum(r.get("estimated_savings", 0) for r in rds_recommendations)
        total_savings = total_ec2_savings + total_rds_savings
        annual_savings = total_savings * 12

        resource_ids = [r.get("instance_id", "") for r in all_recs]
        changes = [
            {
                "resource_id": r.get("instance_id", ""),
                "from": r.get("current_type", r.get("instance_class", "")),
                "to": r.get("recommended_type", r.get("recommended_class", "")),
                "monthly_savings": r.get("estimated_savings", 0),
                "risk": terraform_pr_generator.estimate_change_risk(
                    "ec2" if "current_type" in r else "rds",
                    r.get("current_type", r.get("instance_class", "")),
                    r.get("recommended_type", r.get("recommended_class", "")),
                ).get("risk_level", "unknown"),
            }
            for r in all_recs
        ]

        title = (
            f"Cost Optimization: Rightsize {len(all_recs)} resources "
            f"(est. ${annual_savings:,.0f}/yr savings)"
        )
        description = terraform_pr_generator.build_pr_description(
            changes=changes,
            annual_savings=annual_savings,
            risk_summary="Mixed risk — review each change individually.",
            affected_resources=resource_ids,
        )

        pr_url = terraform_pr_generator.commit_and_create_github_pr(
            tf_changes=tf_changes,
            title=title,
            description=description,
            reviewers=cfg.tf_pr_reviewers or None,
        )
        logger.info(
            "Terraform PR created",
            extra={
                "pr_url": pr_url,
                "recommendations": len(all_recs),
                "annual_savings": annual_savings,
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
            },
        )
        return pr_url
    except Exception as exc:
        logger.warning("Terraform PR creation failed (non-fatal): %s", exc)
        return None


def _stage_s3_lifecycle_analysis(cfg: Config) -> list[dict[str, Any]]:
    """Run S3 access pattern analysis for lifecycle recommendations.

    Args:
        cfg: Validated configuration object.

    Returns:
        List of S3 lifecycle recommendation dicts.
    """
    t0 = time.monotonic()
    try:
        results = s3_lifecycle_optimizer.analyze_s3_access_patterns(
            region=cfg.aws_region,
            table_name=cfg.dynamodb_table,
        )
        logger.info(
            "S3 lifecycle analysis complete",
            extra={
                "buckets_flagged": len(results),
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
            },
        )
        return results
    except Exception as exc:
        logger.warning("S3 lifecycle analysis failed (non-fatal): %s", exc)
        return []


def _stage_tag_compliance_scan(cfg: Config) -> list[dict[str, Any]]:
    """Scan for untagged resources across EC2, RDS, S3, and Lambda.

    Args:
        cfg: Validated configuration object.

    Returns:
        List of untagged resource dicts.
    """
    t0 = time.monotonic()
    try:
        results = tag_compliance_engine.scan_untagged_resources(
            region=cfg.aws_region,
            table_name=cfg.dynamodb_table,
            required_tags=cfg.required_tag_list,
        )
        logger.info(
            "Tag compliance scan complete",
            extra={
                "untagged_resources": len(results),
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
            },
        )
        return results
    except Exception as exc:
        logger.warning("Tag compliance scan failed (non-fatal): %s", exc)
        return []


def _stage_weekly_digest(
    cfg: Config,
    utilization_results: dict[str, Any],
    s3_results: list[dict[str, Any]],
) -> bool:
    """Send the weekly cost digest to Slack.

    Args:
        cfg: Validated configuration object.
        utilization_results: Dict with ``ec2`` and ``rds`` right-sizing lists.
        s3_results: S3 lifecycle recommendation list.

    Returns:
        ``True`` if at least one message was sent successfully.
    """
    if not cfg.weekly_digest_enabled:
        logger.info("Weekly digest is disabled via configuration")
        return False

    t0 = time.monotonic()
    try:
        ec2_monthly = sum(
            r.get("estimated_savings", 0) for r in utilization_results.get("ec2", [])
        )
        rds_monthly = sum(
            r.get("estimated_savings", 0) for r in utilization_results.get("rds", [])
        )
        s3_monthly = sum(r.get("monthly_savings", 0) for r in s3_results)

        result = weekly_digest_generator.send_weekly_team_digest(
            table_name=cfg.dynamodb_table,
            region=cfg.aws_region,
            dashboard_url=cfg.dashboard_url,
            utilization_savings=ec2_monthly + rds_monthly,
            ri_savings=0.0,
            s3_savings=s3_monthly,
            ec2_opportunities=utilization_results.get("ec2", []),
            rds_opportunities=utilization_results.get("rds", []),
        )
        sent = result.get("messages_sent", 0)
        logger.info(
            "Weekly digest sent",
            extra={
                "messages_sent": sent,
                "teams": result.get("teams", []),
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
            },
        )
        return sent > 0
    except Exception as exc:
        logger.error("Weekly digest failed (non-fatal): %s", exc)
        return False


def _stage_ri_analysis(cfg: Config) -> list[dict[str, Any]]:
    """Run Reserved Instance opportunity analysis.

    Args:
        cfg: Validated configuration object.

    Returns:
        List of RI recommendation dicts.
    """
    t0 = time.monotonic()
    try:
        results = savings_optimizer.analyze_reserved_instance_opportunity(
            region=cfg.aws_region,
            table_name=cfg.dynamodb_table,
        )
        logger.info(
            "RI analysis complete",
            extra={
                "ri_opportunities": len(results),
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
            },
        )
        return results
    except Exception as exc:
        logger.warning("RI analysis failed (non-fatal): %s", exc)
        return []


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
    is_friday = today.weekday() == 4  # 0=Monday, 4=Friday

    logger.info(
        "Lambda handler started",
        extra={
            "request_id": request_id,
            "analysis_id": analysis_id,
            "execution_date": execution_date,
            "is_friday": is_friday,
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

        # CS-07 stages still run when no anomaly is detected
        utilization_results = _stage_utilization_analysis(cfg)
        pr_url = _stage_terraform_pr(
            cfg,
            ec2_recommendations=utilization_results.get("ec2", []),
            rds_recommendations=utilization_results.get("rds", []),
        )
        s3_results: list[dict[str, Any]] = []
        if is_friday:
            s3_results = _stage_s3_lifecycle_analysis(cfg)
        untagged_resources = _stage_tag_compliance_scan(cfg)
        if is_friday:
            _stage_weekly_digest(cfg, utilization_results, s3_results)

        opportunity_count = (
            len(utilization_results.get("ec2", []))
            + len(utilization_results.get("rds", []))
            + len(s3_results)
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
                    # CS-07 fields
                    "underutilized_ec2": len(utilization_results.get("ec2", [])),
                    "underutilized_rds": len(utilization_results.get("rds", [])),
                    "terraform_pr_url": pr_url,
                    "untagged_resources": len(untagged_resources),
                    "opportunities_found": opportunity_count,
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

    # ==================================================================
    # CS-07 EXTENSION STAGES
    # These run after the core pipeline regardless of anomaly status.
    # ==================================================================

    # CS-07.1: Utilization analysis (daily; results cached 24 h)
    t0 = time.monotonic()
    utilization_results = _stage_utilization_analysis(cfg)
    metrics["utilization_analysis_ms"] = int((time.monotonic() - t0) * 1000)
    metrics["underutilized_ec2_count"] = len(utilization_results.get("ec2", []))
    metrics["underutilized_rds_count"] = len(utilization_results.get("rds", []))

    # CS-07.2: Auto-generate Terraform PR (daily; only when recommendations exist)
    t0 = time.monotonic()
    pr_url = _stage_terraform_pr(
        cfg,
        ec2_recommendations=utilization_results.get("ec2", []),
        rds_recommendations=utilization_results.get("rds", []),
    )
    metrics["terraform_pr_created"] = pr_url is not None
    metrics["terraform_pr_url"] = pr_url or ""
    metrics["terraform_pr_ms"] = int((time.monotonic() - t0) * 1000)

    # CS-07.3: S3 lifecycle analysis (weekly — Fridays only)
    s3_results: list[dict[str, Any]] = []
    if is_friday:
        t0 = time.monotonic()
        s3_results = _stage_s3_lifecycle_analysis(cfg)
        metrics["s3_lifecycle_buckets"] = len(s3_results)
        metrics["s3_lifecycle_ms"] = int((time.monotonic() - t0) * 1000)

    # CS-07.4: Tag compliance scan (daily)
    t0 = time.monotonic()
    untagged_resources = _stage_tag_compliance_scan(cfg)
    metrics["untagged_resources_count"] = len(untagged_resources)
    metrics["tag_compliance_ms"] = int((time.monotonic() - t0) * 1000)

    # CS-07.5: Weekly digest (Fridays only; replaces daily alert on Fridays)
    if is_friday:
        t0 = time.monotonic()
        digest_sent = _stage_weekly_digest(cfg, utilization_results, s3_results)
        metrics["weekly_digest_sent"] = digest_sent
        metrics["weekly_digest_ms"] = int((time.monotonic() - t0) * 1000)

    execution_time_ms = int((time.monotonic() - pipeline_start) * 1000)
    metrics["total_execution_ms"] = execution_time_ms

    logger.info("Lambda pipeline complete", extra=metrics)

    opportunity_count = (
        len(utilization_results.get("ec2", []))
        + len(utilization_results.get("rds", []))
        + len(s3_results)
    )

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
                # CS-07 fields
                "underutilized_ec2": metrics.get("underutilized_ec2_count", 0),
                "underutilized_rds": metrics.get("underutilized_rds_count", 0),
                "terraform_pr_url": pr_url,
                "untagged_resources": len(untagged_resources),
                "opportunities_found": opportunity_count,
                "metrics": metrics,
            }
        ),
        "executionTime": execution_time_ms,
    }
