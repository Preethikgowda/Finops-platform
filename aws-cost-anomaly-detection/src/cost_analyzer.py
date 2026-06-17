"""AWS Cost Anomaly Detection Engine.

Fetches yesterday's AWS costs via Cost Explorer API, retrieves 7-day historical
cost data from DynamoDB, calculates rolling averages, and detects anomalies
when costs exceed the configurable threshold.
"""

import logging
import time
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)


class AWSException(Exception):
    """Raised for AWS API failures."""

    pass


class CostDataError(Exception):
    """Raised when cost data is invalid or unavailable."""

    pass


@dataclass
class CostAnalysisResult:
    """Result of cost anomaly analysis."""

    anomaly_detected: bool
    cost_delta: float
    percentage_increase: float
    baseline_cost: float
    yesterday_cost: float
    analysis_date: str
    threshold_pct: float


def _build_cost_explorer_client(region: str) -> Any:
    """Create a boto3 Cost Explorer client.

    Args:
        region: AWS region name.

    Returns:
        boto3 Cost Explorer client.
    """
    return boto3.client("ce", region_name=region)


def _retry_with_backoff(func: Any, max_attempts: int = 3, base_delay: float = 1.0) -> Any:
    """Execute a callable with exponential backoff retry logic.

    Args:
        func: Callable to execute. Must be a zero-argument callable.
        max_attempts: Maximum number of attempts before raising.
        base_delay: Initial delay in seconds; doubles on each retry.

    Returns:
        Result of the callable.

    Raises:
        AWSException: When all attempts are exhausted.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(1, max_attempts + 1):
        try:
            return func()
        except (ClientError, BotoCoreError) as exc:
            last_exc = exc
            if attempt == max_attempts:
                break
            delay = base_delay * (2 ** (attempt - 1))
            logger.warning(
                "AWS API call failed (attempt %d/%d), retrying in %.1fs: %s",
                attempt,
                max_attempts,
                delay,
                exc,
            )
            time.sleep(delay)

    raise AWSException(
        f"AWS API call failed after {max_attempts} attempts: {last_exc}"
    ) from last_exc


def fetch_yesterday_cost(
    region: str = "ap-south-1",
    granularity: str = "DAILY",
    metrics: Optional[list[str]] = None,
) -> float:
    """Fetch total AWS cost for yesterday using Cost Explorer.

    Args:
        region: AWS region for the Cost Explorer client.
        granularity: Time granularity for the query (DAILY, MONTHLY).
        metrics: Cost metrics to retrieve. Defaults to ``['UnblendedCost']``.

    Returns:
        Total cost in USD for yesterday.

    Raises:
        AWSException: On AWS API failures after retries.
        CostDataError: When the API returns no cost data.
    """
    if metrics is None:
        metrics = ["UnblendedCost"]

    yesterday = date.today() - timedelta(days=1)
    start = yesterday.strftime("%Y-%m-%d")
    end = date.today().strftime("%Y-%m-%d")

    logger.info(
        "Fetching Cost Explorer data",
        extra={"start": start, "end": end, "granularity": granularity},
    )

    client = _build_cost_explorer_client(region)

    def _call() -> dict:
        return client.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity=granularity,
            Metrics=metrics,
        )

    try:
        response = _retry_with_backoff(_call)
    except AWSException:
        logger.error(
            "Failed to fetch yesterday's cost from Cost Explorer",
            extra={"start": start, "end": end},
        )
        raise

    results = response.get("ResultsByTime", [])
    if not results:
        raise CostDataError(
            f"No cost data returned from Cost Explorer for period {start} to {end}. "
            "Ensure Cost Explorer is enabled in your AWS account."
        )

    total_cost = 0.0
    for result in results:
        for metric_name in metrics:
            amount_str = result.get("Total", {}).get(metric_name, {}).get("Amount", "0")
            try:
                total_cost += float(amount_str)
            except (ValueError, TypeError) as exc:
                logger.warning(
                    "Could not parse cost amount '%s' for metric '%s': %s",
                    amount_str,
                    metric_name,
                    exc,
                )

    logger.info(
        "Yesterday's cost fetched",
        extra={"date": start, "cost_usd": total_cost},
    )
    return total_cost


def calculate_rolling_average(historical_costs: list[float]) -> float:
    """Calculate the average of a list of daily costs.

    Args:
        historical_costs: Ordered list of daily costs in USD (oldest → newest).

    Returns:
        Arithmetic mean of the provided costs.

    Raises:
        CostDataError: When the list is empty.
    """
    if not historical_costs:
        raise CostDataError(
            "Cannot calculate rolling average: no historical cost data provided. "
            "Ensure at least one day of historical data is available in DynamoDB."
        )
    avg = sum(historical_costs) / len(historical_costs)
    logger.debug(
        "Rolling average calculated",
        extra={"num_days": len(historical_costs), "average_usd": avg},
    )
    return avg


def detect_anomaly(
    yesterday_cost: float,
    baseline_cost: float,
    threshold_pct: float = 15.0,
) -> tuple[bool, float, float]:
    """Determine whether yesterday's cost is anomalous relative to the baseline.

    Args:
        yesterday_cost: Total cost for yesterday in USD.
        baseline_cost: Rolling average cost (baseline) in USD.
        threshold_pct: Percentage above baseline that triggers an anomaly.
                       Defaults to ``15.0``.

    Returns:
        Tuple of (anomaly_detected, cost_delta, percentage_increase).

    Raises:
        CostDataError: When baseline_cost is zero (division by zero guard).
    """
    if baseline_cost <= 0:
        raise CostDataError(
            f"Baseline cost is {baseline_cost:.4f} USD which is not positive. "
            "Cannot calculate percentage increase. Verify historical data quality."
        )

    cost_delta = yesterday_cost - baseline_cost
    percentage_increase = (cost_delta / baseline_cost) * 100.0
    anomaly_detected = percentage_increase > threshold_pct

    logger.info(
        "Anomaly detection result",
        extra={
            "yesterday_cost_usd": yesterday_cost,
            "baseline_cost_usd": baseline_cost,
            "cost_delta_usd": cost_delta,
            "percentage_increase": percentage_increase,
            "threshold_pct": threshold_pct,
            "anomaly_detected": anomaly_detected,
        },
    )
    return anomaly_detected, cost_delta, percentage_increase


def get_correlated_changes(
    cloudtrail_database: str,
    cloudtrail_table: str,
    results_bucket: str,
    region: str,
    hours: int = 24,
) -> dict[str, Any]:
    """Fetch correlated resource changes from CloudTrail via Athena.

    Returns a structured summary of EC2, Auto Scaling, RDS, and IAM changes
    detected in CloudTrail that may explain the detected cost anomaly.

    Args:
        cloudtrail_database: Athena database name for CloudTrail logs.
        cloudtrail_table: Athena table name for CloudTrail logs.
        results_bucket: S3 bucket for Athena query results.
        region: AWS region for the Athena client.
        hours: Look-back window in hours.

    Returns:
        CloudTrail resource changes summary dict. Returns an empty summary
        on failure so the pipeline continues without CloudTrail data.
    """
    try:
        from cloudtrail_client import get_resource_changes_summary
        return get_resource_changes_summary(
            region=region,
            cloudtrail_database=cloudtrail_database,
            cloudtrail_table=cloudtrail_table,
            results_bucket=results_bucket,
            hours=hours,
        )
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
            "query_window_hours": hours,
        }


def run_cost_analysis(
    historical_costs: list[float],
    region: str = "ap-south-1",
    threshold_pct: float = 15.0,
) -> CostAnalysisResult:
    """Orchestrate full cost anomaly analysis.

    Fetches yesterday's AWS costs via Cost Explorer, computes the rolling
    average from the supplied historical data, and returns a structured
    analysis result.

    Args:
        historical_costs: List of daily costs (USD) for the rolling window
                          (typically the last 7 days from DynamoDB).
        region: AWS region used by Cost Explorer.
        threshold_pct: Percentage increase above baseline that triggers anomaly.

    Returns:
        :class:`CostAnalysisResult` with all analysis fields populated.

    Raises:
        AWSException: On unrecoverable AWS API failures.
        CostDataError: When cost data is unavailable or invalid.
    """
    analysis_date = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")

    logger.info(
        "Starting cost analysis",
        extra={"analysis_date": analysis_date, "threshold_pct": threshold_pct},
    )

    yesterday_cost = fetch_yesterday_cost(region=region)
    baseline_cost = calculate_rolling_average(historical_costs)
    anomaly_detected, cost_delta, percentage_increase = detect_anomaly(
        yesterday_cost=yesterday_cost,
        baseline_cost=baseline_cost,
        threshold_pct=threshold_pct,
    )

    result = CostAnalysisResult(
        anomaly_detected=anomaly_detected,
        cost_delta=cost_delta,
        percentage_increase=percentage_increase,
        baseline_cost=baseline_cost,
        yesterday_cost=yesterday_cost,
        analysis_date=analysis_date,
        threshold_pct=threshold_pct,
    )

    logger.info(
        "Cost analysis complete",
        extra={
            "anomaly_detected": anomaly_detected,
            "yesterday_cost_usd": yesterday_cost,
            "baseline_cost_usd": baseline_cost,
            "percentage_increase": percentage_increase,
        },
    )
    return result
