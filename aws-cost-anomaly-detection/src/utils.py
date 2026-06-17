"""Utility helpers for the FinOps cost anomaly detection pipeline.

Provides CloudTrail query helpers, date utilities, and shared formatting
functions used across multiple modules.
"""

import logging
from datetime import date, timedelta
from typing import Any

logger = logging.getLogger(__name__)


def get_date_range(days: int, reference_date: date | None = None) -> tuple[str, str]:
    """Calculate a start/end date range going back N days from today.

    Args:
        days: Number of days to look back.
        reference_date: Reference date (defaults to today's date).

    Returns:
        Tuple of (start_date, end_date) as ISO strings (YYYY-MM-DD).
    """
    end = reference_date or date.today()
    start = end - timedelta(days=days)
    return start.isoformat(), (end - timedelta(days=1)).isoformat()


def get_7day_baseline_dates(reference_date: date | None = None) -> tuple[str, str]:
    """Return the 7-day baseline window dates (8 days ago to 2 days ago).

    The window is shifted to exclude yesterday (which is the anomaly date).

    Args:
        reference_date: Reference date (defaults to today).

    Returns:
        Tuple of (start_date, end_date) for the 7-day baseline window.
    """
    ref = reference_date or date.today()
    end = ref - timedelta(days=2)
    start = ref - timedelta(days=8)
    return start.isoformat(), end.isoformat()


def format_currency(amount: float) -> str:
    """Format a USD amount as a human-readable currency string.

    Args:
        amount: Dollar amount to format.

    Returns:
        Formatted string like ``$1,234.56``.
    """
    return f"${amount:,.2f}"


def format_percentage(pct: float, include_sign: bool = True) -> str:
    """Format a percentage value with an optional leading sign.

    Args:
        pct: Percentage value.
        include_sign: Whether to prefix positive values with ``+``.

    Returns:
        Formatted string like ``+23.4%`` or ``-5.1%``.
    """
    sign = "+" if include_sign and pct > 0 else ""
    return f"{sign}{pct:.1f}%"


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Perform division with a safe fallback for zero denominator.

    Args:
        numerator: Dividend.
        denominator: Divisor.
        default: Value to return when denominator is zero.

    Returns:
        Division result or ``default`` if denominator is zero.
    """
    if denominator == 0:
        return default
    return numerator / denominator


def truncate_string(s: str, max_length: int = 200) -> str:
    """Truncate a string to the specified maximum length.

    Args:
        s: Input string.
        max_length: Maximum character count.

    Returns:
        Truncated string with ``...`` appended if truncation occurred.
    """
    if len(s) <= max_length:
        return s
    return s[: max_length - 3] + "..."


def flatten_cloudtrail_events(summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a CloudTrail summary dict into a single list of events.

    Converts the structured summary from :func:`cloudtrail_client.get_resource_changes_summary`
    into a flat list suitable for prompt injection or Slack formatting.

    Args:
        summary: CloudTrail summary dict with ec2_launches, autoscaling_changes,
                 rds_changes, iam_changes keys.

    Returns:
        Flat list of event dicts, each annotated with an ``event_category`` key.
    """
    events: list[dict[str, Any]] = []

    for event in summary.get("ec2_launches", []):
        events.append({**event, "event_category": "EC2 Launch"})

    for event in summary.get("autoscaling_changes", []):
        events.append({**event, "event_category": "Auto Scaling"})

    for event in summary.get("rds_changes", []):
        events.append({**event, "event_category": "RDS Change"})

    for event in summary.get("iam_changes", []):
        events.append({**event, "event_category": "IAM Change"})

    events.sort(key=lambda e: e.get("eventtime", ""), reverse=True)
    return events


def build_cloudtrail_env_config() -> dict[str, str]:
    """Read CloudTrail/Athena configuration from environment variables.

    Returns:
        Dict with keys: cloudtrail_database, cloudtrail_table,
        results_bucket.
    """
    import os
    s3_bucket = os.environ.get("CLOUDTRAIL_S3_BUCKET", "")
    s3_prefix = os.environ.get("CLOUDTRAIL_S3_PREFIX", "AWSLogs/")
    results_bucket = os.environ.get("ATHENA_RESULTS_BUCKET", "")
    database = os.environ.get("ATHENA_DATABASE", "cloudtrail_logs")
    table = os.environ.get("ATHENA_TABLE", "cloudtrail")

    config = {
        "cloudtrail_s3_bucket": s3_bucket,
        "cloudtrail_s3_prefix": s3_prefix,
        "results_bucket": f"s3://{results_bucket}" if results_bucket and not results_bucket.startswith("s3://") else results_bucket,
        "cloudtrail_database": database,
        "cloudtrail_table": table,
    }
    return config
