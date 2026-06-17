"""CloudTrail Client for FinOps Cost Anomaly Detection.

Queries CloudTrail logs via AWS Athena to detect resource changes that may
correlate with cost anomalies. CloudTrail logs are stored in S3 and queried
serverlessly through Athena, replacing the previous Elasticsearch approach.
"""

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

# Default Athena query poll interval and max wait time
_ATHENA_POLL_INTERVAL_S = 2.0
_ATHENA_MAX_WAIT_S = 120.0


class CloudTrailException(Exception):
    """Raised for CloudTrail / Athena query failures."""

    pass


class AthenaQueryTimeout(CloudTrailException):
    """Raised when an Athena query exceeds the maximum wait time."""

    pass


def _utcnow() -> datetime:
    """Return current UTC datetime (extracted for testability)."""
    return datetime.now(tz=timezone.utc)


def _build_athena_client(region: str) -> Any:
    """Create a boto3 Athena client.

    Args:
        region: AWS region name.

    Returns:
        boto3 Athena client.
    """
    return boto3.client("athena", region_name=region)


def _run_athena_query(
    athena_client: Any,
    query: str,
    database: str,
    results_bucket: str,
    max_wait_s: float = _ATHENA_MAX_WAIT_S,
) -> list[dict[str, Any]]:
    """Execute an Athena query and return results as a list of row dicts.

    Args:
        athena_client: boto3 Athena client.
        query: SQL query string.
        database: Athena database name.
        results_bucket: S3 bucket for Athena query results (``s3://...``).
        max_wait_s: Maximum seconds to wait for query completion.

    Returns:
        List of dicts mapping column names to string values.

    Raises:
        AthenaQueryTimeout: When the query does not finish within ``max_wait_s``.
        CloudTrailException: On Athena API errors or query failure.
    """
    try:
        start_response = athena_client.start_query_execution(
            QueryString=query,
            QueryExecutionContext={"Database": database},
            ResultConfiguration={"OutputLocation": results_bucket},
        )
    except (ClientError, BotoCoreError) as exc:
        raise CloudTrailException(f"Failed to start Athena query: {exc}") from exc

    execution_id = start_response["QueryExecutionId"]
    logger.info("Athena query started", extra={"execution_id": execution_id})

    deadline = time.monotonic() + max_wait_s
    while time.monotonic() < deadline:
        try:
            status_response = athena_client.get_query_execution(
                QueryExecutionId=execution_id
            )
        except (ClientError, BotoCoreError) as exc:
            raise CloudTrailException(
                f"Failed to poll Athena query status ({execution_id}): {exc}"
            ) from exc

        state = (
            status_response.get("QueryExecution", {})
            .get("Status", {})
            .get("State", "UNKNOWN")
        )

        if state == "SUCCEEDED":
            break
        if state in ("FAILED", "CANCELLED"):
            reason = (
                status_response.get("QueryExecution", {})
                .get("Status", {})
                .get("StateChangeReason", "unknown reason")
            )
            raise CloudTrailException(
                f"Athena query {execution_id} {state}: {reason}"
            )

        time.sleep(_ATHENA_POLL_INTERVAL_S)
    else:
        raise AthenaQueryTimeout(
            f"Athena query {execution_id} did not complete within {max_wait_s}s."
        )

    try:
        result_response = athena_client.get_query_results(
            QueryExecutionId=execution_id
        )
    except (ClientError, BotoCoreError) as exc:
        raise CloudTrailException(
            f"Failed to fetch Athena results for {execution_id}: {exc}"
        ) from exc

    rows = result_response.get("ResultSet", {}).get("Rows", [])
    if not rows:
        return []

    # First row is always the column header
    headers = [col.get("VarCharValue", "") for col in rows[0].get("Data", [])]
    results: list[dict[str, Any]] = []
    for row in rows[1:]:
        values = [cell.get("VarCharValue", "") for cell in row.get("Data", [])]
        results.append(dict(zip(headers, values)))

    logger.info(
        "Athena query completed",
        extra={"execution_id": execution_id, "row_count": len(results)},
    )
    return results


def get_ec2_launches_last_24h(
    region: str,
    cloudtrail_database: str,
    cloudtrail_table: str,
    results_bucket: str,
    hours: int = 24,
) -> list[dict[str, Any]]:
    """Query CloudTrail for EC2 instance launch events in the last N hours.

    Args:
        region: AWS region for the Athena client.
        cloudtrail_database: Athena database containing CloudTrail logs.
        cloudtrail_table: Athena table name for CloudTrail logs.
        results_bucket: S3 output location for Athena results (``s3://...``).
        hours: Look-back window in hours.

    Returns:
        List of event dicts with keys: eventtime, useridentity_arn,
        requestparameters, sourceipaddress, useragent.

    Raises:
        CloudTrailException: On Athena failures.
    """
    since = _utcnow() - timedelta(hours=hours)
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")

    query = f"""
        SELECT
            eventtime,
            useridentity.arn AS useridentity_arn,
            requestparameters,
            sourceipaddress,
            useragent,
            awsregion
        FROM {cloudtrail_table}
        WHERE eventname = 'RunInstances'
          AND eventtime >= '{since_str}'
        ORDER BY eventtime DESC
        LIMIT 100
    """

    try:
        athena = _build_athena_client(region)
        results = _run_athena_query(
            athena_client=athena,
            query=query,
            database=cloudtrail_database,
            results_bucket=results_bucket,
        )
        logger.info(
            "EC2 launch events fetched",
            extra={"count": len(results), "hours": hours},
        )
        return results
    except Exception as exc:
        logger.warning("Could not fetch EC2 launch events: %s", exc)
        return []


def get_autoscaling_changes(
    region: str,
    cloudtrail_database: str,
    cloudtrail_table: str,
    results_bucket: str,
    hours: int = 24,
) -> list[dict[str, Any]]:
    """Query CloudTrail for Auto Scaling group events in the last N hours.

    Captures scale-out/in events, group creation, and policy updates.

    Args:
        region: AWS region for the Athena client.
        cloudtrail_database: Athena database name.
        cloudtrail_table: Athena table name.
        results_bucket: S3 output location for Athena results.
        hours: Look-back window in hours.

    Returns:
        List of event dicts for Auto Scaling changes.
    """
    since = _utcnow() - timedelta(hours=hours)
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")

    query = f"""
        SELECT
            eventtime,
            eventname,
            useridentity.arn AS useridentity_arn,
            requestparameters,
            sourceipaddress,
            awsregion
        FROM {cloudtrail_table}
        WHERE eventsource = 'autoscaling.amazonaws.com'
          AND eventname IN (
              'CreateAutoScalingGroup',
              'UpdateAutoScalingGroup',
              'SetDesiredCapacity',
              'ExecutePolicy',
              'PutScalingPolicy'
          )
          AND eventtime >= '{since_str}'
        ORDER BY eventtime DESC
        LIMIT 100
    """

    try:
        athena = _build_athena_client(region)
        results = _run_athena_query(
            athena_client=athena,
            query=query,
            database=cloudtrail_database,
            results_bucket=results_bucket,
        )
        logger.info(
            "Auto Scaling change events fetched",
            extra={"count": len(results), "hours": hours},
        )
        return results
    except Exception as exc:
        logger.warning("Could not fetch Auto Scaling events: %s", exc)
        return []


def get_rds_changes(
    region: str,
    cloudtrail_database: str,
    cloudtrail_table: str,
    results_bucket: str,
    hours: int = 24,
) -> list[dict[str, Any]]:
    """Query CloudTrail for RDS instance creation and modification events.

    Args:
        region: AWS region for the Athena client.
        cloudtrail_database: Athena database name.
        cloudtrail_table: Athena table name.
        results_bucket: S3 output location for Athena results.
        hours: Look-back window in hours.

    Returns:
        List of event dicts for RDS changes.
    """
    since = _utcnow() - timedelta(hours=hours)
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")

    query = f"""
        SELECT
            eventtime,
            eventname,
            useridentity.arn AS useridentity_arn,
            requestparameters,
            sourceipaddress,
            awsregion
        FROM {cloudtrail_table}
        WHERE eventsource = 'rds.amazonaws.com'
          AND eventname IN (
              'CreateDBInstance',
              'ModifyDBInstance',
              'RestoreDBInstanceFromDBSnapshot',
              'CreateDBCluster',
              'ModifyDBCluster'
          )
          AND eventtime >= '{since_str}'
        ORDER BY eventtime DESC
        LIMIT 50
    """

    try:
        athena = _build_athena_client(region)
        results = _run_athena_query(
            athena_client=athena,
            query=query,
            database=cloudtrail_database,
            results_bucket=results_bucket,
        )
        logger.info(
            "RDS change events fetched",
            extra={"count": len(results), "hours": hours},
        )
        return results
    except Exception as exc:
        logger.warning("Could not fetch RDS change events: %s", exc)
        return []


def get_iam_changes(
    region: str,
    cloudtrail_database: str,
    cloudtrail_table: str,
    results_bucket: str,
    hours: int = 24,
) -> list[dict[str, Any]]:
    """Query CloudTrail for IAM permission changes (policy attachments, role creation).

    Args:
        region: AWS region for the Athena client.
        cloudtrail_database: Athena database name.
        cloudtrail_table: Athena table name.
        results_bucket: S3 output location for Athena results.
        hours: Look-back window in hours.

    Returns:
        List of event dicts for IAM changes.
    """
    since = _utcnow() - timedelta(hours=hours)
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")

    query = f"""
        SELECT
            eventtime,
            eventname,
            useridentity.arn AS useridentity_arn,
            requestparameters,
            sourceipaddress,
            awsregion
        FROM {cloudtrail_table}
        WHERE eventsource = 'iam.amazonaws.com'
          AND eventname IN (
              'CreateRole',
              'AttachRolePolicy',
              'PutRolePolicy',
              'CreatePolicy',
              'AttachUserPolicy',
              'CreateUser'
          )
          AND eventtime >= '{since_str}'
        ORDER BY eventtime DESC
        LIMIT 50
    """

    try:
        athena = _build_athena_client(region)
        results = _run_athena_query(
            athena_client=athena,
            query=query,
            database=cloudtrail_database,
            results_bucket=results_bucket,
        )
        logger.info(
            "IAM change events fetched",
            extra={"count": len(results), "hours": hours},
        )
        return results
    except Exception as exc:
        logger.warning("Could not fetch IAM change events: %s", exc)
        return []


def get_resource_changes_summary(
    region: str,
    cloudtrail_database: str,
    cloudtrail_table: str,
    results_bucket: str,
    hours: int = 24,
) -> dict[str, Any]:
    """Consolidate all resource changes into a single summary dict.

    Queries EC2 launches, Auto Scaling changes, RDS changes, and IAM changes
    in parallel (sequentially for simplicity) and returns a structured summary
    suitable for passing to the Bedrock analysis prompt.

    Args:
        region: AWS region for the Athena client.
        cloudtrail_database: Athena database name.
        cloudtrail_table: Athena table name.
        results_bucket: S3 output location for Athena results.
        hours: Look-back window in hours.

    Returns:
        Dict with keys: ec2_launches, autoscaling_changes, rds_changes,
        iam_changes, total_events, query_window_hours.
    """
    kwargs = dict(
        region=region,
        cloudtrail_database=cloudtrail_database,
        cloudtrail_table=cloudtrail_table,
        results_bucket=results_bucket,
        hours=hours,
    )

    ec2 = get_ec2_launches_last_24h(**kwargs)
    asg = get_autoscaling_changes(**kwargs)
    rds = get_rds_changes(**kwargs)
    iam = get_iam_changes(**kwargs)

    total = len(ec2) + len(asg) + len(rds) + len(iam)

    summary = {
        "ec2_launches": ec2,
        "autoscaling_changes": asg,
        "rds_changes": rds,
        "iam_changes": iam,
        "total_events": total,
        "query_window_hours": hours,
    }

    logger.info(
        "CloudTrail resource changes summary",
        extra={
            "ec2_launches": len(ec2),
            "asg_changes": len(asg),
            "rds_changes": len(rds),
            "iam_changes": len(iam),
            "total": total,
        },
    )
    return summary


def format_changes_for_prompt(summary: dict[str, Any]) -> str:
    """Format a resource changes summary dict into a human-readable prompt section.

    Args:
        summary: Dict returned by :func:`get_resource_changes_summary`.

    Returns:
        Multi-line string describing the detected resource changes.
    """
    lines: list[str] = []
    hours = summary.get("query_window_hours", 24)
    total = summary.get("total_events", 0)

    lines.append(f"### CloudTrail Resource Changes (Last {hours}h) — {total} events")
    lines.append("")

    ec2 = summary.get("ec2_launches", [])
    if ec2:
        lines.append(f"**EC2 Launches** ({len(ec2)} events):")
        for event in ec2[:10]:
            ts = event.get("eventtime", "unknown")
            actor = event.get("useridentity_arn", "unknown")
            params = event.get("requestparameters", "")
            lines.append(f"  - [{ts}] {actor}: {str(params)[:120]}")
    else:
        lines.append("**EC2 Launches**: None detected")

    lines.append("")

    asg = summary.get("autoscaling_changes", [])
    if asg:
        lines.append(f"**Auto Scaling Changes** ({len(asg)} events):")
        for event in asg[:10]:
            ts = event.get("eventtime", "unknown")
            name = event.get("eventname", "unknown")
            params = event.get("requestparameters", "")
            lines.append(f"  - [{ts}] {name}: {str(params)[:120]}")
    else:
        lines.append("**Auto Scaling Changes**: None detected")

    lines.append("")

    rds = summary.get("rds_changes", [])
    if rds:
        lines.append(f"**RDS Changes** ({len(rds)} events):")
        for event in rds[:5]:
            ts = event.get("eventtime", "unknown")
            name = event.get("eventname", "unknown")
            params = event.get("requestparameters", "")
            lines.append(f"  - [{ts}] {name}: {str(params)[:120]}")
    else:
        lines.append("**RDS Changes**: None detected")

    lines.append("")

    iam = summary.get("iam_changes", [])
    if iam:
        lines.append(f"**IAM Changes** ({len(iam)} events):")
        for event in iam[:5]:
            ts = event.get("eventtime", "unknown")
            name = event.get("eventname", "unknown")
            actor = event.get("useridentity_arn", "unknown")
            lines.append(f"  - [{ts}] {name} by {actor}")
    else:
        lines.append("**IAM Changes**: None detected")

    return "\n".join(lines)
