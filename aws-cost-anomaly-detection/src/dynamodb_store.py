"""DynamoDB Store for FinOps State Management.

Provides persistent state storage for:
- Daily cost baselines (7-day rolling window)
- Idempotency tokens (prevent duplicate Slack alerts)
- CloudTrail query result cache (30-minute TTL)
- Anomaly detection results with timestamps
"""

import logging
import time
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Optional

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

# Default table name; can be overridden via environment variable
DEFAULT_TABLE_NAME = "finops-cost-baselines"

# TTL durations (seconds)
_CACHE_TTL_S = 1800       # 30 minutes for CloudTrail query cache
_BASELINE_TTL_S = 90 * 24 * 3600   # 90 days for cost baseline records
_ANOMALY_TTL_S = 30 * 24 * 3600    # 30 days for anomaly records


class DynamoDBException(Exception):
    """Raised for DynamoDB operation failures."""

    pass


def _build_dynamodb_resource(region: str) -> Any:
    """Create a boto3 DynamoDB resource.

    Args:
        region: AWS region name.

    Returns:
        boto3 DynamoDB resource.
    """
    return boto3.resource("dynamodb", region_name=region)


def _now_epoch() -> int:
    """Return the current Unix epoch timestamp as an integer."""
    return int(time.time())


def put_item(
    table_name: str,
    execution_date: str,
    metric_type: str,
    data: dict[str, Any],
    region: str,
    ttl_seconds: Optional[int] = None,
) -> None:
    """Write an item to the FinOps DynamoDB table.

    The table uses a composite key of (execution_date, metric_type).

    Args:
        table_name: DynamoDB table name.
        execution_date: Partition key — ISO date string (YYYY-MM-DD).
        metric_type: Sort key — one of ``baseline``, ``anomaly``,
                     ``cloudtrail_cache``, ``idempotency``.
        data: Payload dict to store alongside the key.
        region: AWS region for the DynamoDB client.
        ttl_seconds: Optional TTL in seconds from now. When provided, an
                     ``expiration_time`` attribute is added and DynamoDB will
                     auto-delete the item after expiry.

    Raises:
        DynamoDBException: On DynamoDB API failures.
    """
    dynamodb = _build_dynamodb_resource(region)
    table = dynamodb.Table(table_name)

    item: dict[str, Any] = {
        "execution_date": execution_date,
        "metric_type": metric_type,
        "updated_at": datetime.now(tz=timezone.utc).isoformat(),
        **data,
    }

    if ttl_seconds is not None:
        item["expiration_time"] = _now_epoch() + ttl_seconds

    # DynamoDB does not accept Python floats natively; convert to Decimal
    item = _serialize_floats(item)

    try:
        table.put_item(Item=item)
        logger.debug(
            "DynamoDB put_item succeeded",
            extra={
                "table": table_name,
                "pk": execution_date,
                "sk": metric_type,
            },
        )
    except (ClientError, BotoCoreError) as exc:
        raise DynamoDBException(
            f"Failed to write item ({execution_date}/{metric_type}) "
            f"to DynamoDB table '{table_name}': {exc}"
        ) from exc


def get_item(
    table_name: str,
    execution_date: str,
    metric_type: str,
    region: str,
) -> Optional[dict[str, Any]]:
    """Retrieve a single item from the FinOps DynamoDB table.

    Args:
        table_name: DynamoDB table name.
        execution_date: Partition key — ISO date string.
        metric_type: Sort key.
        region: AWS region for the DynamoDB client.

    Returns:
        Item dict if found, ``None`` otherwise.

    Raises:
        DynamoDBException: On DynamoDB API failures.
    """
    dynamodb = _build_dynamodb_resource(region)
    table = dynamodb.Table(table_name)

    try:
        response = table.get_item(
            Key={"execution_date": execution_date, "metric_type": metric_type}
        )
        item = response.get("Item")
        if item:
            item = _deserialize_decimals(item)
        return item
    except (ClientError, BotoCoreError) as exc:
        raise DynamoDBException(
            f"Failed to get item ({execution_date}/{metric_type}) "
            f"from DynamoDB table '{table_name}': {exc}"
        ) from exc


def query_range(
    table_name: str,
    execution_date_start: str,
    execution_date_end: str,
    metric_type: str,
    region: str,
) -> list[dict[str, Any]]:
    """Query items for a date range and specific metric type.

    Uses the GSI (metric_type-execution_date-index) when querying by metric_type
    across multiple dates. Falls back to scan-with-filter when the GSI is
    unavailable.

    Args:
        table_name: DynamoDB table name.
        execution_date_start: Inclusive start date (YYYY-MM-DD).
        execution_date_end: Inclusive end date (YYYY-MM-DD).
        metric_type: Sort key to filter on.
        region: AWS region for the DynamoDB client.

    Returns:
        List of matching item dicts ordered by execution_date ascending.

    Raises:
        DynamoDBException: On DynamoDB API failures.
    """
    dynamodb = _build_dynamodb_resource(region)
    table = dynamodb.Table(table_name)

    try:
        response = table.query(
            IndexName="metric_type-execution_date-index",
            KeyConditionExpression=(
                Key("metric_type").eq(metric_type)
                & Key("execution_date").between(execution_date_start, execution_date_end)
            ),
        )
        items = response.get("Items", [])
        items = [_deserialize_decimals(item) for item in items]
        items.sort(key=lambda x: x.get("execution_date", ""))
        logger.info(
            "DynamoDB range query completed",
            extra={
                "table": table_name,
                "metric_type": metric_type,
                "start": execution_date_start,
                "end": execution_date_end,
                "count": len(items),
            },
        )
        return items
    except (ClientError, BotoCoreError) as exc:
        raise DynamoDBException(
            f"Failed to query range [{execution_date_start}, {execution_date_end}] "
            f"metric_type={metric_type} from '{table_name}': {exc}"
        ) from exc


def store_cost_baseline(
    table_name: str,
    execution_date: str,
    cost_usd: float,
    region: str,
) -> None:
    """Persist a daily cost value as a baseline record.

    Args:
        table_name: DynamoDB table name.
        execution_date: Date of the cost record (YYYY-MM-DD).
        cost_usd: Total cost in USD for that day.
        region: AWS region for the DynamoDB client.
    """
    put_item(
        table_name=table_name,
        execution_date=execution_date,
        metric_type="baseline",
        data={"cost_usd": Decimal(str(round(cost_usd, 6)))},
        region=region,
        ttl_seconds=_BASELINE_TTL_S,
    )
    logger.info(
        "Cost baseline stored",
        extra={"date": execution_date, "cost_usd": cost_usd},
    )


def get_baseline_costs(
    table_name: str,
    start_date: str,
    end_date: str,
    region: str,
) -> list[float]:
    """Retrieve stored daily cost baselines for a date range.

    Returns values ordered chronologically (oldest first) for use in
    rolling-average calculations.

    Args:
        table_name: DynamoDB table name.
        start_date: Inclusive start date (YYYY-MM-DD).
        end_date: Inclusive end date (YYYY-MM-DD).
        region: AWS region for the DynamoDB client.

    Returns:
        List of cost values in USD, ordered by date ascending.
    """
    try:
        items = query_range(
            table_name=table_name,
            execution_date_start=start_date,
            execution_date_end=end_date,
            metric_type="baseline",
            region=region,
        )
        costs = [float(item["cost_usd"]) for item in items if "cost_usd" in item]
        logger.info(
            "Baseline costs retrieved",
            extra={"count": len(costs), "start": start_date, "end": end_date},
        )
        return costs
    except DynamoDBException as exc:
        logger.warning("Could not retrieve baseline costs: %s", exc)
        return []


def cache_cloudtrail_results(
    table_name: str,
    cache_key: str,
    results: dict[str, Any],
    region: str,
) -> None:
    """Cache CloudTrail Athena query results to avoid repeated queries.

    Items expire automatically after 30 minutes via DynamoDB TTL.

    Args:
        table_name: DynamoDB table name.
        cache_key: Unique cache key (e.g., date + query type).
        results: CloudTrail query results dict to cache.
        region: AWS region for the DynamoDB client.
    """
    import json
    try:
        put_item(
            table_name=table_name,
            execution_date=cache_key,
            metric_type="cloudtrail_cache",
            data={"results_json": json.dumps(results)},
            region=region,
            ttl_seconds=_CACHE_TTL_S,
        )
        logger.debug("CloudTrail results cached", extra={"cache_key": cache_key})
    except DynamoDBException as exc:
        logger.warning("Could not cache CloudTrail results: %s", exc)


def get_cached_cloudtrail_results(
    table_name: str,
    cache_key: str,
    region: str,
) -> Optional[dict[str, Any]]:
    """Retrieve cached CloudTrail query results if still valid.

    Args:
        table_name: DynamoDB table name.
        cache_key: Cache key used when storing.
        region: AWS region for the DynamoDB client.

    Returns:
        Cached results dict, or ``None`` if not found or expired.
    """
    import json
    try:
        item = get_item(
            table_name=table_name,
            execution_date=cache_key,
            metric_type="cloudtrail_cache",
            region=region,
        )
        if item and "results_json" in item:
            expiry = item.get("expiration_time", 0)
            if expiry and _now_epoch() > int(expiry):
                return None
            return json.loads(item["results_json"])
        return None
    except DynamoDBException as exc:
        logger.warning("Could not retrieve cached CloudTrail results: %s", exc)
        return None


def store_anomaly_result(
    table_name: str,
    execution_date: str,
    analysis_id: str,
    anomaly_data: dict[str, Any],
    region: str,
) -> None:
    """Persist an anomaly detection result for audit and idempotency.

    Args:
        table_name: DynamoDB table name.
        execution_date: Date of the anomaly (YYYY-MM-DD).
        analysis_id: Unique analysis run identifier.
        anomaly_data: Dict with anomaly metrics and findings.
        region: AWS region for the DynamoDB client.
    """
    put_item(
        table_name=table_name,
        execution_date=execution_date,
        metric_type="anomaly",
        data={"analysis_id": analysis_id, **anomaly_data},
        region=region,
        ttl_seconds=_ANOMALY_TTL_S,
    )
    logger.info(
        "Anomaly result stored",
        extra={"date": execution_date, "analysis_id": analysis_id},
    )


def check_idempotency(
    table_name: str,
    execution_date: str,
    region: str,
) -> bool:
    """Check whether today's analysis has already been completed.

    Args:
        table_name: DynamoDB table name.
        execution_date: Today's date string (YYYY-MM-DD).
        region: AWS region for the DynamoDB client.

    Returns:
        ``True`` if an idempotency record exists for today.
    """
    try:
        item = get_item(
            table_name=table_name,
            execution_date=execution_date,
            metric_type="idempotency",
            region=region,
        )
        exists = item is not None
        if exists:
            logger.info(
                "Idempotency check: analysis already completed",
                extra={"date": execution_date},
            )
        return exists
    except DynamoDBException as exc:
        logger.warning(
            "Could not check idempotency (proceeding anyway): %s", exc
        )
        return False


def record_idempotency(
    table_name: str,
    execution_date: str,
    analysis_id: str,
    result_summary: dict[str, Any],
    region: str,
) -> None:
    """Persist an idempotency record to prevent duplicate pipeline runs.

    Args:
        table_name: DynamoDB table name.
        execution_date: Execution date (YYYY-MM-DD).
        analysis_id: Unique analysis identifier.
        result_summary: High-level result metadata to store.
        region: AWS region for the DynamoDB client.
    """
    try:
        put_item(
            table_name=table_name,
            execution_date=execution_date,
            metric_type="idempotency",
            data={"analysis_id": analysis_id, **result_summary},
            region=region,
            ttl_seconds=_BASELINE_TTL_S,
        )
        logger.info(
            "Idempotency record saved",
            extra={"date": execution_date, "analysis_id": analysis_id},
        )
    except DynamoDBException as exc:
        logger.warning("Could not write idempotency record (non-fatal): %s", exc)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _serialize_floats(obj: Any) -> Any:
    """Recursively convert Python floats to Decimal for DynamoDB compatibility."""
    if isinstance(obj, float):
        return Decimal(str(round(obj, 10)))
    if isinstance(obj, dict):
        return {k: _serialize_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize_floats(v) for v in obj]
    return obj


def _deserialize_decimals(obj: Any) -> Any:
    """Recursively convert DynamoDB Decimal values back to float."""
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: _deserialize_decimals(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deserialize_decimals(v) for v in obj]
    return obj
