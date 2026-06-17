"""Utilization Analyzer for EC2, RDS, and Lambda resources.

Queries CloudWatch metrics to identify underutilized resources running at
<20% CPU/memory for 7+ days, enabling right-sizing recommendations and
cost reduction opportunities.

Results are cached in DynamoDB for 24 hours to minimise CloudWatch API costs.
"""

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import boto3
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

# Retry configuration for AWS API calls
_RETRY_CONFIG = BotocoreConfig(
    retries={"max_attempts": 3, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=30,
)

# Thresholds
_CPU_THRESHOLD_PCT = 20.0
_CONNECTIONS_THRESHOLD = 5
_NETWORK_BYTES_THRESHOLD = 1 * 1024 * 1024 * 1024  # 1 GB per day

# DynamoDB cache TTL: 24 hours
_CACHE_TTL_S = 24 * 3600
_CACHE_METRIC_TYPE = "utilization_cache"

# Approximate monthly cost multipliers by instance type family (on-demand, USD/month)
# Used for rough savings estimates where Pricing API is not called.
_EC2_MONTHLY_COST: dict[str, float] = {
    "t3.nano": 3.80, "t3.micro": 7.59, "t3.small": 15.18, "t3.medium": 30.37,
    "t3.large": 60.74, "t3.xlarge": 121.47, "t3.2xlarge": 242.94,
    "t2.micro": 8.47, "t2.small": 16.94, "t2.medium": 33.87,
    "m5.large": 70.08, "m5.xlarge": 140.16, "m5.2xlarge": 280.32,
    "m5.4xlarge": 560.64, "m5.8xlarge": 1121.28,
    "m6i.large": 72.96, "m6i.xlarge": 145.92, "m6i.2xlarge": 291.84,
    "c5.large": 62.05, "c5.xlarge": 124.10, "c5.2xlarge": 248.19,
    "r5.large": 91.98, "r5.xlarge": 183.96, "r5.2xlarge": 367.92,
}

# Downsize recommendations: current_type -> recommended_type
_EC2_DOWNSIZE_MAP: dict[str, str] = {
    "m5.xlarge": "t3.large", "m5.2xlarge": "t3.xlarge", "m5.4xlarge": "m5.2xlarge",
    "m5.large": "t3.medium",
    "m6i.xlarge": "t3.large", "m6i.2xlarge": "t3.xlarge",
    "c5.xlarge": "t3.large", "c5.2xlarge": "c5.xlarge",
    "r5.xlarge": "r5.large", "r5.2xlarge": "r5.xlarge",
    "t3.2xlarge": "t3.xlarge", "t3.xlarge": "t3.large", "t3.large": "t3.medium",
}

_RDS_DOWNSIZE_MAP: dict[str, str] = {
    "db.m5.xlarge": "db.t3.large", "db.m5.2xlarge": "db.t3.xlarge",
    "db.m5.large": "db.t3.medium", "db.m6g.xlarge": "db.t3.large",
    "db.r5.xlarge": "db.r5.large", "db.r5.2xlarge": "db.r5.xlarge",
    "db.t3.xlarge": "db.t3.large", "db.t3.large": "db.t3.medium",
}

_RDS_MONTHLY_COST: dict[str, float] = {
    "db.t3.micro": 12.41, "db.t3.small": 24.82, "db.t3.medium": 49.64,
    "db.t3.large": 99.28, "db.t3.xlarge": 198.58,
    "db.m5.large": 124.10, "db.m5.xlarge": 248.19, "db.m5.2xlarge": 496.39,
    "db.r5.large": 175.20, "db.r5.xlarge": 350.40, "db.r5.2xlarge": 700.80,
}


def _cloudwatch_client(region: str) -> Any:
    """Build a CloudWatch boto3 client with retry config."""
    return boto3.client("cloudwatch", region_name=region, config=_RETRY_CONFIG)


def _ec2_client(region: str) -> Any:
    """Build an EC2 boto3 client with retry config."""
    return boto3.client("ec2", region_name=region, config=_RETRY_CONFIG)


def _lambda_client(region: str) -> Any:
    """Build a Lambda boto3 client with retry config."""
    return boto3.client("lambda", region_name=region, config=_RETRY_CONFIG)


def _rds_client(region: str) -> Any:
    """Build an RDS boto3 client with retry config."""
    return boto3.client("rds", region_name=region, config=_RETRY_CONFIG)


def _dynamodb_client(region: str) -> Any:
    """Build a DynamoDB resource for cache operations."""
    return boto3.resource("dynamodb", region_name=region, config=_RETRY_CONFIG)


def _now_epoch() -> int:
    """Return the current Unix epoch timestamp."""
    return int(time.time())


def _get_cache(
    table_name: str, cache_key: str, region: str
) -> Optional[Any]:
    """Retrieve a cached result from DynamoDB.

    Args:
        table_name: DynamoDB table name.
        cache_key: Unique identifier for the cached entry.
        region: AWS region.

    Returns:
        Cached data dict if valid and unexpired, otherwise ``None``.
    """
    try:
        dynamodb = _dynamodb_client(region)
        table = dynamodb.Table(table_name)
        response = table.get_item(
            Key={"execution_date": cache_key, "metric_type": _CACHE_METRIC_TYPE}
        )
        item = response.get("Item")
        if not item:
            return None
        expiry = item.get("expiration_time", 0)
        if expiry and _now_epoch() > int(expiry):
            return None
        payload = item.get("results_json")
        return json.loads(payload) if payload else None
    except Exception as exc:
        logger.warning("Cache read failed (proceeding without cache): %s", exc)
        return None


def _set_cache(
    table_name: str, cache_key: str, data: Any, region: str
) -> None:
    """Persist a result to DynamoDB cache with 24-hour TTL.

    Args:
        table_name: DynamoDB table name.
        cache_key: Unique identifier for the cached entry.
        data: Serialisable data to store.
        region: AWS region.
    """
    try:
        dynamodb = _dynamodb_client(region)
        table = dynamodb.Table(table_name)
        table.put_item(
            Item={
                "execution_date": cache_key,
                "metric_type": _CACHE_METRIC_TYPE,
                "results_json": json.dumps(data),
                "expiration_time": _now_epoch() + _CACHE_TTL_S,
                "updated_at": datetime.now(tz=timezone.utc).isoformat(),
            }
        )
    except Exception as exc:
        logger.warning("Cache write failed (non-fatal): %s", exc)


def _get_metric_statistics(
    cw_client: Any,
    namespace: str,
    metric_name: str,
    dimensions: list[dict[str, str]],
    days: int = 7,
    period: int = 86400,
    statistic: str = "Average",
) -> Optional[float]:
    """Fetch the aggregate statistic for a CloudWatch metric over the last N days.

    Args:
        cw_client: boto3 CloudWatch client.
        namespace: CloudWatch namespace (e.g. ``AWS/EC2``).
        metric_name: Metric name (e.g. ``CPUUtilization``).
        dimensions: List of dimension dicts ``[{"Name": k, "Value": v}, ...]``.
        days: Lookback window in days.
        period: Aggregation period in seconds (default 1 day).
        statistic: ``Average``, ``Maximum``, ``Sum``, etc.

    Returns:
        Numeric value if data points exist, otherwise ``None``.
    """
    end_time = datetime.now(tz=timezone.utc)
    start_time = end_time - timedelta(days=days)
    try:
        response = cw_client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start_time,
            EndTime=end_time,
            Period=period * days,
            Statistics=[statistic],
        )
        datapoints = response.get("Datapoints", [])
        if not datapoints:
            return None
        return float(datapoints[0][statistic])
    except (ClientError, BotoCoreError) as exc:
        logger.warning(
            "CloudWatch metric %s/%s query failed: %s", namespace, metric_name, exc
        )
        return None


def _paginate_ec2_instances(ec2: Any) -> list[dict[str, Any]]:
    """Return all running EC2 instances using pagination.

    Args:
        ec2: boto3 EC2 client.

    Returns:
        List of EC2 instance dicts.
    """
    instances: list[dict[str, Any]] = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
        for reservation in page.get("Reservations", []):
            instances.extend(reservation.get("Instances", []))
    return instances


def get_underutilized_ec2_instances(
    region: str = "ap-south-1",
    table_name: str = "finops-cost-baselines",
    cpu_threshold: float = _CPU_THRESHOLD_PCT,
    lookback_days: int = 7,
) -> list[dict[str, Any]]:
    """Identify EC2 instances with average CPU utilization below the threshold.

    Filters out instances launched within the last 24 hours (too new to evaluate)
    and instances tagged with ``ScheduledScaling=true``.

    Args:
        region: AWS region.
        table_name: DynamoDB table for caching results.
        cpu_threshold: CPU percentage below which an instance is considered
                       underutilised (default 20%).
        lookback_days: Number of days to average CPU metrics over.

    Returns:
        List of dicts with keys: ``instance_id``, ``instance_type``,
        ``current_type``, ``avg_cpu``, ``monthly_cost``,
        ``recommended_type``, ``estimated_savings``.
    """
    cache_key = f"ec2_utilization_{region}_{lookback_days}d"
    cached = _get_cache(table_name, cache_key, region)
    if cached is not None:
        logger.info("Returning cached EC2 utilization results for %s", region)
        return cached

    results: list[dict[str, Any]] = []
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=24)

    try:
        ec2 = _ec2_client(region)
        cw = _cloudwatch_client(region)
        instances = _paginate_ec2_instances(ec2)
        logger.info("Evaluating %d running EC2 instances in %s", len(instances), region)

        for inst in instances:
            iid = inst["InstanceId"]
            itype = inst.get("InstanceType", "unknown")

            # Skip recently launched instances
            launch_time = inst.get("LaunchTime")
            if launch_time and launch_time > cutoff:
                logger.debug("Skipping recently launched instance %s", iid)
                continue

            # Skip instances tagged as scheduled scaling
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            if tags.get("ScheduledScaling", "").lower() == "true":
                logger.debug("Skipping scheduled-scaling instance %s", iid)
                continue

            avg_cpu = _get_metric_statistics(
                cw_client=cw,
                namespace="AWS/EC2",
                metric_name="CPUUtilization",
                dimensions=[{"Name": "InstanceId", "Value": iid}],
                days=lookback_days,
            )

            if avg_cpu is None:
                logger.debug("No CPU data for instance %s — skipping", iid)
                continue

            if avg_cpu >= cpu_threshold:
                continue

            monthly_cost = _EC2_MONTHLY_COST.get(itype, 0.0)
            recommended_type = _EC2_DOWNSIZE_MAP.get(itype, "")
            rec_cost = _EC2_MONTHLY_COST.get(recommended_type, 0.0)
            estimated_savings = monthly_cost - rec_cost if recommended_type else 0.0

            results.append(
                {
                    "instance_id": iid,
                    "instance_type": itype,
                    "current_type": itype,
                    "avg_cpu": round(avg_cpu, 2),
                    "monthly_cost": monthly_cost,
                    "recommended_type": recommended_type or "review-manually",
                    "estimated_savings": round(estimated_savings, 2),
                    "name": tags.get("Name", iid),
                    "environment": tags.get("Environment", "unknown"),
                }
            )

        logger.info(
            "Found %d underutilized EC2 instances (<%d%% CPU over %d days)",
            len(results),
            int(cpu_threshold),
            lookback_days,
        )
        _set_cache(table_name, cache_key, results, region)
        return results

    except (ClientError, BotoCoreError) as exc:
        logger.error("EC2 utilization analysis failed: %s", exc)
        return []


def get_underutilized_rds_instances(
    region: str = "ap-south-1",
    table_name: str = "finops-cost-baselines",
    cpu_threshold: float = _CPU_THRESHOLD_PCT,
    connection_threshold: int = _CONNECTIONS_THRESHOLD,
    lookback_days: int = 7,
) -> list[dict[str, Any]]:
    """Identify RDS instances with low CPU and database connections.

    An RDS instance is considered underutilised when average CPU < threshold
    AND average DatabaseConnections < connection threshold over the lookback period.

    Args:
        region: AWS region.
        table_name: DynamoDB table for caching results.
        cpu_threshold: CPU percentage threshold (default 20%).
        connection_threshold: Connection count threshold (default 5).
        lookback_days: Days to average metrics over.

    Returns:
        List of dicts with keys: ``instance_id``, ``instance_class``,
        ``avg_cpu``, ``avg_connections``, ``monthly_cost``,
        ``recommended_class``, ``estimated_savings``.
    """
    cache_key = f"rds_utilization_{region}_{lookback_days}d"
    cached = _get_cache(table_name, cache_key, region)
    if cached is not None:
        logger.info("Returning cached RDS utilization results for %s", region)
        return cached

    results: list[dict[str, Any]] = []

    try:
        rds = _rds_client(region)
        cw = _cloudwatch_client(region)

        paginator = rds.get_paginator("describe_db_instances")
        db_instances: list[dict[str, Any]] = []
        for page in paginator.paginate():
            db_instances.extend(page.get("DBInstances", []))

        logger.info("Evaluating %d RDS instances in %s", len(db_instances), region)

        for db in db_instances:
            if db.get("DBInstanceStatus") != "available":
                continue

            db_id = db["DBInstanceIdentifier"]
            db_class = db.get("DBInstanceClass", "unknown")
            dimensions = [{"Name": "DBInstanceIdentifier", "Value": db_id}]

            avg_cpu = _get_metric_statistics(
                cw_client=cw,
                namespace="AWS/RDS",
                metric_name="CPUUtilization",
                dimensions=dimensions,
                days=lookback_days,
            )
            avg_conns = _get_metric_statistics(
                cw_client=cw,
                namespace="AWS/RDS",
                metric_name="DatabaseConnections",
                dimensions=dimensions,
                days=lookback_days,
            )

            if avg_cpu is None or avg_conns is None:
                logger.debug("Insufficient metrics for RDS instance %s — skipping", db_id)
                continue

            if avg_cpu >= cpu_threshold or avg_conns >= connection_threshold:
                continue

            monthly_cost = _RDS_MONTHLY_COST.get(db_class, 0.0)
            recommended_class = _RDS_DOWNSIZE_MAP.get(db_class, "")
            rec_cost = _RDS_MONTHLY_COST.get(recommended_class, 0.0)
            estimated_savings = monthly_cost - rec_cost if recommended_class else 0.0

            results.append(
                {
                    "instance_id": db_id,
                    "instance_class": db_class,
                    "avg_cpu": round(avg_cpu, 2),
                    "avg_connections": round(avg_conns, 2),
                    "monthly_cost": monthly_cost,
                    "recommended_class": recommended_class or "review-manually",
                    "estimated_savings": round(estimated_savings, 2),
                    "engine": db.get("Engine", "unknown"),
                    "multi_az": db.get("MultiAZ", False),
                }
            )

        logger.info("Found %d underutilized RDS instances", len(results))
        _set_cache(table_name, cache_key, results, region)
        return results

    except (ClientError, BotoCoreError) as exc:
        logger.error("RDS utilization analysis failed: %s", exc)
        return []


def get_oversized_lambda_functions(
    region: str = "ap-south-1",
    table_name: str = "finops-cost-baselines",
    lookback_days: int = 7,
) -> list[dict[str, Any]]:
    """Identify Lambda functions where allocated memory far exceeds actual usage.

    Compares allocated memory to the 95th-percentile duration-derived memory
    estimate. Functions where max duration implies <50% of allocated memory is
    used are flagged for right-sizing.

    Args:
        region: AWS region.
        table_name: DynamoDB table for caching results.
        lookback_days: Days to analyse Lambda Duration metrics.

    Returns:
        List of dicts with keys: ``function_name``, ``allocated_memory``,
        ``max_duration``, ``recommended_memory``, ``estimated_savings``.
    """
    cache_key = f"lambda_utilization_{region}_{lookback_days}d"
    cached = _get_cache(table_name, cache_key, region)
    if cached is not None:
        logger.info("Returning cached Lambda utilization results for %s", region)
        return cached

    results: list[dict[str, Any]] = []

    try:
        lam = _lambda_client(region)
        cw = _cloudwatch_client(region)
        end_time = datetime.now(tz=timezone.utc)
        start_time = end_time - timedelta(days=lookback_days)

        paginator = lam.get_paginator("list_functions")
        functions: list[dict[str, Any]] = []
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))

        logger.info("Evaluating %d Lambda functions in %s", len(functions), region)

        for fn in functions:
            fname = fn["FunctionName"]
            allocated_mb = fn.get("MemorySize", 128)

            try:
                p95_response = cw.get_metric_statistics(
                    Namespace="AWS/Lambda",
                    MetricName="Duration",
                    Dimensions=[{"Name": "FunctionName", "Value": fname}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400 * lookback_days,
                    Statistics=["Maximum"],
                    ExtendedStatistics=["p95"],
                )
            except (ClientError, BotoCoreError) as exc:
                logger.debug("Duration metric unavailable for %s: %s", fname, exc)
                continue

            datapoints = p95_response.get("Datapoints", [])
            if not datapoints:
                continue

            p95_duration_ms = float(datapoints[0].get("ExtendedStatistics", {}).get("p95", 0))
            max_duration_ms = float(datapoints[0].get("Maximum", p95_duration_ms))

            if max_duration_ms <= 0:
                continue

            # Lambda charges per ms; if max duration < 50% of timeout, memory may be oversized.
            # We recommend the next-lower standard memory tier.
            memory_tiers = [128, 256, 512, 1024, 1536, 2048, 3008, 4096, 6144, 8192, 10240]
            current_idx = memory_tiers.index(allocated_mb) if allocated_mb in memory_tiers else None
            if current_idx is None or current_idx == 0:
                continue

            # Cost ratio: Lambda billed in GB-seconds
            # If 95th-percentile duration implies < 50% memory needed, recommend one step down.
            # This is a heuristic; actual usage requires Lambda Power Tuning.
            if p95_duration_ms < (allocated_mb / 128.0) * 100:
                recommended_mb = memory_tiers[current_idx - 1]
                # Approximate cost: $0.0000166667 per GB-second, 1M invocations/month assumed
                gb_seconds_current = (allocated_mb / 1024.0) * (p95_duration_ms / 1000.0) * 1_000_000
                gb_seconds_rec = (recommended_mb / 1024.0) * (p95_duration_ms / 1000.0) * 1_000_000
                monthly_savings = (gb_seconds_current - gb_seconds_rec) * 0.0000166667

                results.append(
                    {
                        "function_name": fname,
                        "allocated_memory": allocated_mb,
                        "max_duration": round(max_duration_ms, 2),
                        "p95_duration": round(p95_duration_ms, 2),
                        "recommended_memory": recommended_mb,
                        "estimated_savings": round(monthly_savings, 2),
                        "runtime": fn.get("Runtime", "unknown"),
                    }
                )

        logger.info("Found %d oversized Lambda functions", len(results))
        _set_cache(table_name, cache_key, results, region)
        return results

    except (ClientError, BotoCoreError) as exc:
        logger.error("Lambda utilization analysis failed: %s", exc)
        return []


def get_network_underutilization(
    region: str = "ap-south-1",
    table_name: str = "finops-cost-baselines",
    daily_bytes_threshold: int = _NETWORK_BYTES_THRESHOLD,
    lookback_days: int = 7,
) -> list[dict[str, Any]]:
    """Identify EC2 instances with very low network traffic.

    Instances with average daily NetworkIn + NetworkOut below the threshold
    may be idle or candidates for NAT gateway optimisation.

    Args:
        region: AWS region.
        table_name: DynamoDB table for caching results.
        daily_bytes_threshold: Minimum bytes/day to be considered active (default 1 GB).
        lookback_days: Days to average network metrics over.

    Returns:
        List of dicts with keys: ``instance_id``, ``instance_type``,
        ``avg_network_in_bytes``, ``avg_network_out_bytes``,
        ``total_daily_bytes``, ``recommendation``.
    """
    cache_key = f"network_utilization_{region}_{lookback_days}d"
    cached = _get_cache(table_name, cache_key, region)
    if cached is not None:
        logger.info("Returning cached network utilization results for %s", region)
        return cached

    results: list[dict[str, Any]] = []

    try:
        ec2 = _ec2_client(region)
        cw = _cloudwatch_client(region)
        instances = _paginate_ec2_instances(ec2)
        logger.info(
            "Evaluating network utilization for %d EC2 instances", len(instances)
        )

        for inst in instances:
            iid = inst["InstanceId"]
            itype = inst.get("InstanceType", "unknown")
            dims = [{"Name": "InstanceId", "Value": iid}]

            net_in = _get_metric_statistics(
                cw_client=cw,
                namespace="AWS/EC2",
                metric_name="NetworkIn",
                dimensions=dims,
                days=lookback_days,
                statistic="Average",
            )
            net_out = _get_metric_statistics(
                cw_client=cw,
                namespace="AWS/EC2",
                metric_name="NetworkOut",
                dimensions=dims,
                days=lookback_days,
                statistic="Average",
            )

            if net_in is None or net_out is None:
                continue

            total_daily = net_in + net_out
            if total_daily >= daily_bytes_threshold:
                continue

            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            results.append(
                {
                    "instance_id": iid,
                    "instance_type": itype,
                    "avg_network_in_bytes": round(net_in, 0),
                    "avg_network_out_bytes": round(net_out, 0),
                    "total_daily_bytes": round(total_daily, 0),
                    "recommendation": "Investigate idle instance or consolidate workload",
                    "name": tags.get("Name", iid),
                }
            )

        logger.info("Found %d instances with low network traffic", len(results))
        _set_cache(table_name, cache_key, results, region)
        return results

    except (ClientError, BotoCoreError) as exc:
        logger.error("Network utilization analysis failed: %s", exc)
        return []
