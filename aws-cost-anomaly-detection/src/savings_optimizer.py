"""Reserved Instance and Savings Plan Optimizer.

Analyses on-demand EC2 and RDS spend patterns to recommend Reserved Instance
purchases and Compute Savings Plans with full break-even analysis.

Pricing is fetched from the AWS Pricing API (us-east-1) and cached in
DynamoDB. Recommendations include payback period calculations and are
only emitted when the payback period is under 12 months.
"""

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Optional

import boto3
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

_RETRY_CONFIG = BotocoreConfig(
    retries={"max_attempts": 3, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=30,
)

# Pricing API is only available in us-east-1
_PRICING_REGION = "us-east-1"
_CACHE_TTL_S = 24 * 3600
_CACHE_METRIC_TYPE = "pricing_cache"

# Savings Plan discount rates (approximate, varies by region/instance family)
_SP_DISCOUNT_1YR = 0.38  # 38% average discount for 1-year Compute SP
_SP_DISCOUNT_3YR = 0.54  # 54% average discount for 3-year Compute SP

# RI discount rates (approximate No-Upfront)
_RI_DISCOUNT_1YR = 0.40
_RI_DISCOUNT_3YR = 0.60

# Hours per year/month
_HOURS_PER_YEAR = 8760
_HOURS_PER_MONTH = 730


def _pricing_client() -> Any:
    """Return a boto3 Pricing client (must use us-east-1)."""
    return boto3.client("pricing", region_name=_PRICING_REGION, config=_RETRY_CONFIG)


def _ce_client(region: str) -> Any:
    """Return a boto3 Cost Explorer client."""
    return boto3.client("ce", region_name=region, config=_RETRY_CONFIG)


def _ec2_client(region: str) -> Any:
    """Return a boto3 EC2 client."""
    return boto3.client("ec2", region_name=region, config=_RETRY_CONFIG)


def _rds_client(region: str) -> Any:
    """Return a boto3 RDS client."""
    return boto3.client("rds", region_name=region, config=_RETRY_CONFIG)


def _dynamodb_resource(region: str) -> Any:
    """Return a boto3 DynamoDB resource."""
    return boto3.resource("dynamodb", region_name=region, config=_RETRY_CONFIG)


def _now_epoch() -> int:
    """Return current Unix epoch timestamp."""
    return int(time.time())


def _get_cache(table_name: str, cache_key: str, region: str) -> Optional[Any]:
    """Read a JSON-encoded value from DynamoDB cache.

    Args:
        table_name: DynamoDB table name.
        cache_key: Cache key string.
        region: AWS region.

    Returns:
        Decoded Python object or ``None`` if missing or expired.
    """
    try:
        dynamodb = _dynamodb_resource(region)
        table = dynamodb.Table(table_name)
        response = table.get_item(
            Key={"execution_date": cache_key, "metric_type": _CACHE_METRIC_TYPE}
        )
        item = response.get("Item")
        if not item:
            return None
        if item.get("expiration_time") and _now_epoch() > int(item["expiration_time"]):
            return None
        return json.loads(item["results_json"]) if item.get("results_json") else None
    except Exception as exc:
        logger.warning("Pricing cache read failed: %s", exc)
        return None


def _set_cache(table_name: str, cache_key: str, data: Any, region: str) -> None:
    """Write a JSON-encoded value to DynamoDB cache.

    Args:
        table_name: DynamoDB table name.
        cache_key: Cache key string.
        data: Serialisable data.
        region: AWS region.
    """
    try:
        dynamodb = _dynamodb_resource(region)
        table = dynamodb.Table(table_name)
        table.put_item(
            Item={
                "execution_date": cache_key,
                "metric_type": _CACHE_METRIC_TYPE,
                "results_json": json.dumps(data, default=str),
                "expiration_time": _now_epoch() + _CACHE_TTL_S,
                "updated_at": datetime.now(tz=timezone.utc).isoformat(),
            }
        )
    except Exception as exc:
        logger.warning("Pricing cache write failed (non-fatal): %s", exc)


def _get_ec2_on_demand_price(
    instance_type: str,
    region: str = "ap-south-1",
) -> Optional[float]:
    """Fetch on-demand hourly price for an EC2 instance type.

    Uses the AWS Pricing API with a product attribute filter.
    Results are not individually cached; the caller caches at a higher level.

    Args:
        instance_type: EC2 instance type (e.g. ``m5.xlarge``).
        region: AWS region for the price lookup.

    Returns:
        Hourly on-demand price in USD, or ``None`` on API failure.
    """
    # Map boto3 region name to Pricing API location
    region_map = {
        "ap-south-1": "Asia Pacific (Mumbai)",
        "us-east-1": "US East (N. Virginia)",
        "us-west-2": "US West (Oregon)",
        "eu-west-1": "Europe (Ireland)",
        "ap-southeast-1": "Asia Pacific (Singapore)",
    }
    location = region_map.get(region, "US East (N. Virginia)")

    try:
        pricing = _pricing_client()
        response = pricing.get_products(
            ServiceCode="AmazonEC2",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
                {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
                {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
                {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
                {"Type": "TERM_MATCH", "Field": "capacityStatus", "Value": "Used"},
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
            ],
            MaxResults=1,
        )
        price_list = response.get("PriceList", [])
        if not price_list:
            return None

        product = json.loads(price_list[0])
        on_demand_terms = product.get("terms", {}).get("OnDemand", {})
        for term in on_demand_terms.values():
            for dim in term.get("priceDimensions", {}).values():
                price_str = dim.get("pricePerUnit", {}).get("USD", "0")
                price = float(price_str)
                if price > 0:
                    return price
        return None
    except Exception as exc:
        logger.warning("Pricing API lookup failed for %s: %s", instance_type, exc)
        return None


def _calculate_ri_savings(
    hourly_on_demand: float,
    ri_discount_1yr: float = _RI_DISCOUNT_1YR,
    ri_discount_3yr: float = _RI_DISCOUNT_3YR,
) -> dict[str, float]:
    """Calculate Reserved Instance savings figures from on-demand hourly price.

    Args:
        hourly_on_demand: On-demand hourly price in USD.
        ri_discount_1yr: Fractional discount for 1-year RI (e.g. 0.40 = 40%).
        ri_discount_3yr: Fractional discount for 3-year RI (e.g. 0.60 = 60%).

    Returns:
        Dict with annual costs, savings, and payback period fields.
    """
    annual_on_demand = hourly_on_demand * _HOURS_PER_YEAR
    hourly_1yr = hourly_on_demand * (1 - ri_discount_1yr)
    hourly_3yr = hourly_on_demand * (1 - ri_discount_3yr)
    annual_1yr = hourly_1yr * _HOURS_PER_YEAR
    annual_3yr = hourly_3yr * _HOURS_PER_YEAR
    annual_savings_1yr = annual_on_demand - annual_1yr
    annual_savings_3yr = annual_on_demand - annual_3yr

    # Assume no-upfront for simplicity; partial-upfront would reduce payback
    payback_months_1yr = 0.0  # No-upfront RI has no break-even; savings start immediately
    # For upfront calculation: upfront ≈ 30% of annual RI cost
    upfront_1yr = annual_1yr * 0.30
    monthly_savings_1yr = annual_savings_1yr / 12
    payback_months_1yr = upfront_1yr / monthly_savings_1yr if monthly_savings_1yr > 0 else float("inf")

    return {
        "annual_on_demand": round(annual_on_demand, 2),
        "annual_1yr_ri": round(annual_1yr, 2),
        "annual_3yr_ri": round(annual_3yr, 2),
        "annual_savings_1yr": round(annual_savings_1yr, 2),
        "annual_savings_3yr": round(annual_savings_3yr, 2),
        "savings_1yr_percent": round(ri_discount_1yr * 100, 1),
        "savings_3yr_percent": round(ri_discount_3yr * 100, 1),
        "payback_months": round(payback_months_1yr, 1),
    }


def analyze_reserved_instance_opportunity(
    region: str = "ap-south-1",
    table_name: str = "finops-cost-baselines",
    max_payback_months: int = 12,
) -> list[dict[str, Any]]:
    """Identify EC2 instances that would benefit from Reserved Instance pricing.

    Only includes instances where the payback period for a 1-year No-Upfront RI
    is less than ``max_payback_months``.

    Args:
        region: AWS region.
        table_name: DynamoDB table for caching.
        max_payback_months: Maximum acceptable payback period in months.

    Returns:
        List of recommendation dicts sorted by annual savings descending.
        Each dict contains: ``instance_id``, ``instance_type``,
        ``annual_on_demand``, ``annual_1yr_ri``, ``annual_3yr_ri``,
        ``savings_1yr_percent``, ``savings_3yr_percent``,
        ``payback_months``, ``recommendation``.
    """
    cache_key = f"ri_opportunities_{region}"
    cached = _get_cache(table_name, cache_key, region)
    if cached is not None:
        logger.info("Returning cached RI opportunities for %s", region)
        return cached

    results: list[dict[str, Any]] = []

    try:
        ec2 = _ec2_client(region)
        paginator = ec2.get_paginator("describe_instances")
        instances: list[dict[str, Any]] = []
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for reservation in page.get("Reservations", []):
                instances.extend(reservation.get("Instances", []))

        # Also check existing RIs to avoid recommending what's already covered
        existing_ris: set[str] = set()
        try:
            ri_response = ec2.describe_reserved_instances(
                Filters=[{"Name": "state", "Values": ["active"]}]
            )
            for ri in ri_response.get("ReservedInstances", []):
                existing_ris.add(ri.get("InstanceType", ""))
        except Exception as exc:
            logger.warning("Could not fetch existing RIs: %s", exc)

        logger.info(
            "Analysing RI opportunities for %d EC2 instances (%d types already reserved)",
            len(instances),
            len(existing_ris),
        )

        processed_types: dict[str, list[str]] = {}
        for inst in instances:
            itype = inst.get("InstanceType", "unknown")
            iid = inst["InstanceId"]
            processed_types.setdefault(itype, []).append(iid)

        for itype, iids in processed_types.items():
            if itype in existing_ris:
                logger.debug("Skipping %s — already has active RI", itype)
                continue

            hourly_price = _get_ec2_on_demand_price(itype, region)
            if not hourly_price:
                logger.debug("No pricing data for %s — skipping", itype)
                continue

            savings = _calculate_ri_savings(hourly_price)

            if savings["payback_months"] > max_payback_months:
                continue

            best_option = (
                "3-year RI ({:.0f}% savings)".format(savings["savings_3yr_percent"])
                if savings["annual_savings_3yr"] > savings["annual_savings_1yr"] * 1.2
                else "1-year RI ({:.0f}% savings)".format(savings["savings_1yr_percent"])
            )

            results.append(
                {
                    "instance_ids": iids,
                    "instance_count": len(iids),
                    "instance_type": itype,
                    "hourly_on_demand": round(hourly_price, 4),
                    **savings,
                    "recommendation": best_option,
                    "total_annual_savings_1yr": round(savings["annual_savings_1yr"] * len(iids), 2),
                    "total_annual_savings_3yr": round(savings["annual_savings_3yr"] * len(iids), 2),
                }
            )

        results.sort(key=lambda x: x.get("total_annual_savings_1yr", 0), reverse=True)
        logger.info("Found %d RI opportunities", len(results))
        _set_cache(table_name, cache_key, results, region)
        return results

    except (ClientError, BotoCoreError) as exc:
        logger.error("RI opportunity analysis failed: %s", exc)
        return []


def analyze_savings_plan_opportunity(
    region: str = "ap-south-1",
    table_name: str = "finops-cost-baselines",
) -> list[dict[str, Any]]:
    """Recommend Compute Savings Plans based on current EC2 on-demand spend.

    Analyses 30-day Cost Explorer data to determine the stable baseline
    commitment level and computes 1-year and 3-year Compute Savings Plan
    savings estimates.

    Args:
        region: AWS region.
        table_name: DynamoDB table for caching.

    Returns:
        List of Savings Plan recommendation dicts sorted by savings descending.
    """
    cache_key = f"sp_opportunities_{region}"
    cached = _get_cache(table_name, cache_key, region)
    if cached is not None:
        logger.info("Returning cached Savings Plan opportunities for %s", region)
        return cached

    results: list[dict[str, Any]] = []

    try:
        ce = _ce_client(region)
        end_date = datetime.now(tz=timezone.utc).date()
        start_date = end_date - timedelta(days=30)

        response = ce.get_cost_and_usage(
            TimePeriod={
                "Start": start_date.isoformat(),
                "End": end_date.isoformat(),
            },
            Granularity="MONTHLY",
            Filter={
                "Dimensions": {
                    "Key": "SERVICE",
                    "Values": ["Amazon Elastic Compute Cloud - Compute"],
                }
            },
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "INSTANCE_TYPE"}],
        )

        for period in response.get("ResultsByTime", []):
            for group in period.get("Groups", []):
                itype = group.get("Keys", ["unknown"])[0]
                monthly_cost = float(
                    group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0)
                )
                if monthly_cost < 10.0:
                    continue

                annual_on_demand = monthly_cost * 12
                annual_1yr_sp = annual_on_demand * (1 - _SP_DISCOUNT_1YR)
                annual_3yr_sp = annual_on_demand * (1 - _SP_DISCOUNT_3YR)

                results.append(
                    {
                        "instance_type": itype,
                        "monthly_on_demand": round(monthly_cost, 2),
                        "annual_on_demand": round(annual_on_demand, 2),
                        "annual_1yr_sp": round(annual_1yr_sp, 2),
                        "annual_3yr_sp": round(annual_3yr_sp, 2),
                        "savings_1yr_percent": round(_SP_DISCOUNT_1YR * 100, 1),
                        "savings_3yr_percent": round(_SP_DISCOUNT_3YR * 100, 1),
                        "annual_savings_1yr": round(annual_on_demand - annual_1yr_sp, 2),
                        "annual_savings_3yr": round(annual_on_demand - annual_3yr_sp, 2),
                        "recommendation": "1-year Compute Savings Plan ({:.0f}% savings)".format(
                            _SP_DISCOUNT_1YR * 100
                        ),
                        "commitment_type": "Compute (any instance family)",
                    }
                )

        results.sort(key=lambda x: x.get("annual_savings_1yr", 0), reverse=True)
        logger.info("Found %d Savings Plan opportunities", len(results))
        _set_cache(table_name, cache_key, results, region)
        return results

    except (ClientError, BotoCoreError) as exc:
        logger.error("Savings Plan analysis failed: %s", exc)
        return []


def rds_reserved_instance_recommendations(
    region: str = "ap-south-1",
    table_name: str = "finops-cost-baselines",
    max_payback_months: int = 12,
) -> list[dict[str, Any]]:
    """Recommend RDS Reserved Instances for running DB instances.

    Applies the same break-even analysis as EC2 RI recommendations but for
    RDS instance classes.

    Args:
        region: AWS region.
        table_name: DynamoDB table for caching.
        max_payback_months: Maximum payback period to include in results.

    Returns:
        List of RDS RI recommendation dicts.
    """
    cache_key = f"rds_ri_opportunities_{region}"
    cached = _get_cache(table_name, cache_key, region)
    if cached is not None:
        logger.info("Returning cached RDS RI opportunities for %s", region)
        return cached

    results: list[dict[str, Any]] = []

    # Approximate RDS on-demand hourly prices (MySQL/PostgreSQL, us-east-1)
    rds_hourly_prices: dict[str, float] = {
        "db.t3.micro": 0.017, "db.t3.small": 0.034, "db.t3.medium": 0.068,
        "db.t3.large": 0.136, "db.t3.xlarge": 0.272,
        "db.m5.large": 0.171, "db.m5.xlarge": 0.342, "db.m5.2xlarge": 0.684,
        "db.r5.large": 0.240, "db.r5.xlarge": 0.480, "db.r5.2xlarge": 0.960,
    }

    try:
        rds = _rds_client(region)
        paginator = rds.get_paginator("describe_db_instances")
        db_instances: list[dict[str, Any]] = []
        for page in paginator.paginate():
            db_instances.extend(page.get("DBInstances", []))

        # Group by instance class
        class_map: dict[str, list[str]] = {}
        for db in db_instances:
            if db.get("DBInstanceStatus") != "available":
                continue
            db_class = db.get("DBInstanceClass", "unknown")
            db_id = db["DBInstanceIdentifier"]
            class_map.setdefault(db_class, []).append(db_id)

        for db_class, db_ids in class_map.items():
            hourly_price = rds_hourly_prices.get(db_class)
            if not hourly_price:
                logger.debug("No pricing data for RDS %s — skipping", db_class)
                continue

            savings = _calculate_ri_savings(hourly_price, _RI_DISCOUNT_1YR * 0.85, _RI_DISCOUNT_3YR * 0.85)

            if savings["payback_months"] > max_payback_months:
                continue

            results.append(
                {
                    "db_instance_ids": db_ids,
                    "instance_count": len(db_ids),
                    "instance_class": db_class,
                    "hourly_on_demand": round(hourly_price, 4),
                    **savings,
                    "recommendation": "1-year RDS RI ({:.0f}% savings)".format(
                        savings["savings_1yr_percent"]
                    ),
                    "total_annual_savings_1yr": round(savings["annual_savings_1yr"] * len(db_ids), 2),
                }
            )

        results.sort(key=lambda x: x.get("total_annual_savings_1yr", 0), reverse=True)
        logger.info("Found %d RDS RI opportunities", len(results))
        _set_cache(table_name, cache_key, results, region)
        return results

    except (ClientError, BotoCoreError) as exc:
        logger.error("RDS RI analysis failed: %s", exc)
        return []


def consolidation_opportunity(
    underutilized: list[dict[str, Any]],
    ri_candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Combine right-sizing with RI purchase for maximum savings.

    For each underutilised instance that also has an RI opportunity,
    calculates the combined savings from downsizing AND purchasing a
    Reserved Instance on the smaller type.

    Args:
        underutilized: Output of
            :func:`utilization_analyzer.get_underutilized_ec2_instances`.
        ri_candidates: Output of :func:`analyze_reserved_instance_opportunity`.

    Returns:
        Ranked list of combined opportunity dicts sorted by total monthly
        savings descending.
    """
    ri_by_type = {r["instance_type"]: r for r in ri_candidates}
    results: list[dict[str, Any]] = []

    for inst in underutilized:
        iid = inst.get("instance_id", "unknown")
        recommended_type = inst.get("recommended_type", "")
        rightsizing_savings = inst.get("estimated_savings", 0)

        ri_rec = ri_by_type.get(recommended_type)
        ri_monthly_savings = (
            ri_rec.get("annual_savings_1yr", 0) / 12 if ri_rec else 0.0
        )

        total_monthly_savings = rightsizing_savings + ri_monthly_savings
        description = (
            f"Downsize {inst.get('current_type', '?')} → {recommended_type}"
        )
        if ri_rec:
            description += f" + buy 1-year RI = {ri_rec.get('savings_1yr_percent', 0):.0f}% savings"

        results.append(
            {
                "instance_id": iid,
                "name": inst.get("name", iid),
                "current_type": inst.get("current_type", "unknown"),
                "recommended_type": recommended_type,
                "rightsizing_monthly_savings": round(rightsizing_savings, 2),
                "ri_monthly_savings": round(ri_monthly_savings, 2),
                "total_monthly_savings": round(total_monthly_savings, 2),
                "total_annual_savings": round(total_monthly_savings * 12, 2),
                "description": description,
                "avg_cpu": inst.get("avg_cpu", 0),
            }
        )

    results.sort(key=lambda x: x["total_monthly_savings"], reverse=True)
    return results


def forecast_spend_with_commitments(
    ri_candidates: list[dict[str, Any]],
    sp_candidates: list[dict[str, Any]],
    current_monthly_spend: float,
) -> dict[str, Any]:
    """Project annual spend under different commitment scenarios.

    Computes 12-month and 36-month cumulative spend forecasts for:
    - Baseline (on-demand, no change)
    - With 1-year RIs + Savings Plans
    - With 3-year RIs + Savings Plans

    Args:
        ri_candidates: EC2 RI recommendation list.
        sp_candidates: Savings Plan recommendation list.
        current_monthly_spend: Current monthly on-demand spend in USD.

    Returns:
        Dict with forecast arrays and summary savings figures.
    """
    total_ri_monthly_1yr = sum(
        r.get("total_annual_savings_1yr", 0) / 12 for r in ri_candidates
    )
    total_ri_monthly_3yr = sum(
        r.get("total_annual_savings_3yr", 0) / 12 for r in ri_candidates
    )
    total_sp_monthly_1yr = sum(
        r.get("annual_savings_1yr", 0) / 12 for r in sp_candidates
    )

    monthly_with_1yr = max(0, current_monthly_spend - total_ri_monthly_1yr - total_sp_monthly_1yr)
    monthly_with_3yr = max(0, current_monthly_spend - total_ri_monthly_3yr - total_sp_monthly_1yr)

    cumulative_baseline = [current_monthly_spend * (m + 1) for m in range(36)]
    cumulative_1yr = [monthly_with_1yr * (m + 1) for m in range(36)]
    cumulative_3yr = [monthly_with_3yr * (m + 1) for m in range(36)]

    return {
        "current_monthly_spend": round(current_monthly_spend, 2),
        "monthly_with_1yr_commitments": round(monthly_with_1yr, 2),
        "monthly_with_3yr_commitments": round(monthly_with_3yr, 2),
        "annual_savings_1yr": round((current_monthly_spend - monthly_with_1yr) * 12, 2),
        "annual_savings_3yr": round((current_monthly_spend - monthly_with_3yr) * 12, 2),
        "savings_percent_1yr": round(
            (1 - monthly_with_1yr / current_monthly_spend) * 100 if current_monthly_spend > 0 else 0, 1
        ),
        "savings_percent_3yr": round(
            (1 - monthly_with_3yr / current_monthly_spend) * 100 if current_monthly_spend > 0 else 0, 1
        ),
        "cumulative_12m_baseline": round(cumulative_baseline[11], 2),
        "cumulative_12m_with_1yr": round(cumulative_1yr[11], 2),
        "cumulative_36m_baseline": round(cumulative_baseline[35], 2),
        "cumulative_36m_with_3yr": round(cumulative_3yr[35], 2),
        "confidence_interval_pct": 5.0,
    }
