"""Tag Compliance Engine for Cost Attribution Enforcement.

Scans EC2, RDS, S3, and Lambda resources for missing required cost-attribution
tags, infers tag values using heuristics, generates Terraform code to apply
corrections, and produces compliance reports.

Required tags (configurable via environment):
    CostCenter, Project, Environment, Owner

Auto-tagging heuristics:
    - ``Environment``: inferred from resource name patterns (prod/staging/dev)
    - ``Owner``: pulled from the resource creation IAM principal via CloudTrail
    - ``Project``: extracted from the resource Name tag prefix
    - ``CostCenter``: inferred from VPC/subnet metadata
"""

import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
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

# Default required tags — overridable via environment
_DEFAULT_REQUIRED_TAGS = ["CostCenter", "Project", "Environment", "Owner"]

# Cache TTL: 24 hours
_CACHE_TTL_S = 24 * 3600
_CACHE_METRIC_TYPE = "tag_compliance_cache"

# Environment detection patterns
_ENV_PATTERNS = {
    "prod": re.compile(r"\b(prod|production|prd)\b", re.IGNORECASE),
    "staging": re.compile(r"\b(staging|stage|stg|uat)\b", re.IGNORECASE),
    "dev": re.compile(r"\b(dev|develop|development|sandbox|sbx)\b", re.IGNORECASE),
    "test": re.compile(r"\b(test|tst|qa)\b", re.IGNORECASE),
}


def _get_required_tags() -> list[str]:
    """Return the list of required tag keys from environment or defaults."""
    env_tags = os.environ.get("REQUIRED_TAG_LIST", "").strip()
    if env_tags:
        return [t.strip() for t in env_tags.split(",") if t.strip()]
    return _DEFAULT_REQUIRED_TAGS


def _ec2_client(region: str) -> Any:
    return boto3.client("ec2", region_name=region, config=_RETRY_CONFIG)


def _rds_client(region: str) -> Any:
    return boto3.client("rds", region_name=region, config=_RETRY_CONFIG)


def _s3_client(region: str) -> Any:
    return boto3.client("s3", region_name=region, config=_RETRY_CONFIG)


def _lambda_client(region: str) -> Any:
    return boto3.client("lambda", region_name=region, config=_RETRY_CONFIG)


def _cloudtrail_client(region: str) -> Any:
    return boto3.client("cloudtrail", region_name=region, config=_RETRY_CONFIG)


def _ce_client(region: str) -> Any:
    return boto3.client("ce", region_name=region, config=_RETRY_CONFIG)


def _dynamodb_resource(region: str) -> Any:
    return boto3.resource("dynamodb", region_name=region, config=_RETRY_CONFIG)


def _now_epoch() -> int:
    return int(time.time())


def _get_cache(table_name: str, cache_key: str, region: str) -> Optional[Any]:
    """Read cached tag compliance data from DynamoDB."""
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
        logger.warning("Tag compliance cache read failed: %s", exc)
        return None


def _set_cache(table_name: str, cache_key: str, data: Any, region: str) -> None:
    """Write tag compliance data to DynamoDB cache."""
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
        logger.warning("Tag compliance cache write failed (non-fatal): %s", exc)


def _infer_environment(name: str) -> str:
    """Infer the ``Environment`` tag value from a resource name string.

    Args:
        name: Resource name or identifier string.

    Returns:
        Inferred environment string (``prod``, ``staging``, ``dev``, ``test``)
        or ``unknown`` if no pattern matches.
    """
    for env, pattern in _ENV_PATTERNS.items():
        if pattern.search(name):
            return env
    return "unknown"


def _infer_project(name: str) -> str:
    """Extract a project/app name from a resource's Name tag.

    Applies simple heuristics: takes the first hyphen-delimited segment of
    the name that is at least 3 characters long.

    Args:
        name: Resource Name tag value.

    Returns:
        Inferred project string or ``unknown``.
    """
    if not name:
        return "unknown"
    parts = re.split(r"[-_]", name)
    for part in parts:
        clean = re.sub(r"\d+$", "", part).lower()
        if len(clean) >= 3 and clean not in {"dev", "prd", "stg", "prod", "test", "uat"}:
            return clean
    return parts[0].lower() if parts else "unknown"


def _get_creator_from_cloudtrail(
    resource_id: str,
    resource_type: str,
    region: str,
    days: int = 30,
) -> str:
    """Attempt to find the IAM principal that created the resource.

    Args:
        resource_id: Resource identifier (instance ID, ARN, etc.).
        resource_type: Human-readable type for the log message.
        region: AWS region.
        days: Lookback window for CloudTrail events.

    Returns:
        IAM principal short name, or ``unknown`` if not found.
    """
    try:
        ct = _cloudtrail_client(region)
        end_time = datetime.now(tz=timezone.utc)
        start_time = end_time - timedelta(days=days)

        response = ct.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": resource_id}
            ],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=10,
        )
        for event in response.get("Events", []):
            username = event.get("Username", "")
            if username and username not in ("root", "anonymous"):
                return username.split("/")[-1]
    except Exception as exc:
        logger.debug("CloudTrail owner lookup for %s failed: %s", resource_id, exc)
    return "unknown"


def _missing_tags(existing_tags: dict[str, str], required: list[str]) -> list[str]:
    """Return the list of required tags not present in the existing tag dict."""
    return [t for t in required if t not in existing_tags or not existing_tags[t]]


def scan_untagged_resources(
    region: str = "ap-south-1",
    table_name: str = "finops-cost-baselines",
    required_tags: Optional[list[str]] = None,
) -> list[dict[str, Any]]:
    """Scan EC2, RDS, S3, and Lambda resources for missing required tags.

    Args:
        region: AWS region.
        table_name: DynamoDB table for caching.
        required_tags: Tag keys that must be present. Defaults to
                       ``_DEFAULT_REQUIRED_TAGS``.

    Returns:
        List of dicts with keys: ``resource_id``, ``resource_type``,
        ``missing_tags``, ``monthly_cost``, ``recommendation``.
    """
    if required_tags is None:
        required_tags = _get_required_tags()

    cache_key = f"untagged_resources_{region}"
    cached = _get_cache(table_name, cache_key, region)
    if cached is not None:
        logger.info("Returning cached tag compliance results for %s", region)
        return cached

    results: list[dict[str, Any]] = []

    # --- EC2 ---
    try:
        ec2 = _ec2_client(region)
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
        ):
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    iid = inst["InstanceId"]
                    itype = inst.get("InstanceType", "unknown")
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    missing = _missing_tags(tags, required_tags)
                    if missing:
                        results.append(
                            {
                                "resource_id": iid,
                                "resource_type": "EC2_INSTANCE",
                                "instance_type": itype,
                                "missing_tags": missing,
                                "existing_tags": tags,
                                "monthly_cost": 0.0,
                                "recommendation": "Add missing tags: " + ", ".join(missing),
                            }
                        )
    except (ClientError, BotoCoreError) as exc:
        logger.warning("EC2 tag scan failed: %s", exc)

    # --- RDS ---
    try:
        rds = _rds_client(region)
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                db_id = db["DBInstanceIdentifier"]
                db_arn = db.get("DBInstanceArn", "")
                tags: dict[str, str] = {}
                try:
                    tag_response = rds.list_tags_for_resource(ResourceName=db_arn)
                    tags = {
                        t["Key"]: t["Value"]
                        for t in tag_response.get("TagList", [])
                    }
                except Exception:
                    pass
                missing = _missing_tags(tags, required_tags)
                if missing:
                    results.append(
                        {
                            "resource_id": db_id,
                            "resource_type": "RDS_INSTANCE",
                            "instance_class": db.get("DBInstanceClass", "unknown"),
                            "missing_tags": missing,
                            "existing_tags": tags,
                            "monthly_cost": 0.0,
                            "recommendation": "Add missing tags: " + ", ".join(missing),
                        }
                    )
    except (ClientError, BotoCoreError) as exc:
        logger.warning("RDS tag scan failed: %s", exc)

    # --- S3 ---
    try:
        s3 = _s3_client(region)
        buckets_response = s3.list_buckets()
        for bucket in buckets_response.get("Buckets", []):
            bucket_name = bucket["Name"]
            tags: dict[str, str] = {}
            try:
                tag_response = s3.get_bucket_tagging(Bucket=bucket_name)
                tags = {
                    t["Key"]: t["Value"]
                    for t in tag_response.get("TagSet", [])
                }
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchTagSet":
                    logger.debug("S3 tag read for %s: %s", bucket_name, exc)
            missing = _missing_tags(tags, required_tags)
            if missing:
                results.append(
                    {
                        "resource_id": bucket_name,
                        "resource_type": "S3_BUCKET",
                        "missing_tags": missing,
                        "existing_tags": tags,
                        "monthly_cost": 0.0,
                        "recommendation": "Add missing tags: " + ", ".join(missing),
                    }
                )
    except (ClientError, BotoCoreError) as exc:
        logger.warning("S3 tag scan failed: %s", exc)

    # --- Lambda ---
    try:
        lam = _lambda_client(region)
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                fn_arn = fn["FunctionArn"]
                fn_name = fn["FunctionName"]
                tags: dict[str, str] = {}
                try:
                    tag_response = lam.list_tags(Resource=fn_arn)
                    tags = tag_response.get("Tags", {})
                except Exception:
                    pass
                missing = _missing_tags(tags, required_tags)
                if missing:
                    results.append(
                        {
                            "resource_id": fn_name,
                            "resource_type": "LAMBDA_FUNCTION",
                            "missing_tags": missing,
                            "existing_tags": tags,
                            "monthly_cost": 0.0,
                            "recommendation": "Add missing tags: " + ", ".join(missing),
                        }
                    )
    except (ClientError, BotoCoreError) as exc:
        logger.warning("Lambda tag scan failed: %s", exc)

    logger.info(
        "Tag compliance scan complete: %d resources with missing tags in %s",
        len(results),
        region,
    )
    _set_cache(table_name, cache_key, results, region)
    return results


def auto_tag_resources(
    untagged_list: list[dict[str, Any]],
    region: str = "ap-south-1",
) -> list[dict[str, Any]]:
    """Infer suggested tag values for untagged resources using heuristics.

    This function does NOT apply tags directly. It returns enriched records
    with suggested tag values. Use :func:`generate_tagging_terraform` to
    produce Terraform code for human review and approval.

    Args:
        untagged_list: Output of :func:`scan_untagged_resources`.
        region: AWS region (used for CloudTrail owner lookups).

    Returns:
        List of dicts extending the input records with a ``suggested_tags``
        dict containing inferred values for each missing tag.
    """
    enriched: list[dict[str, Any]] = []

    for resource in untagged_list:
        resource_id = resource.get("resource_id", "")
        existing_tags = resource.get("existing_tags", {})
        missing = resource.get("missing_tags", [])

        suggested: dict[str, str] = {}
        name = existing_tags.get("Name", resource_id)

        for tag in missing:
            if tag == "Environment":
                suggested[tag] = _infer_environment(name)
            elif tag == "Project":
                suggested[tag] = _infer_project(name)
            elif tag == "Owner":
                owner = _get_creator_from_cloudtrail(
                    resource_id,
                    resource.get("resource_type", ""),
                    region,
                )
                suggested[tag] = owner
            elif tag == "CostCenter":
                # CostCenter is hard to infer automatically; leave as placeholder
                suggested[tag] = "UNKNOWN-review-required"
            else:
                suggested[tag] = "UNKNOWN"

        enriched.append(
            {
                **resource,
                "suggested_tags": suggested,
                "confidence": "low" if "CostCenter" in missing else "medium",
            }
        )

    logger.info("Generated tag suggestions for %d resources", len(enriched))
    return enriched


def generate_tagging_terraform(
    tagged_resources: list[dict[str, Any]],
) -> str:
    """Generate Terraform HCL to apply suggested tags to untagged resources.

    Only generates code for EC2 and Lambda resources (RDS and S3 tag APIs
    differ and are better handled via AWS Config remediation).

    Args:
        tagged_resources: Output of :func:`auto_tag_resources`.

    Returns:
        Terraform HCL string for human review.
    """
    today_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    lines: list[str] = [
        "# Auto-generated by FinOps Tag Compliance Engine",
        f"# Generated: {today_str}",
        "# IMPORTANT: Review all suggested tags before applying.",
        "# CostCenter tags marked UNKNOWN must be updated manually.",
        "",
    ]

    for resource in tagged_resources:
        rtype = resource.get("resource_type", "")
        rid = resource.get("resource_id", "")
        suggested = resource.get("suggested_tags", {})
        if not suggested:
            continue

        tags_hcl = "\n".join(
            f'    {k} = "{v}"' for k, v in suggested.items()
        )
        resource_name = re.sub(r"[^a-z0-9_]", "_", rid.lower())

        if rtype == "EC2_INSTANCE":
            lines += [
                f"# EC2: {rid}",
                f'resource "aws_ec2_tag" "{resource_name}_tags" {{',
                f'  resource_id = "{rid}"',
                "",
                "  tags = {",
                tags_hcl,
                "  }",
                "}",
                "",
            ]
        elif rtype == "LAMBDA_FUNCTION":
            lines += [
                f"# Lambda: {rid}",
                "# Note: Use aws_lambda_function data source to get ARN",
                f'resource "aws_lambda_function" "{resource_name}" {{',
                "  # ... existing config ...",
                "",
                "  tags = {",
                tags_hcl,
                "  }",
                "}",
                "",
            ]
        elif rtype == "S3_BUCKET":
            lines += [
                f"# S3: {rid}",
                f'resource "aws_s3_bucket_tagging" "{resource_name}_tags" {{',
                f'  bucket = "{rid}"',
                "",
                "  tagging {",
                "    tag_set {",
                tags_hcl,
                "    }",
                "  }",
                "}",
                "",
            ]

    return "\n".join(lines)


def enforce_tag_compliance(region: str = "ap-south-1") -> dict[str, Any]:
    """Return guidance for enforcing tag compliance via AWS Config and SCPs.

    This function documents the recommended enforcement mechanisms rather than
    applying them directly (SCP and Config changes require elevated privileges
    and human approval).

    Args:
        region: AWS region.

    Returns:
        Dict describing Config rules and SCP policies to create.
    """
    required_tags = _get_required_tags()
    cost_center_tag = os.environ.get("COST_CENTER_TAG_NAME", "CostCenter")

    return {
        "aws_config_rule": {
            "name": "required-tags",
            "description": f"Ensures resources have required tags: {', '.join(required_tags)}",
            "managed_rule": "REQUIRED_TAGS",
            "parameters": {tag: "" for tag in required_tags},
            "remediation_action": "AWS-AddTagsToInstance",
        },
        "service_control_policy": {
            "description": (
                f"Deny resource creation without {cost_center_tag} tag."
            ),
            "policy_json": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "DenyResourceCreationWithoutCostCenter",
                            "Effect": "Deny",
                            "Action": [
                                "ec2:RunInstances",
                                "rds:CreateDBInstance",
                                "lambda:CreateFunction",
                                "s3:CreateBucket",
                            ],
                            "Resource": "*",
                            "Condition": {
                                "Null": {
                                    f"aws:RequestTag/{cost_center_tag}": "true"
                                }
                            },
                        }
                    ],
                },
                indent=2,
            ),
        },
        "documentation": (
            "Apply the Config rule via Terraform aws_config_config_rule. "
            "Apply the SCP via aws_organizations_policy and attach to target OUs. "
            "See terraform/compliance/ for example configurations."
        ),
    }


def cost_allocation_by_tag(
    region: str = "ap-south-1",
    cost_center_tag: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Query Cost Explorer grouped by CostCenter tag.

    Args:
        region: AWS region.
        cost_center_tag: Tag key to group by (default: value of
                         ``COST_CENTER_TAG_NAME`` env var or ``CostCenter``).

    Returns:
        List of dicts with keys: ``cost_center``, ``total_spend``,
        ``percent_of_total``, ``trend``, ``top_services``.
    """
    if not cost_center_tag:
        cost_center_tag = os.environ.get("COST_CENTER_TAG_NAME", "CostCenter")

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
            Metrics=["UnblendedCost"],
            GroupBy=[
                {"Type": "TAG", "Key": cost_center_tag},
                {"Type": "DIMENSION", "Key": "SERVICE"},
            ],
        )

        cost_map: dict[str, dict[str, Any]] = {}
        total_spend = 0.0

        for period in response.get("ResultsByTime", []):
            for group in period.get("Groups", []):
                keys = group.get("Keys", [])
                cost = float(
                    group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0)
                )
                if len(keys) < 2 or cost < 0.01:
                    continue

                cc_key = keys[0].replace(f"{cost_center_tag}$", "").strip() or "untagged"
                service = keys[1]

                if cc_key not in cost_map:
                    cost_map[cc_key] = {"total": 0.0, "services": {}}
                cost_map[cc_key]["total"] += cost
                cost_map[cc_key]["services"][service] = (
                    cost_map[cc_key]["services"].get(service, 0.0) + cost
                )
                total_spend += cost

        results: list[dict[str, Any]] = []
        for cc, data in cost_map.items():
            top_services = sorted(
                [{"service": s, "cost": round(c, 2)} for s, c in data["services"].items()],
                key=lambda x: x["cost"],
                reverse=True,
            )[:3]

            results.append(
                {
                    "cost_center": cc,
                    "total_spend": round(data["total"], 2),
                    "percent_of_total": round(
                        (data["total"] / total_spend * 100) if total_spend > 0 else 0, 1
                    ),
                    "trend": "data unavailable (single period)",
                    "top_services": top_services,
                }
            )

        results.sort(key=lambda x: x["total_spend"], reverse=True)
        return results

    except (ClientError, BotoCoreError) as exc:
        logger.error("Cost allocation by tag failed: %s", exc)
        return []


def generate_tag_compliance_report(
    untagged_resources: list[dict[str, Any]],
    total_resources: int,
) -> dict[str, Any]:
    """Generate a tag compliance summary report.

    Args:
        untagged_resources: Output of :func:`scan_untagged_resources`.
        total_resources: Total number of resources scanned.

    Returns:
        Dict with compliance percentage, trend description, and resource breakdown.
    """
    untagged_count = len(untagged_resources)
    tagged_count = max(0, total_resources - untagged_count)
    compliance_pct = (tagged_count / total_resources * 100) if total_resources > 0 else 0.0

    by_type: dict[str, int] = {}
    by_missing_tag: dict[str, int] = {}
    for r in untagged_resources:
        rtype = r.get("resource_type", "unknown")
        by_type[rtype] = by_type.get(rtype, 0) + 1
        for tag in r.get("missing_tags", []):
            by_missing_tag[tag] = by_missing_tag.get(tag, 0) + 1

    return {
        "compliance_percent": round(compliance_pct, 1),
        "total_resources": total_resources,
        "tagged_resources": tagged_count,
        "untagged_resources": untagged_count,
        "resources_by_type": by_type,
        "missing_tag_frequency": dict(
            sorted(by_missing_tag.items(), key=lambda x: x[1], reverse=True)
        ),
        "resources_needing_attention": [
            {
                "resource_id": r["resource_id"],
                "resource_type": r["resource_type"],
                "missing_tags": r["missing_tags"],
            }
            for r in untagged_resources[:20]
        ],
        "estimated_unattributed_monthly_cost": sum(
            r.get("monthly_cost", 0) for r in untagged_resources
        ),
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
    }
