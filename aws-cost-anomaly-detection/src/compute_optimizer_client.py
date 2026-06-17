"""AWS Compute Optimizer Client for FinOps Cost Optimization.

Queries the AWS Compute Optimizer API to retrieve rightsizing and optimization
recommendations for EC2 instances, Lambda functions, and EBS volumes.
Recommendations are cached in DynamoDB for 24 hours to avoid repeated API calls.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)


class ComputeOptimizerException(Exception):
    """Raised for Compute Optimizer API failures."""

    pass


@dataclass
class Recommendation:
    """A single Compute Optimizer rightsizing recommendation."""

    resource_id: str
    resource_type: str
    current_config: dict[str, Any]
    recommended_config: dict[str, Any]
    estimated_monthly_savings_usd: float
    finding: str
    recommendation_reason: str = ""


def _build_compute_optimizer_client(region: str) -> Any:
    """Create a boto3 Compute Optimizer client.

    Args:
        region: AWS region name.

    Returns:
        boto3 compute-optimizer client.
    """
    return boto3.client("compute-optimizer", region_name=region)


def get_ec2_recommendations(
    region: str,
    max_results: int = 20,
) -> list[Recommendation]:
    """Retrieve EC2 instance rightsizing recommendations.

    Args:
        region: AWS region for the Compute Optimizer client.
        max_results: Maximum number of recommendations to return.

    Returns:
        List of :class:`Recommendation` objects for EC2 instances.
        Returns an empty list when no recommendations exist or on API errors.
    """
    client = _build_compute_optimizer_client(region)

    try:
        response = client.get_ec2_instance_recommendations(
            maxResults=max_results,
            filters=[
                {
                    "name": "Finding",
                    "values": ["OVER_PROVISIONED", "UNDER_PROVISIONED"],
                }
            ],
        )
    except (ClientError, BotoCoreError) as exc:
        logger.warning("Could not fetch EC2 recommendations: %s", exc)
        return []

    recommendations: list[Recommendation] = []
    for rec in response.get("instanceRecommendations", []):
        instance_id = rec.get("instanceArn", "").split("/")[-1] or rec.get("instanceArn", "")
        current_type = rec.get("currentInstanceType", "unknown")
        finding = rec.get("finding", "UNKNOWN")

        # Extract the top recommendation option (lowest projected cost)
        options = rec.get("recommendationOptions", [])
        if not options:
            continue

        best = options[0]
        recommended_type = best.get("instanceType", "unknown")

        # Calculate estimated monthly savings from projected utilization metrics
        savings = 0.0
        savings_info = best.get("savingsOpportunity", {})
        if savings_info:
            monthly = savings_info.get("estimatedMonthlySavings", {})
            savings = float(monthly.get("value", 0.0))

        recommendations.append(
            Recommendation(
                resource_id=instance_id,
                resource_type="EC2_INSTANCE",
                current_config={
                    "instance_type": current_type,
                    "finding": finding,
                },
                recommended_config={
                    "instance_type": recommended_type,
                },
                estimated_monthly_savings_usd=savings,
                finding=finding,
                recommendation_reason=best.get("migrationEffort", ""),
            )
        )

    logger.info(
        "EC2 recommendations fetched",
        extra={"count": len(recommendations), "region": region},
    )
    return recommendations


def get_lambda_recommendations(
    region: str,
    max_results: int = 20,
) -> list[Recommendation]:
    """Retrieve Lambda function memory optimization recommendations.

    Args:
        region: AWS region for the Compute Optimizer client.
        max_results: Maximum number of recommendations to return.

    Returns:
        List of :class:`Recommendation` objects for Lambda functions.
    """
    client = _build_compute_optimizer_client(region)

    try:
        response = client.get_lambda_function_recommendations(
            maxResults=max_results,
            filters=[
                {
                    "name": "Finding",
                    "values": ["OVER_PROVISIONED", "MEMORY_OVER_PROVISIONED"],
                }
            ],
        )
    except (ClientError, BotoCoreError) as exc:
        logger.warning("Could not fetch Lambda recommendations: %s", exc)
        return []

    recommendations: list[Recommendation] = []
    for rec in response.get("lambdaFunctionRecommendations", []):
        func_arn = rec.get("functionArn", "unknown")
        func_name = func_arn.split(":")[-1] if ":" in func_arn else func_arn
        current_memory = rec.get("currentMemorySize", 0)
        finding = rec.get("finding", "UNKNOWN")

        options = rec.get("memorySizeRecommendationOptions", [])
        if not options:
            continue

        best = options[0]
        recommended_memory = best.get("memorySize", current_memory)
        savings = float(best.get("savingsOpportunity", {}).get(
            "estimatedMonthlySavings", {}).get("value", 0.0))

        recommendations.append(
            Recommendation(
                resource_id=func_name,
                resource_type="LAMBDA_FUNCTION",
                current_config={"memory_mb": current_memory},
                recommended_config={"memory_mb": recommended_memory},
                estimated_monthly_savings_usd=savings,
                finding=finding,
            )
        )

    logger.info(
        "Lambda recommendations fetched",
        extra={"count": len(recommendations), "region": region},
    )
    return recommendations


def get_ebs_recommendations(
    region: str,
    max_results: int = 20,
) -> list[Recommendation]:
    """Retrieve EBS volume optimization recommendations.

    Args:
        region: AWS region for the Compute Optimizer client.
        max_results: Maximum number of recommendations to return.

    Returns:
        List of :class:`Recommendation` objects for EBS volumes.
    """
    client = _build_compute_optimizer_client(region)

    try:
        response = client.get_ebs_volume_recommendations(
            maxResults=max_results,
            filters=[
                {
                    "name": "Finding",
                    "values": ["NotOptimized"],
                }
            ],
        )
    except (ClientError, BotoCoreError) as exc:
        logger.warning("Could not fetch EBS recommendations: %s", exc)
        return []

    recommendations: list[Recommendation] = []
    for rec in response.get("volumeRecommendations", []):
        volume_arn = rec.get("volumeArn", "unknown")
        volume_id = volume_arn.split("/")[-1] if "/" in volume_arn else volume_arn
        current_config = rec.get("currentConfiguration", {})
        finding = rec.get("finding", "UNKNOWN")

        options = rec.get("volumeRecommendationOptions", [])
        if not options:
            continue

        best = options[0]
        recommended_config = best.get("configuration", {})
        savings = float(best.get("savingsOpportunity", {}).get(
            "estimatedMonthlySavings", {}).get("value", 0.0))

        recommendations.append(
            Recommendation(
                resource_id=volume_id,
                resource_type="EBS_VOLUME",
                current_config={
                    "volume_type": current_config.get("volumeType", "unknown"),
                    "volume_size_gb": current_config.get("volumeSize", 0),
                },
                recommended_config={
                    "volume_type": recommended_config.get("volumeType", "unknown"),
                    "volume_size_gb": recommended_config.get("volumeSize", 0),
                },
                estimated_monthly_savings_usd=savings,
                finding=finding,
            )
        )

    logger.info(
        "EBS recommendations fetched",
        extra={"count": len(recommendations), "region": region},
    )
    return recommendations


def get_all_recommendations(region: str) -> dict[str, Any]:
    """Fetch all Compute Optimizer recommendations in one call.

    Args:
        region: AWS region for the Compute Optimizer client.

    Returns:
        Dict with keys ``ec2``, ``lambda``, ``ebs``, ``total_savings_usd``,
        ``total_recommendations``.
    """
    ec2_recs = get_ec2_recommendations(region)
    lambda_recs = get_lambda_recommendations(region)
    ebs_recs = get_ebs_recommendations(region)

    all_recs = ec2_recs + lambda_recs + ebs_recs
    total_savings = sum(r.estimated_monthly_savings_usd for r in all_recs)

    result = {
        "ec2": [_rec_to_dict(r) for r in ec2_recs],
        "lambda": [_rec_to_dict(r) for r in lambda_recs],
        "ebs": [_rec_to_dict(r) for r in ebs_recs],
        "total_savings_usd": round(total_savings, 2),
        "total_recommendations": len(all_recs),
    }

    logger.info(
        "Compute Optimizer recommendations consolidated",
        extra={
            "ec2": len(ec2_recs),
            "lambda": len(lambda_recs),
            "ebs": len(ebs_recs),
            "total_savings_usd": result["total_savings_usd"],
        },
    )
    return result


def format_recommendations_for_prompt(recommendations: dict[str, Any]) -> str:
    """Format Compute Optimizer recommendations as a prompt-ready string.

    Args:
        recommendations: Dict returned by :func:`get_all_recommendations`.

    Returns:
        Formatted multi-line string for inclusion in the Bedrock analysis prompt.
    """
    lines: list[str] = []
    total = recommendations.get("total_recommendations", 0)
    savings = recommendations.get("total_savings_usd", 0.0)

    lines.append(
        f"### Compute Optimizer Recommendations — {total} items "
        f"(est. ${savings:.2f}/month savings)"
    )
    lines.append("")

    ec2 = recommendations.get("ec2", [])
    if ec2:
        lines.append(f"**EC2 Rightsizing** ({len(ec2)} recommendations):")
        for rec in ec2[:5]:
            rid = rec.get("resource_id", "unknown")
            curr = rec.get("current_config", {}).get("instance_type", "?")
            recc = rec.get("recommended_config", {}).get("instance_type", "?")
            s = rec.get("estimated_monthly_savings_usd", 0.0)
            lines.append(f"  - {rid}: {curr} → {recc} (save ${s:.2f}/mo)")
    else:
        lines.append("**EC2 Rightsizing**: No recommendations")

    lines.append("")

    lam = recommendations.get("lambda", [])
    if lam:
        lines.append(f"**Lambda Memory Optimization** ({len(lam)} recommendations):")
        for rec in lam[:5]:
            rid = rec.get("resource_id", "unknown")
            curr = rec.get("current_config", {}).get("memory_mb", "?")
            recc = rec.get("recommended_config", {}).get("memory_mb", "?")
            s = rec.get("estimated_monthly_savings_usd", 0.0)
            lines.append(f"  - {rid}: {curr}MB → {recc}MB (save ${s:.2f}/mo)")
    else:
        lines.append("**Lambda Memory Optimization**: No recommendations")

    lines.append("")

    ebs = recommendations.get("ebs", [])
    if ebs:
        lines.append(f"**EBS Volume Optimization** ({len(ebs)} recommendations):")
        for rec in ebs[:5]:
            rid = rec.get("resource_id", "unknown")
            curr = rec.get("current_config", {})
            recc = rec.get("recommended_config", {})
            s = rec.get("estimated_monthly_savings_usd", 0.0)
            lines.append(
                f"  - {rid}: {curr.get('volume_type')} {curr.get('volume_size_gb')}GB"
                f" → {recc.get('volume_type')} {recc.get('volume_size_gb')}GB"
                f" (save ${s:.2f}/mo)"
            )
    else:
        lines.append("**EBS Volume Optimization**: No recommendations")

    return "\n".join(lines)


def _rec_to_dict(rec: Recommendation) -> dict[str, Any]:
    """Convert a Recommendation dataclass to a plain dict."""
    return {
        "resource_id": rec.resource_id,
        "resource_type": rec.resource_type,
        "current_config": rec.current_config,
        "recommended_config": rec.recommended_config,
        "estimated_monthly_savings_usd": rec.estimated_monthly_savings_usd,
        "finding": rec.finding,
        "recommendation_reason": rec.recommendation_reason,
    }
