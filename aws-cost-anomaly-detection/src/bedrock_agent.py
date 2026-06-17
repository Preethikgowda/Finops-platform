"""Bedrock Agent Integration for FinOps Cost Analysis.

Invokes Amazon Nova Pro via the Converse API to analyze cost anomalies,
CloudTrail resource changes, and Compute Optimizer recommendations, returning
structured root-cause analysis and actionable cost reduction recommendations.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

# Amazon Nova Pro model identifier
DEFAULT_MODEL_ID = "amazon.nova-pro-v1:0"

SYSTEM_PROMPT = """You are a FinOps expert analyzing AWS cost anomalies.

Your task:
1. Analyze the cost spike data
2. Review CloudTrail events to understand what changed
3. Consider Compute Optimizer recommendations
4. Provide root cause analysis
5. Give actionable cost reduction recommendations

Be precise, data-driven, and focus on financial impact.

Always respond in valid JSON matching the schema:
{
  "anomaly_severity": "<HIGH|MEDIUM|LOW>",
  "probable_root_causes": ["<cause1>", "<cause2>"],
  "explanation": "<detailed explanation>",
  "recommendations": ["<action1>", "<action2>"]
}"""


class BedRockException(Exception):
    """Raised for Amazon Bedrock API failures."""

    pass


@dataclass
class BedrockAnalysisResult:
    """Structured response from Bedrock Nova Pro cost analysis."""

    anomaly_severity: str
    probable_root_causes: list[str]
    explanation: str
    recommendations: list[str]
    input_tokens: int = 0
    output_tokens: int = 0
    model_id: str = DEFAULT_MODEL_ID
    is_fallback: bool = False
    raw_response: Optional[str] = field(default=None, repr=False)


def _build_bedrock_client(region: str) -> Any:
    """Create a boto3 Bedrock Runtime client.

    Args:
        region: AWS region where Bedrock is available (ap-south-1 for Nova Pro).

    Returns:
        boto3 Bedrock Runtime client.
    """
    return boto3.client("bedrock-runtime", region_name=region)


def _build_analysis_prompt(
    cost_data: dict[str, Any],
    cloudtrail_summary: Optional[str] = None,
    compute_optimizer_summary: Optional[str] = None,
) -> str:
    """Construct the user-facing analysis prompt from cost data and context.

    Args:
        cost_data: Dictionary containing cost metrics (yesterday_cost,
                   baseline_cost, cost_delta, percentage_increase, etc.).
        cloudtrail_summary: Pre-formatted CloudTrail resource changes section.
        compute_optimizer_summary: Pre-formatted Compute Optimizer recommendations.

    Returns:
        Formatted prompt string.
    """
    prompt_lines = [
        "## AWS Cost Anomaly Report",
        "",
        "### Cost Summary",
        f"- **Yesterday's Cost**: ${cost_data.get('yesterday_cost', 0):.2f} USD",
        f"- **7-Day Baseline Average**: ${cost_data.get('baseline_cost', 0):.2f} USD",
        f"- **Cost Delta**: ${cost_data.get('cost_delta', 0):.2f} USD",
        f"- **Percentage Increase**: {cost_data.get('percentage_increase', 0):.1f}%",
        f"- **Analysis Date**: {cost_data.get('analysis_date', 'N/A')}",
        "",
    ]

    if cloudtrail_summary:
        prompt_lines.append(cloudtrail_summary)
        prompt_lines.append("")

    if compute_optimizer_summary:
        prompt_lines.append(compute_optimizer_summary)
        prompt_lines.append("")

    prompt_lines += [
        "### Analysis Request",
        "Analyze this cost anomaly using the CloudTrail events and Compute Optimizer data above.",
        "Identify the probable root causes and provide specific actionable cost reduction recommendations.",
        "Respond with valid JSON only — no prose outside the JSON object.",
    ]

    return "\n".join(prompt_lines)


def _parse_bedrock_response(content_text: str) -> dict[str, Any]:
    """Parse and validate the JSON response from Nova Pro.

    Args:
        content_text: Raw text content returned by Bedrock.

    Returns:
        Parsed dictionary with anomaly_severity, probable_root_causes,
        explanation, and recommendations.

    Raises:
        BedRockException: When the response cannot be parsed or is missing
                          required fields.
    """
    text = content_text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(
            line for line in lines if not line.strip().startswith("```")
        )

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BedRockException(
            f"Bedrock response is not valid JSON. Raw response (first 500 chars): "
            f"{content_text[:500]}. Error: {exc}"
        ) from exc

    required_fields = ["anomaly_severity", "probable_root_causes", "explanation", "recommendations"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        raise BedRockException(
            f"Bedrock response is missing required fields: {missing}. "
            f"Full response: {data}"
        )

    valid_severities = {"HIGH", "MEDIUM", "LOW"}
    severity = str(data.get("anomaly_severity", "")).upper()
    if severity not in valid_severities:
        logger.warning(
            "Unexpected anomaly_severity '%s', defaulting to MEDIUM", severity
        )
        data["anomaly_severity"] = "MEDIUM"
    else:
        data["anomaly_severity"] = severity

    return data


def _fallback_response(
    cost_data: dict[str, Any],
    reason: str,
) -> BedrockAnalysisResult:
    """Build a generic fallback response when Bedrock is unavailable.

    Args:
        cost_data: Cost metrics for context.
        reason: Human-readable explanation for why the fallback was triggered.

    Returns:
        :class:`BedrockAnalysisResult` with is_fallback=True.
    """
    pct = cost_data.get("percentage_increase", 0)
    if pct > 50:
        severity = "HIGH"
    elif pct > 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    logger.warning(
        "Using fallback Bedrock response",
        extra={"reason": reason, "derived_severity": severity},
    )

    return BedrockAnalysisResult(
        anomaly_severity=severity,
        probable_root_causes=[
            "Automated analysis unavailable — manual investigation required.",
            "Possible causes: new deployments, scaling events, data transfer spikes.",
        ],
        explanation=(
            f"Nova Pro analysis could not be completed ({reason}). "
            f"A cost increase of {pct:.1f}% was detected. "
            "Please review the Cost Explorer console and recent CloudTrail events manually."
        ),
        recommendations=[
            "Review AWS Cost Explorer for service-level breakdown.",
            "Check CloudTrail for recent EC2, RDS, and Auto Scaling changes.",
            "Run AWS Compute Optimizer for rightsizing recommendations.",
            "Compare resource counts today vs the 7-day baseline.",
        ],
        is_fallback=True,
    )


def invoke_bedrock_analysis(
    cost_data: dict[str, Any],
    cloudtrail_summary: Optional[str] = None,
    compute_optimizer_summary: Optional[str] = None,
    model_id: str = DEFAULT_MODEL_ID,
    region: str = "ap-south-1",
    max_tokens: int = 1024,
    temperature: float = 0.7,
    max_attempts: int = 3,
    base_delay: float = 2.0,
    # Legacy parameter kept for backward compatibility
    deployment_logs: Optional[list[dict[str, Any]]] = None,
) -> BedrockAnalysisResult:
    """Invoke Bedrock Amazon Nova Pro to analyze a cost anomaly.

    Calls Nova Pro via the Converse API with structured cost data, CloudTrail
    events, and Compute Optimizer recommendations. Implements exponential-backoff
    retry on transient errors and returns a safe fallback on unrecoverable failures.

    Args:
        cost_data: Cost metrics dictionary (yesterday_cost, baseline_cost, etc.).
        cloudtrail_summary: Pre-formatted CloudTrail resource changes string.
        compute_optimizer_summary: Pre-formatted Compute Optimizer recommendations string.
        model_id: Bedrock model identifier (default: amazon.nova-pro-v1:0).
        region: AWS region for the Bedrock Runtime client (default: ap-south-1).
        max_tokens: Maximum number of tokens in Nova Pro's response.
        temperature: Sampling temperature (0.7 balances precision and creativity).
        max_attempts: Maximum retry attempts on transient failures.
        base_delay: Initial backoff delay in seconds.
        deployment_logs: Deprecated — ignored. Kept for backward compatibility.

    Returns:
        :class:`BedrockAnalysisResult` with analysis or fallback data.
    """
    prompt = _build_analysis_prompt(
        cost_data=cost_data,
        cloudtrail_summary=cloudtrail_summary,
        compute_optimizer_summary=compute_optimizer_summary,
    )

    client = _build_bedrock_client(region)

    messages = [
        {
            "role": "user",
            "content": [{"text": prompt}],
        }
    ]

    system = [{"text": SYSTEM_PROMPT}]
    inference_config = {"maxTokens": max_tokens, "temperature": temperature}

    last_exc: Optional[Exception] = None
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(
                "Invoking Bedrock Nova Pro",
                extra={"model_id": model_id, "attempt": attempt, "region": region},
            )
            response = client.converse(
                modelId=model_id,
                messages=messages,
                system=system,
                inferenceConfig=inference_config,
            )

            usage = response.get("usage", {})
            input_tokens = usage.get("inputTokens", 0)
            output_tokens = usage.get("outputTokens", 0)

            logger.info(
                "Bedrock Nova Pro invocation successful",
                extra={
                    "model_id": model_id,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                },
            )

            content_blocks = (
                response.get("output", {})
                .get("message", {})
                .get("content", [])
            )
            raw_text = " ".join(
                block.get("text", "") for block in content_blocks if "text" in block
            )

            parsed = _parse_bedrock_response(raw_text)

            return BedrockAnalysisResult(
                anomaly_severity=parsed["anomaly_severity"],
                probable_root_causes=parsed["probable_root_causes"],
                explanation=parsed["explanation"],
                recommendations=parsed["recommendations"],
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                model_id=model_id,
                is_fallback=False,
                raw_response=raw_text,
            )

        except (ClientError, BotoCoreError) as exc:
            last_exc = exc
            error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")

            non_retryable = {
                "AccessDeniedException",
                "ValidationException",
                "ResourceNotFoundException",
                "ModelNotReadyException",
            }
            if error_code in non_retryable or attempt == max_attempts:
                logger.error(
                    "Bedrock Nova Pro API error (non-retryable or max attempts reached)",
                    extra={"error_code": error_code, "attempt": attempt, "error": str(exc)},
                )
                break

            delay = base_delay * (2 ** (attempt - 1))
            logger.warning(
                "Bedrock Nova Pro transient error, retrying in %.1fs (attempt %d/%d): %s",
                delay,
                attempt,
                max_attempts,
                exc,
            )
            time.sleep(delay)

        except BedRockException as exc:
            logger.error("Failed to parse Nova Pro response: %s", exc)
            last_exc = exc
            break

    return _fallback_response(
        cost_data,
        reason=str(last_exc) if last_exc else "unknown error",
    )
