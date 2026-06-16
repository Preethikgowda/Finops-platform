"""Bedrock Agent Integration for FinOps Cost Analysis.

Invokes Amazon Bedrock Claude Sonnet 3.5 via the Converse API to analyze
cost anomalies and deployment events, returning structured root-cause analysis
and recommendations.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

# Default Bedrock model identifier (Claude Sonnet 3.5 v2)
DEFAULT_MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v2:0"

SYSTEM_PROMPT = """You are an expert FinOps (Financial Operations) analyst specializing in AWS cloud cost
optimization and anomaly investigation. Your role is to:

1. Analyze AWS cost anomalies and identify the most probable root causes.
2. Correlate cost spikes with deployment events, infrastructure changes, and usage patterns.
3. Provide actionable, prioritized recommendations to reduce costs.
4. Communicate clearly with both technical and non-technical stakeholders.

When analyzing cost data:
- Consider compute, storage, data transfer, and managed service costs separately.
- Look for correlations between deployment events and cost increases.
- Distinguish between one-time charges vs recurring cost increases.
- Estimate the financial impact of each identified root cause.
- Recommend specific AWS services, features, or architectural changes where relevant.

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
    """Structured response from Bedrock cost analysis."""

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
        region: AWS region where Bedrock is available.

    Returns:
        boto3 Bedrock Runtime client.
    """
    return boto3.client("bedrock-runtime", region_name=region)


def _build_analysis_prompt(
    cost_data: dict[str, Any],
    deployment_logs: list[dict[str, Any]],
) -> str:
    """Construct the user-facing analysis prompt from cost data and logs.

    Args:
        cost_data: Dictionary containing cost metrics (yesterday_cost,
                   baseline_cost, cost_delta, percentage_increase, etc.).
        deployment_logs: List of recent deployment events from Elasticsearch.

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
        "### Recent Deployment Events (Last 24 Hours)",
    ]

    if deployment_logs:
        for event in deployment_logs[:20]:  # Cap at 20 events to control token usage
            timestamp = event.get("timestamp", "unknown")
            event_type = event.get("event_type", "unknown")
            description = event.get("description", "no description")
            service = event.get("service", "unknown service")
            prompt_lines.append(f"- [{timestamp}] {event_type} | {service}: {description}")
    else:
        prompt_lines.append("- No deployment events recorded in the last 24 hours.")

    prompt_lines += [
        "",
        "### Analysis Request",
        "Please analyze this cost anomaly, identify probable root causes considering the deployment",
        "events above, and provide specific actionable recommendations.",
        "Respond with valid JSON only — no prose outside the JSON object.",
    ]

    return "\n".join(prompt_lines)


def _parse_bedrock_response(content_text: str) -> dict[str, Any]:
    """Parse and validate the JSON response from Claude.

    Args:
        content_text: Raw text content returned by Bedrock.

    Returns:
        Parsed dictionary with anomaly_severity, probable_root_causes,
        explanation, and recommendations.

    Raises:
        BedRockException: When the response cannot be parsed or is missing
                          required fields.
    """
    # Strip any markdown code fences Claude occasionally adds
    text = content_text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop opening and closing fence lines
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
            f"Bedrock analysis could not be completed ({reason}). "
            f"A cost increase of {pct:.1f}% was detected. "
            "Please review the Cost Explorer console and recent deployment events manually."
        ),
        recommendations=[
            "Review AWS Cost Explorer for service-level breakdown.",
            "Check recent deployment events and auto-scaling activity.",
            "Compare resource counts today vs the 7-day baseline.",
            "Investigate data transfer and storage costs.",
        ],
        is_fallback=True,
    )


def invoke_bedrock_analysis(
    cost_data: dict[str, Any],
    deployment_logs: list[dict[str, Any]],
    model_id: str = DEFAULT_MODEL_ID,
    region: str = "us-east-1",
    max_tokens: int = 1024,
    max_attempts: int = 3,
    base_delay: float = 2.0,
) -> BedrockAnalysisResult:
    """Invoke Bedrock Claude to analyze a cost anomaly.

    Calls Claude via the Converse API with structured cost and deployment data.
    Implements exponential-backoff retry on transient errors and returns a
    safe fallback response on unrecoverable failures.

    Args:
        cost_data: Cost metrics dictionary (output of CostAnalysisResult or
                   equivalent dict with yesterday_cost, baseline_cost, etc.).
        deployment_logs: Recent deployment/infrastructure events from Elasticsearch.
        model_id: Bedrock model identifier.
        region: AWS region for the Bedrock Runtime client.
        max_tokens: Maximum number of tokens in Claude's response.
        max_attempts: Maximum retry attempts on transient failures.
        base_delay: Initial backoff delay in seconds.

    Returns:
        :class:`BedrockAnalysisResult` with analysis or fallback data.
    """
    prompt = _build_analysis_prompt(cost_data, deployment_logs)

    client = _build_bedrock_client(region)

    messages = [
        {
            "role": "user",
            "content": [{"text": prompt}],
        }
    ]

    system = [{"text": SYSTEM_PROMPT}]
    inference_config = {"maxTokens": max_tokens, "temperature": 0.1}

    last_exc: Optional[Exception] = None
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(
                "Invoking Bedrock model",
                extra={"model_id": model_id, "attempt": attempt},
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
                "Bedrock invocation successful",
                extra={
                    "model_id": model_id,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                },
            )

            # Extract text from the response
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

            # Non-retryable errors: access denied, model not available, etc.
            non_retryable = {
                "AccessDeniedException",
                "ValidationException",
                "ResourceNotFoundException",
            }
            if error_code in non_retryable or attempt == max_attempts:
                logger.error(
                    "Bedrock API error (non-retryable or max attempts reached)",
                    extra={"error_code": error_code, "attempt": attempt, "error": str(exc)},
                )
                break

            delay = base_delay * (2 ** (attempt - 1))
            logger.warning(
                "Bedrock API transient error, retrying in %.1fs (attempt %d/%d): %s",
                delay,
                attempt,
                max_attempts,
                exc,
            )
            time.sleep(delay)

        except BedRockException as exc:
            logger.error("Failed to parse Bedrock response: %s", exc)
            last_exc = exc
            break

    return _fallback_response(
        cost_data,
        reason=str(last_exc) if last_exc else "unknown error",
    )
