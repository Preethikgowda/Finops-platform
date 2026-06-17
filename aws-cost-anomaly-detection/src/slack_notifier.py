"""Slack Notifier for AWS Cost Anomaly Alerts.

Formats rich Slack Block Kit messages containing cost anomaly data, Nova Pro
AI-generated root-cause analysis, CloudTrail findings, Compute Optimizer
recommendations, and recommended actions, then posts them to a configured
Slack webhook URL.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import requests
from requests.exceptions import RequestException, Timeout

logger = logging.getLogger(__name__)

# Timeout for Slack webhook HTTP requests (seconds)
SLACK_REQUEST_TIMEOUT = 10

SEVERITY_EMOJI = {
    "HIGH": ":red_circle:",
    "MEDIUM": ":large_yellow_circle:",
    "LOW": ":large_green_circle:",
}

SEVERITY_COLOR = {
    "HIGH": "#E01E5A",
    "MEDIUM": "#ECB22E",
    "LOW": "#2EB67D",
}


class SlackException(Exception):
    """Raised for Slack webhook delivery failures."""

    pass


def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_cloudtrail_findings(
    cloudtrail_summary: Optional[dict[str, Any]],
    max_events_per_category: int = 3,
) -> str:
    """Format CloudTrail resource changes for Slack display.

    Args:
        cloudtrail_summary: Dict with ec2_launches, autoscaling_changes,
                            rds_changes, iam_changes keys.
        max_events_per_category: Max events to show per category.

    Returns:
        Formatted multi-line string or a default message if no events.
    """
    if not cloudtrail_summary or cloudtrail_summary.get("total_events", 0) == 0:
        return "_No CloudTrail resource changes detected in the last 24 hours._"

    lines: list[str] = []
    hours = cloudtrail_summary.get("query_window_hours", 24)

    ec2 = cloudtrail_summary.get("ec2_launches", [])
    if ec2:
        lines.append(f"*EC2 Launches* ({len(ec2)} instances):")
        for event in ec2[:max_events_per_category]:
            ts = event.get("eventtime", "unknown")
            actor = event.get("useridentity_arn", "").split("/")[-1] or "unknown"
            lines.append(f"  • `{ts}` by {actor}")
        if len(ec2) > max_events_per_category:
            lines.append(f"  _…and {len(ec2) - max_events_per_category} more_")

    asg = cloudtrail_summary.get("autoscaling_changes", [])
    if asg:
        lines.append(f"*Auto Scaling Changes* ({len(asg)} events):")
        for event in asg[:max_events_per_category]:
            ts = event.get("eventtime", "unknown")
            name = event.get("eventname", "unknown")
            lines.append(f"  • `{ts}` {name}")
        if len(asg) > max_events_per_category:
            lines.append(f"  _…and {len(asg) - max_events_per_category} more_")

    rds = cloudtrail_summary.get("rds_changes", [])
    if rds:
        lines.append(f"*RDS Changes* ({len(rds)} events):")
        for event in rds[:max_events_per_category]:
            ts = event.get("eventtime", "unknown")
            name = event.get("eventname", "unknown")
            lines.append(f"  • `{ts}` {name}")

    iam = cloudtrail_summary.get("iam_changes", [])
    if iam:
        lines.append(f"*IAM Changes* ({len(iam)} events):")
        for event in iam[:max_events_per_category]:
            ts = event.get("eventtime", "unknown")
            name = event.get("eventname", "unknown")
            lines.append(f"  • `{ts}` {name}")

    return "\n".join(lines) if lines else "_No significant changes detected._"


def _format_recommendations(recommendations: list[str]) -> str:
    """Format recommendation strings as a numbered Slack list.

    Args:
        recommendations: List of recommendation strings.

    Returns:
        Numbered list string for use in Slack Block Kit text blocks.
    """
    if not recommendations:
        return "_No recommendations available._"
    return "\n".join(
        f"{i}. {rec}" for i, rec in enumerate(recommendations, start=1)
    )


def build_slack_message(
    analysis_date: str,
    yesterday_cost: float,
    baseline_cost: float,
    cost_delta: float,
    percentage_increase: float,
    severity: str,
    root_causes: list[str],
    explanation: str,
    recommendations: list[str],
    cloudtrail_summary: Optional[dict[str, Any]] = None,
    compute_optimizer_savings_usd: float = 0.0,
    dashboard_url: str = "",
    analysis_id: Optional[str] = None,
    model_id: str = "amazon.nova-pro-v1:0",
    # Legacy parameter kept for backward compatibility
    deployment_events: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Build a richly formatted Slack Block Kit message for a cost anomaly alert.

    Args:
        analysis_date: Date of the anomalous cost period (YYYY-MM-DD).
        yesterday_cost: Total cost for the anomalous day in USD.
        baseline_cost: 7-day rolling average cost in USD.
        cost_delta: Difference between yesterday_cost and baseline_cost.
        percentage_increase: Percentage by which costs exceeded baseline.
        severity: Severity classification — HIGH, MEDIUM, or LOW.
        root_causes: List of probable root cause strings from Nova Pro.
        explanation: Detailed explanation string from Nova Pro.
        recommendations: List of recommended action strings from Nova Pro.
        cloudtrail_summary: CloudTrail resource changes summary dict.
        compute_optimizer_savings_usd: Estimated monthly savings from Compute Optimizer.
        dashboard_url: Optional URL to the cost dashboard for the alert link.
        analysis_id: Optional unique identifier for correlation/tracking.
        model_id: Bedrock model used for analysis (shown in footer).
        deployment_events: Deprecated — ignored. Kept for backward compatibility.

    Returns:
        Slack API-compatible message dict (``blocks`` + ``text`` fallback).
    """
    if analysis_id is None:
        analysis_id = str(uuid.uuid4())[:8]

    severity = severity.upper()
    emoji = SEVERITY_EMOJI.get(severity, ":white_circle:")
    color = SEVERITY_COLOR.get(severity, "#cccccc")
    timestamp_iso = _utcnow_iso()

    root_cause_text = "\n".join(f"• {cause}" for cause in root_causes) or "_No root causes identified._"
    cloudtrail_text = _format_cloudtrail_findings(cloudtrail_summary)
    recommendations_text = _format_recommendations(recommendations)

    delta_sign = "+" if cost_delta >= 0 else ""

    header_text = f"{emoji} *AWS Cost Anomaly Detected — {severity} Severity*"
    fallback_text = (
        f"AWS Cost Anomaly [{severity}]: {analysis_date} cost ${yesterday_cost:.2f} "
        f"({delta_sign}{percentage_increase:.1f}% vs ${baseline_cost:.2f} baseline)"
    )

    savings_text = (
        f" | :money_with_wings: Est. monthly savings available: *${compute_optimizer_savings_usd:,.2f}*"
        if compute_optimizer_savings_usd > 0
        else ""
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"AWS Cost Anomaly — {severity} Severity",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": header_text,
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Analysis Date*\n{analysis_date}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Analysis ID*\n`{analysis_id}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Yesterday's Cost*\n${yesterday_cost:,.2f}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*7-Day Baseline*\n${baseline_cost:,.2f}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Cost Delta*\n{delta_sign}${abs(cost_delta):,.2f}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Increase*\n{delta_sign}{percentage_increase:.1f}%",
                },
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:mag: Root Cause Analysis (Amazon Nova Pro)*\n{explanation}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:bulb: Probable Root Causes*\n{root_cause_text}",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:cloud: CloudTrail Resource Changes (Last 24h)*\n{cloudtrail_text}",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:clipboard: Recommended Actions*\n{recommendations_text}",
            },
        },
    ]

    if compute_optimizer_savings_usd > 0:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*:money_with_wings: Compute Optimizer Opportunities*\n"
                        f"Estimated monthly savings: *${compute_optimizer_savings_usd:,.2f}*"
                    ),
                },
            }
        )

    if dashboard_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": ":bar_chart: Open Cost Dashboard",
                            "emoji": True,
                        },
                        "url": dashboard_url,
                        "action_id": "open_cost_dashboard",
                        "style": "primary",
                    }
                ],
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f":clock1: `{timestamp_iso}` UTC  |  "
                        f"Analysis ID: `{analysis_id}`  |  "
                        f"Model: `{model_id}`"
                        f"{savings_text}"
                    ),
                }
            ],
        }
    )

    return {
        "text": fallback_text,
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
            }
        ],
    }


def post_to_slack(
    webhook_url: str,
    message: dict[str, Any],
    timeout: int = SLACK_REQUEST_TIMEOUT,
) -> bool:
    """Post a message payload to a Slack incoming webhook.

    Slack errors (non-200 responses or HTTP exceptions) are logged but do **not**
    raise by default — callers can check the return value. This ensures a Slack
    outage does not halt the anomaly detection pipeline.

    Args:
        webhook_url: Slack incoming webhook URL.
        message: Slack-compatible message payload dict.
        timeout: HTTP request timeout in seconds.

    Returns:
        ``True`` if the message was delivered successfully, ``False`` otherwise.

    Raises:
        SlackException: Only when the webhook URL is empty/invalid.
    """
    if not webhook_url:
        raise SlackException(
            "SLACK_WEBHOOK_URL is not configured. "
            "Set this environment variable to enable Slack notifications."
        )

    try:
        logger.info("Posting alert to Slack webhook")
        response = requests.post(
            webhook_url,
            json=message,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )

        if response.status_code == 200 and response.text == "ok":
            logger.info("Slack alert delivered successfully")
            return True

        logger.error(
            "Slack webhook returned unexpected response",
            extra={
                "status_code": response.status_code,
                "response_body": response.text[:200],
            },
        )
        return False

    except Timeout as exc:
        logger.error(
            "Slack webhook request timed out after %ds: %s", timeout, exc
        )
        return False

    except RequestException as exc:
        logger.error("Slack webhook request failed: %s", exc)
        return False


def send_anomaly_alert(
    webhook_url: str,
    analysis_date: str,
    yesterday_cost: float,
    baseline_cost: float,
    cost_delta: float,
    percentage_increase: float,
    severity: str,
    root_causes: list[str],
    explanation: str,
    recommendations: list[str],
    cloudtrail_summary: Optional[dict[str, Any]] = None,
    compute_optimizer_savings_usd: float = 0.0,
    dashboard_url: str = "",
    analysis_id: Optional[str] = None,
    model_id: str = "amazon.nova-pro-v1:0",
    # Legacy parameter kept for backward compatibility
    deployment_events: Optional[list[dict[str, Any]]] = None,
) -> bool:
    """Build and send a cost anomaly alert to Slack in one call.

    Convenience wrapper that combines :func:`build_slack_message` and
    :func:`post_to_slack`.

    Args:
        webhook_url: Slack incoming webhook URL.
        analysis_date: Date of the anomalous cost period (YYYY-MM-DD).
        yesterday_cost: Total cost for the anomalous day in USD.
        baseline_cost: 7-day rolling average cost in USD.
        cost_delta: Absolute cost difference in USD.
        percentage_increase: Percentage increase vs baseline.
        severity: Severity — HIGH, MEDIUM, or LOW.
        root_causes: List of probable root cause strings.
        explanation: Detailed Nova Pro explanation.
        recommendations: List of recommended actions.
        cloudtrail_summary: CloudTrail resource changes summary dict.
        compute_optimizer_savings_usd: Estimated monthly savings from Compute Optimizer.
        dashboard_url: Optional URL to cost dashboard.
        analysis_id: Optional tracking identifier.
        model_id: Bedrock model used for the analysis.
        deployment_events: Deprecated — ignored. Kept for backward compatibility.

    Returns:
        ``True`` if the alert was sent successfully.
    """
    if analysis_id is None:
        analysis_id = str(uuid.uuid4())[:8]

    message = build_slack_message(
        analysis_date=analysis_date,
        yesterday_cost=yesterday_cost,
        baseline_cost=baseline_cost,
        cost_delta=cost_delta,
        percentage_increase=percentage_increase,
        severity=severity,
        root_causes=root_causes,
        explanation=explanation,
        recommendations=recommendations,
        cloudtrail_summary=cloudtrail_summary,
        compute_optimizer_savings_usd=compute_optimizer_savings_usd,
        dashboard_url=dashboard_url,
        analysis_id=analysis_id,
        model_id=model_id,
    )

    logger.info(
        "Sending Slack anomaly alert",
        extra={
            "severity": severity,
            "analysis_date": analysis_date,
            "analysis_id": analysis_id,
            "percentage_increase": percentage_increase,
            "model_id": model_id,
        },
    )

    return post_to_slack(webhook_url=webhook_url, message=message)
