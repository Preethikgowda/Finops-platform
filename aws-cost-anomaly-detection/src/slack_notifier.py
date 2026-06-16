"""Slack Notifier for AWS Cost Anomaly Alerts.

Formats rich Slack Block Kit messages containing cost anomaly data, AI-generated
root-cause analysis, deployment events, and recommended actions, then posts them
to a configured Slack webhook URL.
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


def _format_deployment_events(events: list[dict[str, Any]], max_events: int = 5) -> str:
    """Format deployment events as a compact Slack-friendly bullet list.

    Args:
        events: List of deployment event dicts (``event_type``, ``service``,
                ``description``, ``timestamp`` keys expected).
        max_events: Maximum number of events to include in the message.

    Returns:
        Multi-line string suitable for a Slack text block, or a default
        message when no events are present.
    """
    if not events:
        return "_No deployment events in the last 24 hours._"

    lines: list[str] = []
    for event in events[:max_events]:
        ts = event.get("timestamp", event.get("@timestamp", "unknown"))
        event_type = event.get("event_type", "event")
        service = event.get("service", "unknown service")
        description = event.get("description", "no description")
        lines.append(f"• `{ts}` *{event_type}* — {service}: {description}")

    overflow = len(events) - max_events
    if overflow > 0:
        lines.append(f"_…and {overflow} more event(s)_")

    return "\n".join(lines)


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
    deployment_events: list[dict[str, Any]],
    dashboard_url: str = "",
    analysis_id: Optional[str] = None,
) -> dict[str, Any]:
    """Build a richly formatted Slack Block Kit message for a cost anomaly alert.

    Args:
        analysis_date: Date of the anomalous cost period (YYYY-MM-DD).
        yesterday_cost: Total cost for the anomalous day in USD.
        baseline_cost: 7-day rolling average cost in USD.
        cost_delta: Difference between yesterday_cost and baseline_cost.
        percentage_increase: Percentage by which costs exceeded baseline.
        severity: Severity classification — HIGH, MEDIUM, or LOW.
        root_causes: List of probable root cause strings from Bedrock.
        explanation: Detailed explanation string from Bedrock.
        recommendations: List of recommended action strings from Bedrock.
        deployment_events: List of deployment event dicts from Elasticsearch.
        dashboard_url: Optional URL to the cost dashboard for the alert link.
        analysis_id: Optional unique identifier for correlation/tracking.
                     Generated automatically if not provided.

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
    deployment_text = _format_deployment_events(deployment_events)
    recommendations_text = _format_recommendations(recommendations)

    delta_sign = "+" if cost_delta >= 0 else ""

    header_text = f"{emoji} *AWS Cost Anomaly Detected — {severity} Severity*"
    fallback_text = (
        f"AWS Cost Anomaly [{severity}]: {analysis_date} cost ${yesterday_cost:.2f} "
        f"({delta_sign}{percentage_increase:.1f}% vs ${baseline_cost:.2f} baseline)"
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
                "text": f"*:mag: Root Cause Analysis*\n{explanation}",
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
                "text": f"*:rocket: Recent Deployment Events (Last 24h)*\n{deployment_text}",
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

    # Append dashboard button if URL is provided
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
                        f":clock1: Alert generated at `{timestamp_iso}` UTC  |  "
                        f"Analysis ID: `{analysis_id}`"
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
    deployment_events: list[dict[str, Any]],
    dashboard_url: str = "",
    analysis_id: Optional[str] = None,
) -> bool:
    """Build and send an anomaly alert to Slack in one call.

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
        explanation: Detailed Bedrock explanation.
        recommendations: List of recommended actions.
        deployment_events: Recent deployment events from Elasticsearch.
        dashboard_url: Optional URL to cost dashboard.
        analysis_id: Optional tracking identifier.

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
        deployment_events=deployment_events,
        dashboard_url=dashboard_url,
        analysis_id=analysis_id,
    )

    logger.info(
        "Sending Slack anomaly alert",
        extra={
            "severity": severity,
            "analysis_date": analysis_date,
            "analysis_id": analysis_id,
            "percentage_increase": percentage_increase,
        },
    )

    return post_to_slack(webhook_url=webhook_url, message=message)
