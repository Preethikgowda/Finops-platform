"""Weekly Cost Digest Generator.

Aggregates cost findings from all analysers into a team-level weekly digest
delivered to Slack on Fridays. Unlike the daily anomaly alert, this digest:

- Summarises all anomalies from Mon–Fri grouped by severity.
- Shows per-team/cost-centre spend breakdowns.
- Ranks cost reduction opportunities by potential savings.
- Provides 30-day spend forecasts with confidence intervals.
- Sends one message per team/cost-centre to avoid alert fatigue.

Designed to run on Fridays at 17:00 (UTC) as part of the Lambda handler
schedule. The daily anomaly detection continues on Mon–Thu.
"""

import json
import logging
import os
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

import boto3
import requests
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import BotoCoreError, ClientError
from boto3.dynamodb.conditions import Key
from requests.exceptions import RequestException, Timeout

logger = logging.getLogger(__name__)

_RETRY_CONFIG = BotocoreConfig(
    retries={"max_attempts": 3, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=30,
)

SLACK_REQUEST_TIMEOUT = 15


def _dynamodb_resource(region: str) -> Any:
    return boto3.resource("dynamodb", region_name=region, config=_RETRY_CONFIG)


def _ce_client(region: str) -> Any:
    return boto3.client("ce", region_name=region, config=_RETRY_CONFIG)


def _slack_webhook() -> str:
    url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not url:
        raise EnvironmentError("SLACK_WEBHOOK_URL is required for Slack notifications.")
    return url


def _cost_center_tag() -> str:
    return os.environ.get("COST_CENTER_TAG_NAME", "CostCenter").strip() or "CostCenter"


def _post_to_slack(webhook_url: str, message: dict[str, Any]) -> bool:
    """Post a Slack message payload to a webhook URL.

    Args:
        webhook_url: Slack incoming webhook URL.
        message: Slack-compatible message dict.

    Returns:
        ``True`` on success.
    """
    try:
        response = requests.post(
            webhook_url,
            json=message,
            headers={"Content-Type": "application/json"},
            timeout=SLACK_REQUEST_TIMEOUT,
        )
        if response.status_code == 200 and response.text == "ok":
            logger.info("Slack digest delivered successfully")
            return True
        logger.error(
            "Slack webhook unexpected response: %s %s",
            response.status_code,
            response.text[:200],
        )
        return False
    except Timeout as exc:
        logger.error("Slack webhook timed out: %s", exc)
        return False
    except RequestException as exc:
        logger.error("Slack webhook request failed: %s", exc)
        return False


def aggregate_weekly_anomalies(
    table_name: str,
    region: str = "ap-south-1",
    days: int = 7,
) -> dict[str, Any]:
    """Query DynamoDB for all anomalies recorded in the past N days.

    Groups anomalies by severity and computes a total estimated cost impact.

    Args:
        table_name: DynamoDB table name.
        region: AWS region.
        days: Lookback window in days.

    Returns:
        Dict with keys: ``total_anomalies``, ``by_severity`` (HIGH/MEDIUM/LOW
        counts), ``total_cost_impact``, ``anomalies`` (list of records).
    """
    end_date = date.today()
    start_date = end_date - timedelta(days=days)

    try:
        dynamodb = _dynamodb_resource(region)
        table = dynamodb.Table(table_name)

        response = table.query(
            IndexName="metric_type-execution_date-index",
            KeyConditionExpression=(
                Key("metric_type").eq("anomaly")
                & Key("execution_date").between(
                    start_date.isoformat(), end_date.isoformat()
                )
            ),
        )
        anomalies = response.get("Items", [])

        by_severity: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_cost_impact = 0.0

        for anomaly in anomalies:
            severity = str(anomaly.get("severity", "LOW")).upper()
            by_severity[severity] = by_severity.get(severity, 0) + 1
            try:
                pct = float(anomaly.get("percentage_increase", 0))
                baseline_approx = float(anomaly.get("yesterday_cost_usd", 0)) / max(1, (1 + pct / 100))
                cost_impact = float(anomaly.get("yesterday_cost_usd", 0)) - baseline_approx
                total_cost_impact += max(0, cost_impact)
            except (ValueError, TypeError):
                pass

        summary_msg = (
            f"{len(anomalies)} anomalies detected this week, "
            f"total cost impact: ${total_cost_impact:,.2f}"
        )
        logger.info("Weekly anomaly aggregate: %s", summary_msg)

        return {
            "total_anomalies": len(anomalies),
            "by_severity": by_severity,
            "total_cost_impact": round(total_cost_impact, 2),
            "summary": summary_msg,
            "anomalies": anomalies,
            "period_start": start_date.isoformat(),
            "period_end": end_date.isoformat(),
        }

    except Exception as exc:
        logger.error("Weekly anomaly aggregation failed: %s", exc)
        return {
            "total_anomalies": 0,
            "by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "total_cost_impact": 0.0,
            "summary": "Anomaly data unavailable.",
            "anomalies": [],
        }


def calculate_team_spend_breakdown(
    region: str = "ap-south-1",
) -> list[dict[str, Any]]:
    """Query Cost Explorer to break down weekly spend by CostCenter tag.

    Compares current week to the previous week for trend analysis.

    Args:
        region: AWS region.

    Returns:
        List of dicts with keys: ``team``, ``weekly_spend``,
        ``weekly_change_percent``, ``monthly_forecast``, ``top_services``.
    """
    tag_key = _cost_center_tag()

    try:
        ce = _ce_client(region)
        today = date.today()
        week_start = today - timedelta(days=7)
        prev_week_start = today - timedelta(days=14)

        def _fetch_by_team(start: date, end: date) -> dict[str, dict[str, Any]]:
            resp = ce.get_cost_and_usage(
                TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
                Granularity="WEEKLY",
                Metrics=["UnblendedCost"],
                GroupBy=[
                    {"Type": "TAG", "Key": tag_key},
                    {"Type": "DIMENSION", "Key": "SERVICE"},
                ],
            )
            team_map: dict[str, dict[str, Any]] = {}
            for period in resp.get("ResultsByTime", []):
                for group in period.get("Groups", []):
                    keys = group.get("Keys", [])
                    cost = float(
                        group.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0)
                    )
                    if len(keys) < 2 or cost < 0.01:
                        continue
                    team = keys[0].replace(f"{tag_key}$", "").strip() or "untagged"
                    service = keys[1]
                    if team not in team_map:
                        team_map[team] = {"total": 0.0, "services": {}}
                    team_map[team]["total"] += cost
                    team_map[team]["services"][service] = (
                        team_map[team]["services"].get(service, 0.0) + cost
                    )
            return team_map

        current_week = _fetch_by_team(week_start, today)
        previous_week = _fetch_by_team(prev_week_start, week_start)

        results: list[dict[str, Any]] = []
        all_teams = set(current_week.keys()) | set(previous_week.keys())

        for team in all_teams:
            current_spend = current_week.get(team, {}).get("total", 0.0)
            prev_spend = previous_week.get(team, {}).get("total", 0.0)

            change_pct = 0.0
            if prev_spend > 0:
                change_pct = (current_spend - prev_spend) / prev_spend * 100

            # Monthly forecast: weekly × 4.33
            monthly_forecast = current_spend * 4.33

            top_services = sorted(
                [
                    {"service": s, "cost": round(c, 2)}
                    for s, c in current_week.get(team, {}).get("services", {}).items()
                ],
                key=lambda x: x["cost"],
                reverse=True,
            )[:3]

            results.append(
                {
                    "team": team,
                    "weekly_spend": round(current_spend, 2),
                    "prev_weekly_spend": round(prev_spend, 2),
                    "weekly_change_percent": round(change_pct, 1),
                    "monthly_forecast": round(monthly_forecast, 2),
                    "top_services": top_services,
                }
            )

        results.sort(key=lambda x: x["weekly_spend"], reverse=True)
        return results

    except (ClientError, BotoCoreError) as exc:
        logger.error("Team spend breakdown failed: %s", exc)
        return []


def top_cost_reduction_opportunities(
    utilization_savings: float = 0.0,
    ri_savings: float = 0.0,
    s3_savings: float = 0.0,
    ec2_opportunities: Optional[list[dict[str, Any]]] = None,
    rds_opportunities: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    """Rank cost reduction opportunities by monthly savings potential.

    Consolidates results from all analysers into a prioritised action list.

    Args:
        utilization_savings: Monthly savings from EC2/RDS right-sizing.
        ri_savings: Monthly savings from RI purchases.
        s3_savings: Monthly savings from S3 lifecycle policies.
        ec2_opportunities: Detailed EC2 right-sizing recs (optional).
        rds_opportunities: Detailed RDS right-sizing recs (optional).

    Returns:
        Ranked list of opportunity dicts with keys: ``category``,
        ``monthly_savings``, ``effort``, ``description``.
    """
    opportunities: list[dict[str, Any]] = []

    if utilization_savings > 0:
        ec2_count = len(ec2_opportunities) if ec2_opportunities else 0
        rds_count = len(rds_opportunities) if rds_opportunities else 0
        opportunities.append(
            {
                "category": "Right-sizing",
                "monthly_savings": round(utilization_savings, 2),
                "annual_savings": round(utilization_savings * 12, 2),
                "effort": "low",
                "description": (
                    f"Downsize {ec2_count} EC2 and {rds_count} RDS instances"
                    " running at <20% utilisation"
                ),
                "action": "Auto-generate Terraform PR",
            }
        )

    if ri_savings > 0:
        opportunities.append(
            {
                "category": "Reserved Instances",
                "monthly_savings": round(ri_savings, 2),
                "annual_savings": round(ri_savings * 12, 2),
                "effort": "medium",
                "description": "Purchase 1-year Reserved Instances for stable workloads",
                "action": "Submit RI purchase order via AWS console",
            }
        )

    if s3_savings > 0:
        opportunities.append(
            {
                "category": "S3 Lifecycle",
                "monthly_savings": round(s3_savings, 2),
                "annual_savings": round(s3_savings * 12, 2),
                "effort": "low",
                "description": "Apply Glacier lifecycle policies to infrequently accessed objects",
                "action": "Auto-generate Terraform PR",
            }
        )

    opportunities.sort(key=lambda x: x["monthly_savings"], reverse=True)

    total_monthly = sum(o["monthly_savings"] for o in opportunities)
    total_annual = sum(o["annual_savings"] for o in opportunities)
    logger.info(
        "Top opportunities: %d items, $%.2f/month total potential savings",
        len(opportunities),
        total_monthly,
    )

    return opportunities


def spend_forecast(
    region: str = "ap-south-1",
    lookback_days: int = 30,
) -> dict[str, Any]:
    """Forecast monthly spend using linear extrapolation from daily costs.

    Args:
        region: AWS region.
        lookback_days: Days of historical data to use for the forecast.

    Returns:
        Dict with ``monthly_forecast``, ``confidence_interval_pct``,
        ``trend_direction``, ``budget_warning``.
    """
    try:
        ce = _ce_client(region)
        end_date = date.today()
        start_date = end_date - timedelta(days=lookback_days)

        response = ce.get_cost_and_usage(
            TimePeriod={"Start": start_date.isoformat(), "End": end_date.isoformat()},
            Granularity="DAILY",
            Metrics=["UnblendedCost"],
        )

        daily_costs: list[float] = []
        for period in response.get("ResultsByTime", []):
            cost = float(
                period.get("Total", {}).get("UnblendedCost", {}).get("Amount", 0)
            )
            daily_costs.append(cost)

        if not daily_costs:
            return {
                "monthly_forecast": 0.0,
                "confidence_interval_pct": 5.0,
                "trend_direction": "unknown",
                "budget_warning": False,
            }

        n = len(daily_costs)
        avg_daily = sum(daily_costs) / n
        monthly_forecast = avg_daily * 30.44

        # Simple linear trend: compare first half vs second half
        half = n // 2
        first_half_avg = sum(daily_costs[:half]) / half if half > 0 else avg_daily
        second_half_avg = sum(daily_costs[half:]) / max(1, n - half)
        trend_pct = (
            (second_half_avg - first_half_avg) / first_half_avg * 100
            if first_half_avg > 0
            else 0.0
        )

        trend_direction = "up" if trend_pct > 2 else ("down" if trend_pct < -2 else "stable")

        # Budget warning: if forecast exceeds last month by > 20%
        last_30_total = sum(daily_costs)
        extrapolated = (last_30_total / n) * 30.44
        budget_warning = trend_pct > 15.0

        return {
            "monthly_forecast": round(monthly_forecast, 2),
            "monthly_forecast_low": round(monthly_forecast * 0.95, 2),
            "monthly_forecast_high": round(monthly_forecast * 1.05, 2),
            "confidence_interval_pct": 5.0,
            "trend_direction": trend_direction,
            "trend_change_pct": round(trend_pct, 1),
            "avg_daily_spend": round(avg_daily, 2),
            "budget_warning": budget_warning,
        }

    except (ClientError, BotoCoreError) as exc:
        logger.error("Spend forecast failed: %s", exc)
        return {
            "monthly_forecast": 0.0,
            "confidence_interval_pct": 5.0,
            "trend_direction": "unknown",
            "budget_warning": False,
        }


def historical_comparison(
    region: str = "ap-south-1",
) -> dict[str, Any]:
    """Compare this week and this month against the previous periods.

    Args:
        region: AWS region.

    Returns:
        Dict with week-over-week and month-over-month comparisons.
    """
    try:
        ce = _ce_client(region)
        today = date.today()

        periods = {
            "this_week": (today - timedelta(days=7), today),
            "last_week": (today - timedelta(days=14), today - timedelta(days=7)),
            "this_month": (today.replace(day=1), today),
            "last_month": (
                (today.replace(day=1) - timedelta(days=1)).replace(day=1),
                today.replace(day=1),
            ),
        }

        totals: dict[str, float] = {}
        for label, (start, end) in periods.items():
            if start >= end:
                totals[label] = 0.0
                continue
            resp = ce.get_cost_and_usage(
                TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
            )
            totals[label] = sum(
                float(p.get("Total", {}).get("UnblendedCost", {}).get("Amount", 0))
                for p in resp.get("ResultsByTime", [])
            )

        wow = (
            (totals["this_week"] - totals["last_week"]) / totals["last_week"] * 100
            if totals.get("last_week", 0) > 0
            else 0.0
        )
        mom = (
            (totals["this_month"] - totals["last_month"]) / totals["last_month"] * 100
            if totals.get("last_month", 0) > 0
            else 0.0
        )

        return {
            "this_week_spend": round(totals.get("this_week", 0), 2),
            "last_week_spend": round(totals.get("last_week", 0), 2),
            "week_over_week_pct": round(wow, 1),
            "this_month_spend": round(totals.get("this_month", 0), 2),
            "last_month_spend": round(totals.get("last_month", 0), 2),
            "month_over_month_pct": round(mom, 1),
            "trend": "spending more" if wow > 5 else ("spending less" if wow < -5 else "stable"),
        }

    except (ClientError, BotoCoreError) as exc:
        logger.error("Historical comparison failed: %s", exc)
        return {
            "this_week_spend": 0.0,
            "last_week_spend": 0.0,
            "week_over_week_pct": 0.0,
            "this_month_spend": 0.0,
            "last_month_spend": 0.0,
            "month_over_month_pct": 0.0,
            "trend": "unknown",
        }


def _build_team_digest_message(
    team: str,
    team_data: dict[str, Any],
    opportunities: list[dict[str, Any]],
    anomaly_summary: dict[str, Any],
    forecast: dict[str, Any],
    dashboard_url: str = "",
) -> dict[str, Any]:
    """Build a Slack Block Kit message for one team's weekly digest.

    Args:
        team: Team or cost-centre name.
        team_data: Output from :func:`calculate_team_spend_breakdown` for this team.
        opportunities: Top opportunities from :func:`top_cost_reduction_opportunities`.
        anomaly_summary: Output of :func:`aggregate_weekly_anomalies`.
        forecast: Output of :func:`spend_forecast`.
        dashboard_url: Optional URL for the "Review" button.

    Returns:
        Slack Block Kit message dict.
    """
    weekly_spend = team_data.get("weekly_spend", 0)
    change_pct = team_data.get("weekly_change_percent", 0)
    monthly_forecast = team_data.get("monthly_forecast", forecast.get("monthly_forecast", 0))
    top_services = team_data.get("top_services", [])
    anomaly_count = anomaly_summary.get("total_anomalies", 0)

    change_arrow = "↑" if change_pct > 0 else ("↓" if change_pct < 0 else "→")
    change_sign = "+" if change_pct > 0 else ""

    services_text = "\n".join(
        f"  • {s['service']}: ${s['cost']:,.2f}" for s in top_services[:3]
    ) or "  • No service data available"

    opportunity_lines = "\n".join(
        f"  {i}. {o['description']}: -${o['monthly_savings']:,.2f}/month"
        for i, o in enumerate(opportunities[:3], 1)
    ) or "  No opportunities identified this week"

    total_opportunity = sum(o.get("monthly_savings", 0) for o in opportunities[:3])

    anomaly_lines = ""
    if anomaly_count > 0:
        sev = anomaly_summary.get("by_severity", {})
        anomaly_lines = (
            f"  • HIGH: {sev.get('HIGH', 0)}, "
            f"MEDIUM: {sev.get('MEDIUM', 0)}, "
            f"LOW: {sev.get('LOW', 0)}"
        )

    header_text = f":bar_chart: Weekly Cost Digest — {team}"
    fallback_text = (
        f"Weekly Cost Digest [{team}]: ${weekly_spend:,.2f} "
        f"({change_arrow}{abs(change_pct):.1f}% WoW)"
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Weekly Cost Digest — {team}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"*:money_with_wings: Spend*\n"
                        f"${weekly_spend:,.2f} "
                        f"({change_arrow}{change_sign}{abs(change_pct):.1f}% WoW)"
                    ),
                },
                {
                    "type": "mrkdwn",
                    "text": f"*:chart_with_upwards_trend: Monthly Forecast*\n${monthly_forecast:,.2f}",
                },
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:cloud: Top Services*\n{services_text}",
            },
        },
    ]

    if anomaly_count > 0:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*:warning: Anomalies This Week:* {anomaly_count} detected\n"
                        f"{anomaly_lines}"
                    ),
                },
            }
        )

    blocks += [
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*:bulb: Cost Reduction Opportunities*\n"
                    f"{opportunity_lines}\n\n"
                    f"*Total potential: -${total_opportunity:,.2f}/month*"
                ),
            },
        },
    ]

    if dashboard_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": ":bar_chart: Review & Approve",
                            "emoji": True,
                        },
                        "url": dashboard_url,
                        "style": "primary",
                        "action_id": "open_weekly_dashboard",
                    }
                ],
            }
        )

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f":clock1: Generated `{timestamp}` UTC | FinOps Weekly Digest",
                }
            ],
        }
    )

    return {
        "text": fallback_text,
        "blocks": blocks,
    }


def send_weekly_team_digest(
    table_name: str = "finops-cost-baselines",
    region: str = "ap-south-1",
    dashboard_url: str = "",
    utilization_savings: float = 0.0,
    ri_savings: float = 0.0,
    s3_savings: float = 0.0,
    ec2_opportunities: Optional[list[dict[str, Any]]] = None,
    rds_opportunities: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Orchestrate and send the weekly cost digest to Slack.

    Sends one message per team/cost-centre. Falls back to a single
    organisation-wide digest if no team breakdown is available.

    Args:
        table_name: DynamoDB table name for anomaly history.
        region: AWS region.
        dashboard_url: Optional URL for the review button in each digest.
        utilization_savings: Monthly savings from right-sizing recommendations.
        ri_savings: Monthly savings from Reserved Instance recommendations.
        s3_savings: Monthly savings from S3 lifecycle recommendations.
        ec2_opportunities: Detailed EC2 utilisation opportunities list.
        rds_opportunities: Detailed RDS utilisation opportunities list.

    Returns:
        Dict with ``messages_sent`` count and ``teams`` list.
    """
    webhook_url = _slack_webhook()
    dashboard_url = dashboard_url or os.environ.get("COST_DASHBOARD_URL", "")

    anomaly_summary = aggregate_weekly_anomalies(table_name, region)
    team_breakdown = calculate_team_spend_breakdown(region)
    opportunities = top_cost_reduction_opportunities(
        utilization_savings=utilization_savings,
        ri_savings=ri_savings,
        s3_savings=s3_savings,
        ec2_opportunities=ec2_opportunities or [],
        rds_opportunities=rds_opportunities or [],
    )
    forecast = spend_forecast(region)

    sent_count = 0
    teams_sent: list[str] = []

    if team_breakdown:
        for team_data in team_breakdown:
            team = team_data.get("team", "unknown")
            message = _build_team_digest_message(
                team=team,
                team_data=team_data,
                opportunities=opportunities,
                anomaly_summary=anomaly_summary,
                forecast=forecast,
                dashboard_url=dashboard_url,
            )
            if _post_to_slack(webhook_url, message):
                sent_count += 1
                teams_sent.append(team)
            else:
                logger.warning("Failed to send digest for team: %s", team)
    else:
        # Fall back: send a single org-wide digest
        historical = historical_comparison(region)
        total_weekly = sum(t.get("weekly_spend", 0) for t in team_breakdown)
        fallback_team_data = {
            "team": "All Teams",
            "weekly_spend": historical.get("this_week_spend", 0),
            "weekly_change_percent": historical.get("week_over_week_pct", 0),
            "monthly_forecast": forecast.get("monthly_forecast", 0),
            "top_services": [],
        }
        message = _build_team_digest_message(
            team="All Teams",
            team_data=fallback_team_data,
            opportunities=opportunities,
            anomaly_summary=anomaly_summary,
            forecast=forecast,
            dashboard_url=dashboard_url,
        )
        if _post_to_slack(webhook_url, message):
            sent_count = 1
            teams_sent = ["All Teams"]

    logger.info(
        "Weekly digest complete: sent %d messages for teams: %s",
        sent_count,
        teams_sent,
    )
    return {"messages_sent": sent_count, "teams": teams_sent}
