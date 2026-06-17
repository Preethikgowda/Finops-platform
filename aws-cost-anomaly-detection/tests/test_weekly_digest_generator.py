"""Tests for weekly_digest_generator.py.

Covers:
- Weekly anomaly aggregation from DynamoDB
- Team spend breakdown (Cost Explorer)
- Top cost reduction opportunity ranking
- Spend forecast (linear extrapolation)
- Historical week-over-week / month-over-month comparison
- Slack digest message building
- send_weekly_team_digest orchestration
"""

import json
import os
from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest

from weekly_digest_generator import (
    aggregate_weekly_anomalies,
    calculate_team_spend_breakdown,
    historical_comparison,
    send_weekly_team_digest,
    spend_forecast,
    top_cost_reduction_opportunities,
    _build_team_digest_message,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def slack_env(monkeypatch):
    """Provide required SLACK_WEBHOOK_URL for all tests."""
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/test")


@pytest.fixture
def sample_anomaly_items():
    return [
        {
            "metric_type": "anomaly",
            "execution_date": "2024-01-15",
            "severity": "HIGH",
            "yesterday_cost_usd": "200.00",
            "percentage_increase": "50.0",
            "analysis_id": "abc123",
        },
        {
            "metric_type": "anomaly",
            "execution_date": "2024-01-16",
            "severity": "MEDIUM",
            "yesterday_cost_usd": "150.00",
            "percentage_increase": "20.0",
            "analysis_id": "def456",
        },
    ]


# ---------------------------------------------------------------------------
# aggregate_weekly_anomalies
# ---------------------------------------------------------------------------

class TestAggregateWeeklyAnomalies:
    def test_groups_by_severity(self, sample_anomaly_items):
        with patch("weekly_digest_generator._dynamodb_resource") as mock_db:
            table = mock_db.return_value.Table.return_value
            table.query.return_value = {"Items": sample_anomaly_items}

            result = aggregate_weekly_anomalies("test-table", region="ap-south-1")

        assert result["total_anomalies"] == 2
        assert result["by_severity"]["HIGH"] == 1
        assert result["by_severity"]["MEDIUM"] == 1

    def test_zero_anomalies_returns_empty_summary(self):
        with patch("weekly_digest_generator._dynamodb_resource") as mock_db:
            table = mock_db.return_value.Table.return_value
            table.query.return_value = {"Items": []}

            result = aggregate_weekly_anomalies("test-table", region="ap-south-1")

        assert result["total_anomalies"] == 0
        assert result["total_cost_impact"] == 0.0

    def test_cost_impact_is_positive(self, sample_anomaly_items):
        with patch("weekly_digest_generator._dynamodb_resource") as mock_db:
            table = mock_db.return_value.Table.return_value
            table.query.return_value = {"Items": sample_anomaly_items}

            result = aggregate_weekly_anomalies("test-table", region="ap-south-1")

        assert result["total_cost_impact"] >= 0.0

    def test_api_failure_returns_safe_defaults(self):
        with patch("weekly_digest_generator._dynamodb_resource") as mock_db:
            mock_db.return_value.Table.return_value.query.side_effect = Exception("DB error")

            result = aggregate_weekly_anomalies("test-table", region="ap-south-1")

        assert result["total_anomalies"] == 0
        assert result["summary"] is not None

    def test_summary_string_contains_count(self, sample_anomaly_items):
        with patch("weekly_digest_generator._dynamodb_resource") as mock_db:
            table = mock_db.return_value.Table.return_value
            table.query.return_value = {"Items": sample_anomaly_items}

            result = aggregate_weekly_anomalies("test-table", region="ap-south-1")

        assert "2" in result["summary"]


# ---------------------------------------------------------------------------
# calculate_team_spend_breakdown
# ---------------------------------------------------------------------------

class TestCalculateTeamSpendBreakdown:
    def test_returns_team_entries(self):
        ce_response = {
            "ResultsByTime": [
                {
                    "Groups": [
                        {
                            "Keys": ["CostCenter$engineering", "Amazon EC2"],
                            "Metrics": {"UnblendedCost": {"Amount": "1000.00"}},
                        },
                        {
                            "Keys": ["CostCenter$engineering", "Amazon RDS"],
                            "Metrics": {"UnblendedCost": {"Amount": "300.00"}},
                        },
                    ]
                }
            ]
        }

        with patch("weekly_digest_generator._ce_client") as mock_ce:
            mock_ce.return_value.get_cost_and_usage.return_value = ce_response

            results = calculate_team_spend_breakdown(region="ap-south-1")

        engineering = next((r for r in results if r["team"] == "engineering"), None)
        assert engineering is not None
        assert engineering["weekly_spend"] == pytest.approx(1300.0, rel=1e-3)

    def test_monthly_forecast_is_weekly_times_4_33(self):
        ce_response = {
            "ResultsByTime": [
                {
                    "Groups": [
                        {
                            "Keys": ["CostCenter$team-a", "Amazon EC2"],
                            "Metrics": {"UnblendedCost": {"Amount": "100.0"}},
                        }
                    ]
                }
            ]
        }

        with patch("weekly_digest_generator._ce_client") as mock_ce:
            mock_ce.return_value.get_cost_and_usage.return_value = ce_response

            results = calculate_team_spend_breakdown(region="ap-south-1")

        team = results[0]
        assert team["monthly_forecast"] == pytest.approx(100.0 * 4.33, rel=1e-2)

    def test_top_services_limited_to_3(self):
        groups = [
            {
                "Keys": ["CostCenter$eng", f"Service-{i}"],
                "Metrics": {"UnblendedCost": {"Amount": str(100 - i * 10)}},
            }
            for i in range(6)
        ]
        with patch("weekly_digest_generator._ce_client") as mock_ce:
            mock_ce.return_value.get_cost_and_usage.return_value = {
                "ResultsByTime": [{"Groups": groups}]
            }

            results = calculate_team_spend_breakdown(region="ap-south-1")

        eng = next((r for r in results if r["team"] == "eng"), None)
        assert len(eng["top_services"]) <= 3

    def test_api_failure_returns_empty_list(self):
        from botocore.exceptions import ClientError
        with patch("weekly_digest_generator._ce_client") as mock_ce:
            mock_ce.return_value.get_cost_and_usage.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "D"}}, "GetCostAndUsage"
            )

            results = calculate_team_spend_breakdown(region="ap-south-1")

        assert results == []


# ---------------------------------------------------------------------------
# top_cost_reduction_opportunities
# ---------------------------------------------------------------------------

class TestTopCostReductionOpportunities:
    def test_all_opportunity_types_included(self):
        results = top_cost_reduction_opportunities(
            utilization_savings=100.0,
            ri_savings=200.0,
            s3_savings=50.0,
        )
        categories = {r["category"] for r in results}
        assert "Right-sizing" in categories
        assert "Reserved Instances" in categories
        assert "S3 Lifecycle" in categories

    def test_sorted_by_savings_descending(self):
        results = top_cost_reduction_opportunities(
            utilization_savings=50.0,
            ri_savings=300.0,
            s3_savings=10.0,
        )
        for i in range(len(results) - 1):
            assert results[i]["monthly_savings"] >= results[i + 1]["monthly_savings"]

    def test_zero_savings_items_excluded(self):
        results = top_cost_reduction_opportunities(
            utilization_savings=0.0,
            ri_savings=0.0,
            s3_savings=0.0,
        )
        assert results == []

    def test_annual_savings_is_monthly_times_12(self):
        results = top_cost_reduction_opportunities(utilization_savings=100.0)
        rightsizing = next(r for r in results if r["category"] == "Right-sizing")
        assert rightsizing["annual_savings"] == pytest.approx(100.0 * 12, rel=1e-3)


# ---------------------------------------------------------------------------
# spend_forecast
# ---------------------------------------------------------------------------

class TestSpendForecast:
    def test_forecast_calculated_from_daily_costs(self):
        daily_cost = 100.0
        periods = [
            {"Total": {"UnblendedCost": {"Amount": str(daily_cost)}}}
            for _ in range(30)
        ]

        with patch("weekly_digest_generator._ce_client") as mock_ce:
            mock_ce.return_value.get_cost_and_usage.return_value = {
                "ResultsByTime": periods
            }

            result = spend_forecast(region="ap-south-1")

        assert result["monthly_forecast"] == pytest.approx(daily_cost * 30.44, rel=0.01)
        assert result["avg_daily_spend"] == pytest.approx(daily_cost, rel=1e-3)

    def test_trend_detected_as_up(self):
        # Second half more expensive than first
        costs = [50.0] * 15 + [150.0] * 15
        periods = [
            {"Total": {"UnblendedCost": {"Amount": str(c)}}} for c in costs
        ]
        with patch("weekly_digest_generator._ce_client") as mock_ce:
            mock_ce.return_value.get_cost_and_usage.return_value = {
                "ResultsByTime": periods
            }
            result = spend_forecast(region="ap-south-1")

        assert result["trend_direction"] == "up"

    def test_empty_data_returns_zero_forecast(self):
        with patch("weekly_digest_generator._ce_client") as mock_ce:
            mock_ce.return_value.get_cost_and_usage.return_value = {"ResultsByTime": []}
            result = spend_forecast(region="ap-south-1")

        assert result["monthly_forecast"] == 0.0

    def test_api_failure_returns_safe_defaults(self):
        from botocore.exceptions import ClientError
        with patch("weekly_digest_generator._ce_client") as mock_ce:
            mock_ce.return_value.get_cost_and_usage.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "D"}}, "GetCostAndUsage"
            )
            result = spend_forecast(region="ap-south-1")

        assert result["monthly_forecast"] == 0.0
        assert result["trend_direction"] == "unknown"


# ---------------------------------------------------------------------------
# historical_comparison
# ---------------------------------------------------------------------------

class TestHistoricalComparison:
    def test_wow_percent_calculation(self):
        # Current week $200, last week $100 → +100%
        with patch("weekly_digest_generator._ce_client") as mock_ce:
            mock_ce.return_value.get_cost_and_usage.side_effect = [
                # this_week
                {"ResultsByTime": [{"Total": {"UnblendedCost": {"Amount": "200"}}}]},
                # last_week
                {"ResultsByTime": [{"Total": {"UnblendedCost": {"Amount": "100"}}}]},
                # this_month
                {"ResultsByTime": [{"Total": {"UnblendedCost": {"Amount": "800"}}}]},
                # last_month
                {"ResultsByTime": [{"Total": {"UnblendedCost": {"Amount": "700"}}}]},
            ]
            result = historical_comparison(region="ap-south-1")

        assert result["week_over_week_pct"] == pytest.approx(100.0, rel=1e-2)

    def test_api_failure_returns_zeros(self):
        from botocore.exceptions import ClientError
        with patch("weekly_digest_generator._ce_client") as mock_ce:
            mock_ce.return_value.get_cost_and_usage.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "D"}}, "GetCostAndUsage"
            )
            result = historical_comparison(region="ap-south-1")

        assert result["week_over_week_pct"] == 0.0
        assert result["trend"] == "unknown"


# ---------------------------------------------------------------------------
# _build_team_digest_message
# ---------------------------------------------------------------------------

class TestBuildTeamDigestMessage:
    def test_message_contains_team_name(self):
        msg = _build_team_digest_message(
            team="engineering",
            team_data={"weekly_spend": 500.0, "weekly_change_percent": 5.0, "monthly_forecast": 2166.0, "top_services": []},
            opportunities=[],
            anomaly_summary={"total_anomalies": 0, "by_severity": {}},
            forecast={"monthly_forecast": 2166.0},
        )
        assert "engineering" in json.dumps(msg)

    def test_message_has_blocks_and_text(self):
        msg = _build_team_digest_message(
            team="ops",
            team_data={"weekly_spend": 100.0, "weekly_change_percent": 0.0, "monthly_forecast": 433.0, "top_services": []},
            opportunities=[],
            anomaly_summary={"total_anomalies": 0, "by_severity": {}},
            forecast={"monthly_forecast": 433.0},
        )
        assert "text" in msg
        assert "blocks" in msg

    def test_anomaly_block_shown_when_anomalies_present(self):
        msg = _build_team_digest_message(
            team="finance",
            team_data={"weekly_spend": 200.0, "weekly_change_percent": 10.0, "monthly_forecast": 866.0, "top_services": []},
            opportunities=[],
            anomaly_summary={"total_anomalies": 3, "by_severity": {"HIGH": 1, "MEDIUM": 2, "LOW": 0}},
            forecast={"monthly_forecast": 866.0},
        )
        blocks_text = json.dumps(msg["blocks"])
        assert "3" in blocks_text or "Anomal" in blocks_text

    def test_dashboard_button_shown_when_url_provided(self):
        msg = _build_team_digest_message(
            team="platform",
            team_data={"weekly_spend": 100.0, "weekly_change_percent": 0.0, "monthly_forecast": 433.0, "top_services": []},
            opportunities=[],
            anomaly_summary={"total_anomalies": 0, "by_severity": {}},
            forecast={"monthly_forecast": 433.0},
            dashboard_url="https://example.com/dashboard",
        )
        blocks_text = json.dumps(msg["blocks"])
        assert "https://example.com/dashboard" in blocks_text


# ---------------------------------------------------------------------------
# send_weekly_team_digest integration
# ---------------------------------------------------------------------------

class TestSendWeeklyTeamDigest:
    def test_sends_message_for_each_team(self):
        team_data = [
            {"team": "eng", "weekly_spend": 100.0, "weekly_change_percent": 0.0, "monthly_forecast": 433.0, "top_services": []},
            {"team": "ops", "weekly_spend": 50.0, "weekly_change_percent": 2.0, "monthly_forecast": 216.0, "top_services": []},
        ]
        with patch("weekly_digest_generator.aggregate_weekly_anomalies", return_value={"total_anomalies": 0, "by_severity": {}, "total_cost_impact": 0.0, "summary": ""}), \
             patch("weekly_digest_generator.calculate_team_spend_breakdown", return_value=team_data), \
             patch("weekly_digest_generator.top_cost_reduction_opportunities", return_value=[]), \
             patch("weekly_digest_generator.spend_forecast", return_value={"monthly_forecast": 0.0}), \
             patch("weekly_digest_generator._post_to_slack", return_value=True) as mock_post:

            result = send_weekly_team_digest(region="ap-south-1")

        assert result["messages_sent"] == 2
        assert set(result["teams"]) == {"eng", "ops"}
        assert mock_post.call_count == 2

    def test_fallback_when_no_team_breakdown(self):
        with patch("weekly_digest_generator.aggregate_weekly_anomalies", return_value={"total_anomalies": 0, "by_severity": {}, "total_cost_impact": 0.0, "summary": ""}), \
             patch("weekly_digest_generator.calculate_team_spend_breakdown", return_value=[]), \
             patch("weekly_digest_generator.top_cost_reduction_opportunities", return_value=[]), \
             patch("weekly_digest_generator.spend_forecast", return_value={"monthly_forecast": 500.0}), \
             patch("weekly_digest_generator.historical_comparison", return_value={"this_week_spend": 500.0, "week_over_week_pct": 3.0}), \
             patch("weekly_digest_generator._post_to_slack", return_value=True):

            result = send_weekly_team_digest(region="ap-south-1")

        assert result["messages_sent"] == 1
        assert "All Teams" in result["teams"]

    def test_slack_failure_counted_correctly(self):
        team_data = [
            {"team": "eng", "weekly_spend": 100.0, "weekly_change_percent": 0.0, "monthly_forecast": 433.0, "top_services": []},
        ]
        with patch("weekly_digest_generator.aggregate_weekly_anomalies", return_value={"total_anomalies": 0, "by_severity": {}, "total_cost_impact": 0.0, "summary": ""}), \
             patch("weekly_digest_generator.calculate_team_spend_breakdown", return_value=team_data), \
             patch("weekly_digest_generator.top_cost_reduction_opportunities", return_value=[]), \
             patch("weekly_digest_generator.spend_forecast", return_value={"monthly_forecast": 0.0}), \
             patch("weekly_digest_generator._post_to_slack", return_value=False):

            result = send_weekly_team_digest(region="ap-south-1")

        assert result["messages_sent"] == 0

    def test_missing_webhook_raises(self, monkeypatch):
        monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
        with pytest.raises(EnvironmentError, match="SLACK_WEBHOOK_URL"):
            send_weekly_team_digest(region="ap-south-1")
