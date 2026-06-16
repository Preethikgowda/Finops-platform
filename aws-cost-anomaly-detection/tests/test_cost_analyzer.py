"""Unit tests for cost_analyzer.py."""

import sys
import os
from datetime import date
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cost_analyzer import (
    AWSException,
    CostAnalysisResult,
    CostDataError,
    calculate_rolling_average,
    detect_anomaly,
    fetch_yesterday_cost,
    run_cost_analysis,
)


# ---------------------------------------------------------------------------
# fetch_yesterday_cost
# ---------------------------------------------------------------------------


class TestFetchYesterdayCost:
    """Tests for fetch_yesterday_cost()."""

    def test_returns_correct_cost_from_api(self):
        """Returns the unblended cost from a well-formed CE response."""
        mock_response = {
            "ResultsByTime": [
                {
                    "Total": {
                        "UnblendedCost": {"Amount": "123.45", "Unit": "USD"}
                    }
                }
            ]
        }
        with patch("cost_analyzer._build_cost_explorer_client") as mock_builder:
            mock_ce = MagicMock()
            mock_ce.get_cost_and_usage.return_value = mock_response
            mock_builder.return_value = mock_ce

            cost = fetch_yesterday_cost(region="us-east-1")

        assert cost == pytest.approx(123.45)

    def test_sums_multiple_results(self):
        """Sums costs across multiple ResultsByTime entries."""
        mock_response = {
            "ResultsByTime": [
                {"Total": {"UnblendedCost": {"Amount": "50.00", "Unit": "USD"}}},
                {"Total": {"UnblendedCost": {"Amount": "75.00", "Unit": "USD"}}},
            ]
        }
        with patch("cost_analyzer._build_cost_explorer_client") as mock_builder:
            mock_ce = MagicMock()
            mock_ce.get_cost_and_usage.return_value = mock_response
            mock_builder.return_value = mock_ce

            cost = fetch_yesterday_cost()

        assert cost == pytest.approx(125.0)

    def test_raises_cost_data_error_on_empty_results(self):
        """Raises CostDataError when ResultsByTime is empty."""
        with patch("cost_analyzer._build_cost_explorer_client") as mock_builder:
            mock_ce = MagicMock()
            mock_ce.get_cost_and_usage.return_value = {"ResultsByTime": []}
            mock_builder.return_value = mock_ce

            with pytest.raises(CostDataError, match="No cost data returned"):
                fetch_yesterday_cost()

    def test_raises_aws_exception_after_retries(self):
        """Raises AWSException when all retries are exhausted."""
        from botocore.exceptions import ClientError

        error_response = {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}}

        with patch("cost_analyzer._build_cost_explorer_client") as mock_builder:
            mock_ce = MagicMock()
            mock_ce.get_cost_and_usage.side_effect = ClientError(error_response, "GetCostAndUsage")
            mock_builder.return_value = mock_ce

            with patch("cost_analyzer.time.sleep"):  # Bypass sleep in tests
                with pytest.raises(AWSException):
                    fetch_yesterday_cost()

    def test_handles_unparseable_amount_gracefully(self):
        """Skips entries with non-numeric amount strings (logs warning, returns 0)."""
        mock_response = {
            "ResultsByTime": [
                {"Total": {"UnblendedCost": {"Amount": "NOT_A_NUMBER", "Unit": "USD"}}}
            ]
        }
        with patch("cost_analyzer._build_cost_explorer_client") as mock_builder:
            mock_ce = MagicMock()
            mock_ce.get_cost_and_usage.return_value = mock_response
            mock_builder.return_value = mock_ce

            cost = fetch_yesterday_cost()

        assert cost == pytest.approx(0.0)

    def test_uses_correct_date_range(self):
        """Passes yesterday as start and today as end to Cost Explorer."""
        yesterday = (date.today() - __import__("datetime").timedelta(days=1)).strftime("%Y-%m-%d")
        today = date.today().strftime("%Y-%m-%d")

        mock_response = {
            "ResultsByTime": [
                {"Total": {"UnblendedCost": {"Amount": "10.00", "Unit": "USD"}}}
            ]
        }
        with patch("cost_analyzer._build_cost_explorer_client") as mock_builder:
            mock_ce = MagicMock()
            mock_ce.get_cost_and_usage.return_value = mock_response
            mock_builder.return_value = mock_ce

            fetch_yesterday_cost()

            call_kwargs = mock_ce.get_cost_and_usage.call_args[1]
            assert call_kwargs["TimePeriod"]["Start"] == yesterday
            assert call_kwargs["TimePeriod"]["End"] == today


# ---------------------------------------------------------------------------
# calculate_rolling_average
# ---------------------------------------------------------------------------


class TestCalculateRollingAverage:
    """Tests for calculate_rolling_average()."""

    def test_correct_average(self):
        assert calculate_rolling_average([10.0, 20.0, 30.0]) == pytest.approx(20.0)

    def test_single_value(self):
        assert calculate_rolling_average([42.5]) == pytest.approx(42.5)

    def test_all_zeros(self):
        assert calculate_rolling_average([0.0, 0.0, 0.0]) == pytest.approx(0.0)

    def test_empty_list_raises(self):
        with pytest.raises(CostDataError, match="no historical cost data"):
            calculate_rolling_average([])

    def test_seven_day_window(self):
        costs = [100.0, 110.0, 90.0, 105.0, 95.0, 115.0, 85.0]
        avg = calculate_rolling_average(costs)
        assert avg == pytest.approx(sum(costs) / len(costs))


# ---------------------------------------------------------------------------
# detect_anomaly
# ---------------------------------------------------------------------------


class TestDetectAnomaly:
    """Tests for detect_anomaly()."""

    def test_detects_anomaly_above_threshold(self):
        anomaly, delta, pct = detect_anomaly(
            yesterday_cost=120.0, baseline_cost=100.0, threshold_pct=15.0
        )
        assert anomaly is True
        assert delta == pytest.approx(20.0)
        assert pct == pytest.approx(20.0)

    def test_no_anomaly_at_threshold(self):
        anomaly, delta, pct = detect_anomaly(
            yesterday_cost=115.0, baseline_cost=100.0, threshold_pct=15.0
        )
        # Exactly at threshold (not strictly above) → no anomaly
        assert anomaly is False
        assert pct == pytest.approx(15.0)

    def test_no_anomaly_below_threshold(self):
        anomaly, delta, pct = detect_anomaly(
            yesterday_cost=110.0, baseline_cost=100.0, threshold_pct=15.0
        )
        assert anomaly is False
        assert pct == pytest.approx(10.0)

    def test_negative_delta(self):
        anomaly, delta, pct = detect_anomaly(
            yesterday_cost=80.0, baseline_cost=100.0, threshold_pct=15.0
        )
        assert anomaly is False
        assert delta == pytest.approx(-20.0)
        assert pct == pytest.approx(-20.0)

    def test_zero_baseline_raises(self):
        with pytest.raises(CostDataError, match="Baseline cost is"):
            detect_anomaly(yesterday_cost=100.0, baseline_cost=0.0)

    def test_negative_baseline_raises(self):
        with pytest.raises(CostDataError):
            detect_anomaly(yesterday_cost=100.0, baseline_cost=-5.0)

    def test_custom_threshold(self):
        anomaly, _, pct = detect_anomaly(
            yesterday_cost=105.0, baseline_cost=100.0, threshold_pct=3.0
        )
        assert anomaly is True
        assert pct == pytest.approx(5.0)


# ---------------------------------------------------------------------------
# run_cost_analysis (integration-style)
# ---------------------------------------------------------------------------


class TestRunCostAnalysis:
    """Integration-style tests for run_cost_analysis()."""

    def _mock_cost_response(self, amount: str = "120.00") -> dict:
        return {
            "ResultsByTime": [
                {"Total": {"UnblendedCost": {"Amount": amount, "Unit": "USD"}}}
            ]
        }

    def test_anomaly_detected_returns_correct_result(self):
        historical_costs = [100.0] * 7
        with patch("cost_analyzer._build_cost_explorer_client") as mock_builder:
            mock_ce = MagicMock()
            mock_ce.get_cost_and_usage.return_value = self._mock_cost_response("120.00")
            mock_builder.return_value = mock_ce

            result = run_cost_analysis(historical_costs=historical_costs, threshold_pct=15.0)

        assert isinstance(result, CostAnalysisResult)
        assert result.anomaly_detected is True
        assert result.yesterday_cost == pytest.approx(120.0)
        assert result.baseline_cost == pytest.approx(100.0)
        assert result.cost_delta == pytest.approx(20.0)
        assert result.percentage_increase == pytest.approx(20.0)

    def test_no_anomaly_when_within_threshold(self):
        historical_costs = [100.0] * 7
        with patch("cost_analyzer._build_cost_explorer_client") as mock_builder:
            mock_ce = MagicMock()
            mock_ce.get_cost_and_usage.return_value = self._mock_cost_response("110.00")
            mock_builder.return_value = mock_ce

            result = run_cost_analysis(historical_costs=historical_costs, threshold_pct=15.0)

        assert result.anomaly_detected is False
        assert result.percentage_increase == pytest.approx(10.0)

    def test_propagates_aws_exception(self):
        from botocore.exceptions import ClientError

        error_response = {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}}
        with patch("cost_analyzer._build_cost_explorer_client") as mock_builder:
            mock_ce = MagicMock()
            mock_ce.get_cost_and_usage.side_effect = ClientError(error_response, "op")
            mock_builder.return_value = mock_ce

            with patch("cost_analyzer.time.sleep"):
                with pytest.raises(AWSException):
                    run_cost_analysis(historical_costs=[100.0])

    def test_propagates_empty_historical_costs(self):
        with patch("cost_analyzer._build_cost_explorer_client") as mock_builder:
            mock_ce = MagicMock()
            mock_ce.get_cost_and_usage.return_value = self._mock_cost_response()
            mock_builder.return_value = mock_ce

            with pytest.raises(CostDataError, match="no historical cost data"):
                run_cost_analysis(historical_costs=[])

    def test_analysis_date_is_yesterday(self):
        yesterday = (date.today() - __import__("datetime").timedelta(days=1)).strftime("%Y-%m-%d")
        historical_costs = [50.0] * 7
        with patch("cost_analyzer._build_cost_explorer_client") as mock_builder:
            mock_ce = MagicMock()
            mock_ce.get_cost_and_usage.return_value = self._mock_cost_response("55.00")
            mock_builder.return_value = mock_ce

            result = run_cost_analysis(historical_costs=historical_costs)

        assert result.analysis_date == yesterday
