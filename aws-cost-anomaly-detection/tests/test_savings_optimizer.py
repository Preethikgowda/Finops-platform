"""Tests for savings_optimizer.py.

Covers:
- RI break-even calculation maths
- EC2 RI opportunity analysis
- Savings Plan opportunity analysis
- RDS RI recommendations
- Consolidation opportunity combining right-sizing + RI
- Spend forecast with commitments
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from savings_optimizer import (
    _calculate_ri_savings,
    analyze_reserved_instance_opportunity,
    analyze_savings_plan_opportunity,
    consolidation_opportunity,
    forecast_spend_with_commitments,
    rds_reserved_instance_recommendations,
)


# ---------------------------------------------------------------------------
# RI break-even calculation
# ---------------------------------------------------------------------------

class TestCalculateRiSavings:
    def test_annual_on_demand_correct(self):
        result = _calculate_ri_savings(hourly_on_demand=1.0)
        assert result["annual_on_demand"] == pytest.approx(8760.0, rel=1e-3)

    def test_1yr_ri_less_than_on_demand(self):
        result = _calculate_ri_savings(hourly_on_demand=1.0)
        assert result["annual_1yr_ri"] < result["annual_on_demand"]

    def test_3yr_ri_less_than_1yr_ri(self):
        result = _calculate_ri_savings(hourly_on_demand=1.0)
        assert result["annual_3yr_ri"] < result["annual_1yr_ri"]

    def test_savings_percentages_positive(self):
        result = _calculate_ri_savings(hourly_on_demand=0.5)
        assert result["savings_1yr_percent"] > 0
        assert result["savings_3yr_percent"] > 0

    def test_annual_savings_equals_difference(self):
        result = _calculate_ri_savings(hourly_on_demand=2.0)
        expected_savings_1yr = result["annual_on_demand"] - result["annual_1yr_ri"]
        assert result["annual_savings_1yr"] == pytest.approx(expected_savings_1yr, rel=1e-3)

    def test_custom_discount_rates(self):
        result = _calculate_ri_savings(
            hourly_on_demand=1.0,
            ri_discount_1yr=0.50,
            ri_discount_3yr=0.70,
        )
        assert result["savings_1yr_percent"] == pytest.approx(50.0, rel=1e-2)
        assert result["savings_3yr_percent"] == pytest.approx(70.0, rel=1e-2)

    def test_payback_months_is_non_negative(self):
        result = _calculate_ri_savings(hourly_on_demand=1.0)
        assert result["payback_months"] >= 0


# ---------------------------------------------------------------------------
# EC2 RI opportunity analysis
# ---------------------------------------------------------------------------

class TestAnalyzeReservedInstanceOpportunity:
    @pytest.fixture
    def running_instance(self):
        return {
            "InstanceId": "i-abc",
            "InstanceType": "m5.xlarge",
        }

    def test_returns_recommendations_for_running_instances(self, running_instance):
        with patch("savings_optimizer._get_cache", return_value=None), \
             patch("savings_optimizer._set_cache"), \
             patch("savings_optimizer._ec2_client") as mock_ec2, \
             patch("savings_optimizer._get_ec2_on_demand_price", return_value=0.192):

            mock_ec2.return_value.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [running_instance]}]}
            ]
            mock_ec2.return_value.describe_reserved_instances.return_value = {
                "ReservedInstances": []
            }

            results = analyze_reserved_instance_opportunity(region="ap-south-1")

        assert len(results) >= 1
        assert results[0]["instance_type"] == "m5.xlarge"
        assert results[0]["annual_savings_1yr"] > 0

    def test_already_reserved_instances_excluded(self, running_instance):
        with patch("savings_optimizer._get_cache", return_value=None), \
             patch("savings_optimizer._set_cache"), \
             patch("savings_optimizer._ec2_client") as mock_ec2, \
             patch("savings_optimizer._get_ec2_on_demand_price", return_value=0.192):

            mock_ec2.return_value.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [running_instance]}]}
            ]
            mock_ec2.return_value.describe_reserved_instances.return_value = {
                "ReservedInstances": [
                    {"InstanceType": "m5.xlarge", "State": "active"}
                ]
            }

            results = analyze_reserved_instance_opportunity(region="ap-south-1")

        assert all(r["instance_type"] != "m5.xlarge" for r in results)

    def test_no_price_data_skipped(self, running_instance):
        with patch("savings_optimizer._get_cache", return_value=None), \
             patch("savings_optimizer._set_cache"), \
             patch("savings_optimizer._ec2_client") as mock_ec2, \
             patch("savings_optimizer._get_ec2_on_demand_price", return_value=None):

            mock_ec2.return_value.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [running_instance]}]}
            ]
            mock_ec2.return_value.describe_reserved_instances.return_value = {
                "ReservedInstances": []
            }

            results = analyze_reserved_instance_opportunity(region="ap-south-1")

        assert len(results) == 0

    def test_cache_hit_avoids_api_calls(self):
        cached = [{"instance_type": "t3.large", "annual_savings_1yr": 500.0}]
        with patch("savings_optimizer._get_cache", return_value=cached), \
             patch("savings_optimizer._ec2_client") as mock_ec2:

            results = analyze_reserved_instance_opportunity(region="ap-south-1")

        mock_ec2.assert_not_called()
        assert results == cached

    def test_api_failure_returns_empty_list(self):
        from botocore.exceptions import ClientError
        with patch("savings_optimizer._get_cache", return_value=None), \
             patch("savings_optimizer._ec2_client") as mock_ec2:

            mock_ec2.return_value.get_paginator.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
                "DescribeInstances",
            )
            results = analyze_reserved_instance_opportunity(region="ap-south-1")

        assert results == []

    def test_results_sorted_by_savings_descending(self, running_instance):
        """Results must be sorted with highest savings first."""
        inst2 = {**running_instance, "InstanceId": "i-xyz", "InstanceType": "c5.xlarge"}
        price_map = {"m5.xlarge": 0.192, "c5.xlarge": 0.17}

        with patch("savings_optimizer._get_cache", return_value=None), \
             patch("savings_optimizer._set_cache"), \
             patch("savings_optimizer._ec2_client") as mock_ec2, \
             patch(
                 "savings_optimizer._get_ec2_on_demand_price",
                 side_effect=lambda itype, region: price_map.get(itype, 0.10),
             ):

            mock_ec2.return_value.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [running_instance, inst2]}]}
            ]
            mock_ec2.return_value.describe_reserved_instances.return_value = {
                "ReservedInstances": []
            }

            results = analyze_reserved_instance_opportunity(region="ap-south-1")

        for i in range(len(results) - 1):
            assert (
                results[i]["total_annual_savings_1yr"]
                >= results[i + 1]["total_annual_savings_1yr"]
            )


# ---------------------------------------------------------------------------
# Savings Plan analysis
# ---------------------------------------------------------------------------

class TestAnalyzeSavingsPlanOpportunity:
    def test_returns_sp_opportunities(self):
        with patch("savings_optimizer._get_cache", return_value=None), \
             patch("savings_optimizer._set_cache"), \
             patch("savings_optimizer._ce_client") as mock_ce:

            mock_ce.return_value.get_cost_and_usage.return_value = {
                "ResultsByTime": [
                    {
                        "Groups": [
                            {
                                "Keys": ["m5.xlarge", "Amazon EC2"],
                                "Metrics": {"UnblendedCost": {"Amount": "500.0"}},
                            }
                        ]
                    }
                ]
            }

            results = analyze_savings_plan_opportunity(region="ap-south-1")

        assert len(results) >= 1
        assert results[0]["annual_savings_1yr"] > 0

    def test_low_cost_instances_excluded(self):
        """Instance types with < $10/month spend should not generate recommendations."""
        with patch("savings_optimizer._get_cache", return_value=None), \
             patch("savings_optimizer._set_cache"), \
             patch("savings_optimizer._ce_client") as mock_ce:

            mock_ce.return_value.get_cost_and_usage.return_value = {
                "ResultsByTime": [
                    {
                        "Groups": [
                            {
                                "Keys": ["t3.nano", "Amazon EC2"],
                                "Metrics": {"UnblendedCost": {"Amount": "1.50"}},
                            }
                        ]
                    }
                ]
            }

            results = analyze_savings_plan_opportunity(region="ap-south-1")

        assert results == []

    def test_ce_api_failure_returns_empty(self):
        from botocore.exceptions import ClientError
        with patch("savings_optimizer._get_cache", return_value=None), \
             patch("savings_optimizer._ce_client") as mock_ce:

            mock_ce.return_value.get_cost_and_usage.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "D"}}, "GetCostAndUsage"
            )
            results = analyze_savings_plan_opportunity(region="ap-south-1")

        assert results == []


# ---------------------------------------------------------------------------
# RDS RI recommendations
# ---------------------------------------------------------------------------

class TestRdsReservedInstanceRecommendations:
    def test_available_rds_generates_recommendation(self):
        db = {
            "DBInstanceIdentifier": "prod-db",
            "DBInstanceClass": "db.m5.xlarge",
            "DBInstanceStatus": "available",
        }
        with patch("savings_optimizer._get_cache", return_value=None), \
             patch("savings_optimizer._set_cache"), \
             patch("savings_optimizer._rds_client") as mock_rds:

            mock_rds.return_value.get_paginator.return_value.paginate.return_value = [
                {"DBInstances": [db]}
            ]

            results = rds_reserved_instance_recommendations(region="ap-south-1")

        assert len(results) >= 1
        assert results[0]["instance_class"] == "db.m5.xlarge"

    def test_unavailable_instance_skipped(self):
        db = {
            "DBInstanceIdentifier": "stopped-db",
            "DBInstanceClass": "db.m5.xlarge",
            "DBInstanceStatus": "stopped",
        }
        with patch("savings_optimizer._get_cache", return_value=None), \
             patch("savings_optimizer._set_cache"), \
             patch("savings_optimizer._rds_client") as mock_rds:

            mock_rds.return_value.get_paginator.return_value.paginate.return_value = [
                {"DBInstances": [db]}
            ]

            results = rds_reserved_instance_recommendations(region="ap-south-1")

        assert results == []


# ---------------------------------------------------------------------------
# Consolidation opportunity
# ---------------------------------------------------------------------------

class TestConsolidationOpportunity:
    def test_combines_rightsizing_and_ri_savings(self):
        underutilized = [
            {
                "instance_id": "i-1",
                "name": "svc-prod",
                "current_type": "m5.xlarge",
                "recommended_type": "t3.large",
                "estimated_savings": 70.0,
                "avg_cpu": 8.0,
            }
        ]
        ri_candidates = [
            {
                "instance_type": "t3.large",
                "annual_savings_1yr": 240.0,
            }
        ]

        results = consolidation_opportunity(underutilized, ri_candidates)

        assert len(results) == 1
        assert results[0]["rightsizing_monthly_savings"] == 70.0
        assert results[0]["ri_monthly_savings"] == pytest.approx(20.0, rel=1e-2)
        assert results[0]["total_monthly_savings"] == pytest.approx(90.0, rel=1e-2)

    def test_no_ri_candidate_for_type(self):
        underutilized = [
            {
                "instance_id": "i-2",
                "name": "svc",
                "current_type": "m5.2xlarge",
                "recommended_type": "t3.xlarge",
                "estimated_savings": 150.0,
                "avg_cpu": 12.0,
            }
        ]
        ri_candidates: list = []

        results = consolidation_opportunity(underutilized, ri_candidates)

        assert len(results) == 1
        assert results[0]["ri_monthly_savings"] == 0.0

    def test_results_sorted_by_total_savings(self):
        underutilized = [
            {"instance_id": "i-a", "name": "a", "current_type": "t3.large", "recommended_type": "t3.medium", "estimated_savings": 30.0, "avg_cpu": 5.0},
            {"instance_id": "i-b", "name": "b", "current_type": "m5.xlarge", "recommended_type": "t3.large", "estimated_savings": 80.0, "avg_cpu": 10.0},
        ]
        results = consolidation_opportunity(underutilized, [])

        assert results[0]["total_monthly_savings"] >= results[1]["total_monthly_savings"]


# ---------------------------------------------------------------------------
# Spend forecast
# ---------------------------------------------------------------------------

class TestForecastSpendWithCommitments:
    def test_savings_reduces_monthly_spend(self):
        ri_candidates = [
            {"total_annual_savings_1yr": 1200.0, "total_annual_savings_3yr": 2000.0}
        ]
        sp_candidates = [{"annual_savings_1yr": 600.0}]

        result = forecast_spend_with_commitments(
            ri_candidates=ri_candidates,
            sp_candidates=sp_candidates,
            current_monthly_spend=1000.0,
        )

        assert result["monthly_with_1yr_commitments"] < 1000.0
        assert result["monthly_with_3yr_commitments"] < result["monthly_with_1yr_commitments"]

    def test_cumulative_12m_baseline_correct(self):
        result = forecast_spend_with_commitments(
            ri_candidates=[],
            sp_candidates=[],
            current_monthly_spend=100.0,
        )
        assert result["cumulative_12m_baseline"] == pytest.approx(1200.0, rel=1e-3)

    def test_no_commitments_baseline_unchanged(self):
        result = forecast_spend_with_commitments(
            ri_candidates=[],
            sp_candidates=[],
            current_monthly_spend=500.0,
        )
        assert result["monthly_with_1yr_commitments"] == pytest.approx(500.0, rel=1e-3)

    def test_savings_percent_positive(self):
        ri_candidates = [{"total_annual_savings_1yr": 600.0, "total_annual_savings_3yr": 1000.0}]
        result = forecast_spend_with_commitments(
            ri_candidates=ri_candidates,
            sp_candidates=[],
            current_monthly_spend=200.0,
        )
        assert result["savings_percent_1yr"] > 0
        assert result["savings_percent_3yr"] > result["savings_percent_1yr"]
