"""Unit tests for compute_optimizer_client.py."""

import sys
import os
from unittest.mock import MagicMock, patch
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from compute_optimizer_client import (
    Recommendation,
    _rec_to_dict,
    format_recommendations_for_prompt,
    get_all_recommendations,
    get_ebs_recommendations,
    get_ec2_recommendations,
    get_lambda_recommendations,
)


def _make_ec2_response() -> dict:
    return {
        "instanceRecommendations": [
            {
                "instanceArn": "arn:aws:ec2:ap-south-1:123:instance/i-0abc123",
                "instanceName": "web-server-1",
                "currentInstanceType": "m5.xlarge",
                "finding": "OVER_PROVISIONED",
                "recommendationOptions": [
                    {
                        "instanceType": "t3.medium",
                        "savingsOpportunity": {
                            "estimatedMonthlySavings": {"value": 95.0, "currency": "USD"}
                        },
                        "migrationEffort": "Low",
                    }
                ],
            }
        ]
    }


def _make_lambda_response() -> dict:
    return {
        "lambdaFunctionRecommendations": [
            {
                "functionArn": "arn:aws:lambda:ap-south-1:123:function:my-function",
                "currentMemorySize": 1024,
                "finding": "OVER_PROVISIONED",
                "memorySizeRecommendationOptions": [
                    {
                        "memorySize": 512,
                        "savingsOpportunity": {
                            "estimatedMonthlySavings": {"value": 20.0, "currency": "USD"}
                        },
                    }
                ],
            }
        ]
    }


def _make_ebs_response() -> dict:
    return {
        "volumeRecommendations": [
            {
                "volumeArn": "arn:aws:ec2:ap-south-1:123:volume/vol-0abc123",
                "currentConfiguration": {"volumeType": "gp2", "volumeSize": 500},
                "finding": "NotOptimized",
                "volumeRecommendationOptions": [
                    {
                        "configuration": {"volumeType": "gp3", "volumeSize": 500},
                        "savingsOpportunity": {
                            "estimatedMonthlySavings": {"value": 30.0, "currency": "USD"}
                        },
                    }
                ],
            }
        ]
    }


class TestGetEc2Recommendations:
    """Tests for get_ec2_recommendations()."""

    def test_returns_recommendations_on_success(self):
        with patch("compute_optimizer_client._build_compute_optimizer_client") as mock_builder:
            mock_client = MagicMock()
            mock_client.get_ec2_instance_recommendations.return_value = _make_ec2_response()
            mock_builder.return_value = mock_client

            recs = get_ec2_recommendations(region="ap-south-1")

        assert len(recs) == 1
        assert recs[0].resource_id == "i-0abc123"
        assert recs[0].resource_type == "EC2_INSTANCE"
        assert recs[0].current_config["instance_type"] == "m5.xlarge"
        assert recs[0].recommended_config["instance_type"] == "t3.medium"
        assert recs[0].estimated_monthly_savings_usd == pytest.approx(95.0)

    def test_returns_empty_list_on_api_error(self):
        from botocore.exceptions import ClientError
        error_resp = {"Error": {"Code": "OptInRequiredException", "Message": "Not opted in"}}

        with patch("compute_optimizer_client._build_compute_optimizer_client") as mock_builder:
            mock_client = MagicMock()
            mock_client.get_ec2_instance_recommendations.side_effect = ClientError(error_resp, "GetEC2")
            mock_builder.return_value = mock_client

            recs = get_ec2_recommendations(region="ap-south-1")

        assert recs == []

    def test_skips_instance_with_no_options(self):
        response = {
            "instanceRecommendations": [
                {
                    "instanceArn": "arn:aws:ec2:ap-south-1:123:instance/i-noopt",
                    "currentInstanceType": "m5.large",
                    "finding": "OVER_PROVISIONED",
                    "recommendationOptions": [],
                }
            ]
        }
        with patch("compute_optimizer_client._build_compute_optimizer_client") as mock_builder:
            mock_client = MagicMock()
            mock_client.get_ec2_instance_recommendations.return_value = response
            mock_builder.return_value = mock_client

            recs = get_ec2_recommendations(region="ap-south-1")

        assert recs == []


class TestGetLambdaRecommendations:
    """Tests for get_lambda_recommendations()."""

    def test_returns_recommendations_on_success(self):
        with patch("compute_optimizer_client._build_compute_optimizer_client") as mock_builder:
            mock_client = MagicMock()
            mock_client.get_lambda_function_recommendations.return_value = _make_lambda_response()
            mock_builder.return_value = mock_client

            recs = get_lambda_recommendations(region="ap-south-1")

        assert len(recs) == 1
        assert recs[0].resource_id == "my-function"
        assert recs[0].resource_type == "LAMBDA_FUNCTION"
        assert recs[0].current_config["memory_mb"] == 1024
        assert recs[0].recommended_config["memory_mb"] == 512
        assert recs[0].estimated_monthly_savings_usd == pytest.approx(20.0)

    def test_returns_empty_on_error(self):
        from botocore.exceptions import BotoCoreError

        with patch("compute_optimizer_client._build_compute_optimizer_client") as mock_builder:
            mock_client = MagicMock()
            mock_client.get_lambda_function_recommendations.side_effect = BotoCoreError()
            mock_builder.return_value = mock_client

            recs = get_lambda_recommendations(region="ap-south-1")

        assert recs == []


class TestGetEbsRecommendations:
    """Tests for get_ebs_recommendations()."""

    def test_returns_recommendations_on_success(self):
        with patch("compute_optimizer_client._build_compute_optimizer_client") as mock_builder:
            mock_client = MagicMock()
            mock_client.get_ebs_volume_recommendations.return_value = _make_ebs_response()
            mock_builder.return_value = mock_client

            recs = get_ebs_recommendations(region="ap-south-1")

        assert len(recs) == 1
        assert recs[0].resource_id == "vol-0abc123"
        assert recs[0].resource_type == "EBS_VOLUME"
        assert recs[0].current_config["volume_type"] == "gp2"
        assert recs[0].recommended_config["volume_type"] == "gp3"
        assert recs[0].estimated_monthly_savings_usd == pytest.approx(30.0)

    def test_returns_empty_on_error(self):
        from botocore.exceptions import ClientError
        error_resp = {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}}

        with patch("compute_optimizer_client._build_compute_optimizer_client") as mock_builder:
            mock_client = MagicMock()
            mock_client.get_ebs_volume_recommendations.side_effect = ClientError(error_resp, "GetEBS")
            mock_builder.return_value = mock_client

            recs = get_ebs_recommendations(region="ap-south-1")

        assert recs == []


class TestGetAllRecommendations:
    """Tests for get_all_recommendations()."""

    def test_consolidates_all_resource_types(self):
        ec2_rec = Recommendation(
            resource_id="i-0abc123", resource_type="EC2_INSTANCE",
            current_config={"instance_type": "m5.xlarge"},
            recommended_config={"instance_type": "t3.medium"},
            estimated_monthly_savings_usd=95.0, finding="OVER_PROVISIONED",
        )
        lam_rec = Recommendation(
            resource_id="my-function", resource_type="LAMBDA_FUNCTION",
            current_config={"memory_mb": 1024},
            recommended_config={"memory_mb": 512},
            estimated_monthly_savings_usd=20.0, finding="OVER_PROVISIONED",
        )
        ebs_rec = Recommendation(
            resource_id="vol-0abc123", resource_type="EBS_VOLUME",
            current_config={"volume_type": "gp2", "volume_size_gb": 500},
            recommended_config={"volume_type": "gp3", "volume_size_gb": 500},
            estimated_monthly_savings_usd=30.0, finding="NotOptimized",
        )

        with patch("compute_optimizer_client.get_ec2_recommendations", return_value=[ec2_rec]):
            with patch("compute_optimizer_client.get_lambda_recommendations", return_value=[lam_rec]):
                with patch("compute_optimizer_client.get_ebs_recommendations", return_value=[ebs_rec]):
                    result = get_all_recommendations(region="ap-south-1")

        assert result["total_recommendations"] == 3
        assert result["total_savings_usd"] == pytest.approx(145.0)
        assert len(result["ec2"]) == 1
        assert len(result["lambda"]) == 1
        assert len(result["ebs"]) == 1

    def test_returns_zero_when_no_recommendations(self):
        with patch("compute_optimizer_client.get_ec2_recommendations", return_value=[]):
            with patch("compute_optimizer_client.get_lambda_recommendations", return_value=[]):
                with patch("compute_optimizer_client.get_ebs_recommendations", return_value=[]):
                    result = get_all_recommendations(region="ap-south-1")

        assert result["total_recommendations"] == 0
        assert result["total_savings_usd"] == 0.0


class TestFormatRecommendationsForPrompt:
    """Tests for format_recommendations_for_prompt()."""

    def test_includes_header_with_total_savings(self):
        recs = {
            "ec2": [{"resource_id": "i-0abc", "current_config": {"instance_type": "m5.xlarge"},
                      "recommended_config": {"instance_type": "t3.medium"},
                      "estimated_monthly_savings_usd": 95.0}],
            "lambda": [],
            "ebs": [],
            "total_savings_usd": 95.0,
            "total_recommendations": 1,
        }
        text = format_recommendations_for_prompt(recs)
        assert "Compute Optimizer Recommendations" in text
        assert "$95.00" in text

    def test_shows_no_recommendations_when_empty(self):
        recs = {
            "ec2": [], "lambda": [], "ebs": [],
            "total_savings_usd": 0.0, "total_recommendations": 0,
        }
        text = format_recommendations_for_prompt(recs)
        assert "No recommendations" in text
