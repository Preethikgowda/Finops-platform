"""Shared pytest fixtures and configuration."""

import json
import os
import sys

import pytest

# Ensure src/ is on the path for all tests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Set minimal required environment variables before any module import
os.environ.setdefault("SLACK_WEBHOOK_URL", "https://hooks.slack.com/test")
os.environ.setdefault("AWS_REGION", "ap-south-1")
os.environ.setdefault("DYNAMODB_TABLE_NAME", "finops-cost-baselines")


@pytest.fixture
def sample_cost_data() -> dict:
    """Standard cost data dict used across test modules."""
    return {
        "yesterday_cost": 150.0,
        "baseline_cost": 100.0,
        "cost_delta": 50.0,
        "percentage_increase": 50.0,
        "analysis_date": "2024-01-15",
    }


@pytest.fixture
def sample_cloudtrail_summary() -> dict:
    """Standard CloudTrail resource changes summary used across test modules."""
    return {
        "ec2_launches": [
            {
                "eventtime": "2024-01-15T10:00:00Z",
                "useridentity_arn": "arn:aws:iam::123456789012:user/deploy-bot",
                "requestparameters": '{"instanceType": "m5.xlarge", "maxCount": 3}',
                "sourceipaddress": "10.0.0.1",
                "awsregion": "ap-south-1",
            }
        ],
        "autoscaling_changes": [
            {
                "eventtime": "2024-01-15T11:00:00Z",
                "eventname": "SetDesiredCapacity",
                "useridentity_arn": "arn:aws:iam::123456789012:role/asg-role",
                "requestparameters": '{"desiredCapacity": 8}',
                "sourceipaddress": "autoscaling.amazonaws.com",
                "awsregion": "ap-south-1",
            }
        ],
        "rds_changes": [],
        "iam_changes": [],
        "total_events": 2,
        "query_window_hours": 24,
    }


@pytest.fixture
def valid_nova_pro_response_json() -> str:
    """Valid JSON string as returned by Amazon Nova Pro."""
    return json.dumps(
        {
            "anomaly_severity": "HIGH",
            "probable_root_causes": [
                "3x m5.xlarge EC2 instances launched in production",
                "Auto Scaling group scaled from 3 to 8 instances",
            ],
            "explanation": "The 50% cost increase correlates with infrastructure scale-out events detected in CloudTrail.",
            "recommendations": [
                "Review EC2 instance types for right-sizing opportunities.",
                "Enable AWS Cost Anomaly Detection for automated alerts.",
                "Consider Reserved Instances for predictable workloads.",
            ],
        }
    )


@pytest.fixture
def sample_compute_optimizer_recs() -> dict:
    """Sample Compute Optimizer recommendations dict."""
    return {
        "ec2": [
            {
                "resource_id": "i-0abc123",
                "resource_type": "EC2_INSTANCE",
                "current_config": {"instance_type": "m5.xlarge", "finding": "OVER_PROVISIONED"},
                "recommended_config": {"instance_type": "t3.medium"},
                "estimated_monthly_savings_usd": 95.0,
                "finding": "OVER_PROVISIONED",
                "recommendation_reason": "Low",
            }
        ],
        "lambda": [],
        "ebs": [],
        "total_savings_usd": 95.0,
        "total_recommendations": 1,
    }
