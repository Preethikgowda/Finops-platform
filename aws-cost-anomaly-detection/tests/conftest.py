"""Shared pytest fixtures and configuration."""

import os
import sys

import pytest

# Ensure src/ is on the path for all tests
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Set minimal required environment variables before any module import
os.environ.setdefault("ES_HOST", "localhost")
os.environ.setdefault("SLACK_WEBHOOK_URL", "https://hooks.slack.com/test")
os.environ.setdefault("AWS_REGION", "us-east-1")


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
def sample_deployment_events() -> list:
    """Standard list of deployment events."""
    return [
        {
            "timestamp": "2024-01-15T10:00:00Z",
            "event_type": "deployment",
            "service": "api-gateway",
            "description": "Deploy v2.1.0 to production",
        },
        {
            "timestamp": "2024-01-15T12:00:00Z",
            "event_type": "scaling_event",
            "service": "ec2-asg-prod",
            "description": "Scaled out from 3 to 8 instances",
        },
    ]


@pytest.fixture
def valid_bedrock_response_json() -> str:
    """Valid JSON string as returned by Claude."""
    import json

    return json.dumps(
        {
            "anomaly_severity": "HIGH",
            "probable_root_causes": [
                "EC2 instance count doubled following deployment",
                "Data transfer spike due to larger API payloads",
            ],
            "explanation": "The 50% cost increase correlates with the api-gateway deployment.",
            "recommendations": [
                "Review EC2 instance types for right-sizing opportunities.",
                "Enable AWS Cost Anomaly Detection for automated alerts.",
            ],
        }
    )
