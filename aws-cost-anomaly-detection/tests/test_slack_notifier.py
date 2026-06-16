"""Unit tests for slack_notifier.py."""

import sys
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from slack_notifier import (
    SlackException,
    _format_deployment_events,
    _format_recommendations,
    build_slack_message,
    post_to_slack,
    send_anomaly_alert,
)


SAMPLE_DEPLOYMENT_EVENTS = [
    {
        "timestamp": "2024-01-15T10:00:00Z",
        "event_type": "deployment",
        "service": "api-gateway",
        "description": "Deploy v2.1.0",
    },
    {
        "timestamp": "2024-01-15T12:00:00Z",
        "event_type": "scaling_event",
        "service": "ec2-asg",
        "description": "Scale out to 10 instances",
    },
]


class TestFormatDeploymentEvents:
    """Tests for _format_deployment_events()."""

    def test_formats_single_event(self):
        events = [
            {
                "timestamp": "2024-01-15T10:00:00Z",
                "event_type": "deploy",
                "service": "my-svc",
                "description": "some change",
            }
        ]
        text = _format_deployment_events(events)
        assert "my-svc" in text
        assert "some change" in text

    def test_empty_list_returns_default_message(self):
        text = _format_deployment_events([])
        assert "No deployment events" in text

    def test_caps_at_max_events(self):
        events = [
            {
                "timestamp": f"T{i}",
                "event_type": "deploy",
                "service": f"svc-{i}",
                "description": "d",
            }
            for i in range(10)
        ]
        text = _format_deployment_events(events, max_events=3)
        assert "svc-0" in text
        assert "svc-2" in text
        assert "svc-3" not in text
        assert "7 more" in text

    def test_no_overflow_message_when_within_limit(self):
        events = [
            {
                "timestamp": "T1",
                "event_type": "deploy",
                "service": "svc",
                "description": "d",
            }
        ]
        text = _format_deployment_events(events, max_events=5)
        assert "more" not in text

    def test_uses_at_timestamp_fallback(self):
        events = [
            {
                "@timestamp": "2024-01-15T10:00:00Z",
                "event_type": "deploy",
                "service": "svc",
                "description": "d",
            }
        ]
        text = _format_deployment_events(events)
        assert "2024-01-15" in text


class TestFormatRecommendations:
    """Tests for _format_recommendations()."""

    def test_numbered_list(self):
        recs = ["Do this", "Do that", "Do the other"]
        text = _format_recommendations(recs)
        assert "1. Do this" in text
        assert "2. Do that" in text
        assert "3. Do the other" in text

    def test_empty_returns_default(self):
        text = _format_recommendations([])
        assert "No recommendations" in text


class TestBuildSlackMessage:
    """Tests for build_slack_message()."""

    def _build_default(self, **kwargs):
        defaults = dict(
            analysis_date="2024-01-15",
            yesterday_cost=150.0,
            baseline_cost=100.0,
            cost_delta=50.0,
            percentage_increase=50.0,
            severity="HIGH",
            root_causes=["EC2 spike"],
            explanation="Costs increased due to EC2.",
            recommendations=["Review EC2 usage"],
            deployment_events=SAMPLE_DEPLOYMENT_EVENTS,
            dashboard_url="https://console.aws.amazon.com/cost-reports",
            analysis_id="abc12345",
        )
        defaults.update(kwargs)
        return build_slack_message(**defaults)

    def test_returns_dict_with_text_and_attachments(self):
        msg = self._build_default()
        assert "text" in msg
        assert "attachments" in msg

    def test_fallback_text_contains_severity(self):
        msg = self._build_default(severity="HIGH")
        assert "HIGH" in msg["text"]

    def test_fallback_text_contains_cost(self):
        msg = self._build_default(yesterday_cost=150.0)
        assert "150.00" in msg["text"]

    def test_blocks_are_present(self):
        msg = self._build_default()
        blocks = msg["attachments"][0]["blocks"]
        assert len(blocks) > 0

    def test_high_severity_color_is_red(self):
        msg = self._build_default(severity="HIGH")
        assert msg["attachments"][0]["color"] == "#E01E5A"

    def test_medium_severity_color_is_yellow(self):
        msg = self._build_default(severity="MEDIUM")
        assert msg["attachments"][0]["color"] == "#ECB22E"

    def test_low_severity_color_is_green(self):
        msg = self._build_default(severity="LOW")
        assert msg["attachments"][0]["color"] == "#2EB67D"

    def test_analysis_id_present_in_blocks(self):
        msg = self._build_default(analysis_id="test1234")
        full_text = str(msg)
        assert "test1234" in full_text

    def test_dashboard_url_creates_button_block(self):
        msg = self._build_default(dashboard_url="https://example.com/dashboard")
        block_types = [b["type"] for b in msg["attachments"][0]["blocks"]]
        assert "actions" in block_types

    def test_no_button_when_no_dashboard_url(self):
        msg = self._build_default(dashboard_url="")
        block_types = [b["type"] for b in msg["attachments"][0]["blocks"]]
        assert "actions" not in block_types

    def test_auto_generates_analysis_id(self):
        msg = build_slack_message(
            analysis_date="2024-01-15",
            yesterday_cost=120.0,
            baseline_cost=100.0,
            cost_delta=20.0,
            percentage_increase=20.0,
            severity="LOW",
            root_causes=[],
            explanation="test",
            recommendations=[],
            deployment_events=[],
        )
        assert "text" in msg

    def test_deployment_events_rendered(self):
        msg = self._build_default()
        full_text = str(msg)
        assert "api-gateway" in full_text


class TestPostToSlack:
    """Tests for post_to_slack()."""

    def test_raises_on_empty_webhook_url(self):
        with pytest.raises(SlackException, match="SLACK_WEBHOOK_URL"):
            post_to_slack(webhook_url="", message={})

    def test_returns_true_on_success(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "ok"

        with patch("slack_notifier.requests.post", return_value=mock_response):
            result = post_to_slack("https://hooks.slack.com/test", {"text": "hello"})

        assert result is True

    def test_returns_false_on_non_200_status(self):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "invalid_payload"

        with patch("slack_notifier.requests.post", return_value=mock_response):
            result = post_to_slack("https://hooks.slack.com/test", {"text": "hello"})

        assert result is False

    def test_returns_false_on_timeout(self):
        with patch("slack_notifier.requests.post", side_effect=requests.Timeout()):
            result = post_to_slack("https://hooks.slack.com/test", {"text": "hello"})

        assert result is False

    def test_returns_false_on_request_exception(self):
        with patch(
            "slack_notifier.requests.post",
            side_effect=requests.exceptions.ConnectionError(),
        ):
            result = post_to_slack("https://hooks.slack.com/test", {"text": "hello"})

        assert result is False

    def test_posts_json_content_type(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "ok"

        with patch("slack_notifier.requests.post", return_value=mock_response) as mock_post:
            post_to_slack("https://hooks.slack.com/test", {"text": "hello"})

        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["headers"]["Content-Type"] == "application/json"


class TestSendAnomalyAlert:
    """Tests for send_anomaly_alert()."""

    def test_successful_send(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "ok"

        with patch("slack_notifier.requests.post", return_value=mock_response):
            result = send_anomaly_alert(
                webhook_url="https://hooks.slack.com/test",
                analysis_date="2024-01-15",
                yesterday_cost=150.0,
                baseline_cost=100.0,
                cost_delta=50.0,
                percentage_increase=50.0,
                severity="HIGH",
                root_causes=["EC2 spike"],
                explanation="Explanation text",
                recommendations=["Fix it"],
                deployment_events=SAMPLE_DEPLOYMENT_EVENTS,
            )

        assert result is True

    def test_returns_false_when_post_fails(self):
        with patch("slack_notifier.requests.post", side_effect=requests.Timeout()):
            result = send_anomaly_alert(
                webhook_url="https://hooks.slack.com/test",
                analysis_date="2024-01-15",
                yesterday_cost=150.0,
                baseline_cost=100.0,
                cost_delta=50.0,
                percentage_increase=50.0,
                severity="HIGH",
                root_causes=[],
                explanation="",
                recommendations=[],
                deployment_events=[],
            )

        assert result is False
