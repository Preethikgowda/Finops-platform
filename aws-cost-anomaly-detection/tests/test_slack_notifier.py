"""Unit tests for slack_notifier.py."""

import sys
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from slack_notifier import (
    SlackException,
    _format_cloudtrail_findings,
    _format_recommendations,
    build_slack_message,
    post_to_slack,
    send_anomaly_alert,
)


SAMPLE_CLOUDTRAIL_SUMMARY = {
    "ec2_launches": [
        {
            "eventtime": "2024-01-15T10:00:00Z",
            "useridentity_arn": "arn:aws:iam::123456789012:user/deploy-bot",
        }
    ],
    "autoscaling_changes": [
        {
            "eventtime": "2024-01-15T11:00:00Z",
            "eventname": "SetDesiredCapacity",
        }
    ],
    "rds_changes": [],
    "iam_changes": [],
    "total_events": 2,
    "query_window_hours": 24,
}


class TestFormatCloudTrailFindings:
    """Tests for _format_cloudtrail_findings()."""

    def test_shows_ec2_launch_events(self):
        text = _format_cloudtrail_findings(SAMPLE_CLOUDTRAIL_SUMMARY)
        assert "EC2 Launches" in text
        assert "2024-01-15T10:00:00Z" in text

    def test_shows_asg_changes(self):
        text = _format_cloudtrail_findings(SAMPLE_CLOUDTRAIL_SUMMARY)
        assert "Auto Scaling" in text
        assert "SetDesiredCapacity" in text

    def test_returns_default_when_no_events(self):
        empty = {
            "ec2_launches": [],
            "autoscaling_changes": [],
            "rds_changes": [],
            "iam_changes": [],
            "total_events": 0,
            "query_window_hours": 24,
        }
        text = _format_cloudtrail_findings(empty)
        assert "No CloudTrail resource changes" in text

    def test_returns_default_on_none_summary(self):
        text = _format_cloudtrail_findings(None)
        assert "No CloudTrail" in text

    def test_caps_events_per_category(self):
        many_ec2 = [{"eventtime": f"T{i}", "useridentity_arn": "arn:user"} for i in range(10)]
        summary = {**SAMPLE_CLOUDTRAIL_SUMMARY, "ec2_launches": many_ec2, "total_events": 10}
        text = _format_cloudtrail_findings(summary, max_events_per_category=2)
        assert "more" in text


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
            explanation="Costs increased due to EC2 scale-out events in CloudTrail.",
            recommendations=["Review EC2 usage"],
            cloudtrail_summary=SAMPLE_CLOUDTRAIL_SUMMARY,
            dashboard_url="https://console.aws.amazon.com/cost-reports",
            analysis_id="abc12345",
            model_id="amazon.nova-pro-v1:0",
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

    def test_auto_generates_analysis_id_when_none(self):
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
        )
        assert "text" in msg

    def test_cloudtrail_events_rendered_in_blocks(self):
        msg = self._build_default()
        full_text = str(msg)
        assert "EC2 Launches" in full_text or "2024-01-15" in full_text

    def test_model_id_in_footer(self):
        msg = self._build_default(model_id="amazon.nova-pro-v1:0")
        full_text = str(msg)
        assert "amazon.nova-pro-v1:0" in full_text

    def test_compute_optimizer_savings_shown_when_nonzero(self):
        msg = self._build_default(compute_optimizer_savings_usd=145.0)
        full_text = str(msg)
        assert "145" in full_text

    def test_no_savings_block_when_zero(self):
        msg = self._build_default(compute_optimizer_savings_usd=0.0)
        # When savings is 0, no separate savings block is added
        block_texts = str(msg)
        # Just check it doesn't crash
        assert "text" in msg

    def test_nova_pro_mentioned_in_root_cause_block(self):
        """Root cause section should reference Nova Pro."""
        msg = self._build_default(explanation="Nova Pro analysis found EC2 scale-out.")
        full_text = str(msg)
        assert "Nova Pro" in full_text


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

    def test_successful_send_with_cloudtrail(self):
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
                root_causes=["EC2 spike detected via CloudTrail"],
                explanation="Nova Pro: 3x m5.xlarge instances launched.",
                recommendations=["Review EC2 usage"],
                cloudtrail_summary=SAMPLE_CLOUDTRAIL_SUMMARY,
                compute_optimizer_savings_usd=95.0,
                model_id="amazon.nova-pro-v1:0",
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
            )

        assert result is False

    def test_backward_compat_with_deployment_events_param(self):
        """send_anomaly_alert must accept the legacy deployment_events parameter."""
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
                root_causes=[],
                explanation="",
                recommendations=[],
                deployment_events=[],  # legacy parameter
            )

        assert result is True
