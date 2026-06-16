"""Unit tests for lambda_handler.py."""

import json
import os
import sys
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Set required env vars before importing the module
os.environ.setdefault("ES_HOST", "localhost")
os.environ.setdefault("SLACK_WEBHOOK_URL", "https://hooks.slack.com/test")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class MockContext:
    """Minimal AWS Lambda context mock."""

    aws_request_id = "test-request-id-1234"


def _mock_env(overrides: dict | None = None):
    """Return a minimal valid environment dict for Config."""
    env = {
        "ES_HOST": "localhost",
        "ES_PORT": "9200",
        "SLACK_WEBHOOK_URL": "https://hooks.slack.com/test",
        "AWS_REGION": "us-east-1",
        "BEDROCK_MODEL_ID": "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "COST_THRESHOLD_PCT": "15.0",
        "DYNAMODB_TABLE": "cost-idempotency",
    }
    if overrides:
        env.update(overrides)
    return env


class TestConfig:
    """Tests for Config validation."""

    def test_raises_on_missing_es_host(self):
        from lambda_handler import Config

        env = _mock_env({"ES_HOST": ""})
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(EnvironmentError, match="ES_HOST"):
                Config()

    def test_raises_on_missing_slack_webhook(self):
        from lambda_handler import Config

        env = _mock_env({"SLACK_WEBHOOK_URL": ""})
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(EnvironmentError, match="SLACK_WEBHOOK_URL"):
                Config()

    def test_defaults_threshold_to_15(self):
        from lambda_handler import Config

        env = _mock_env()
        env.pop("COST_THRESHOLD_PCT", None)
        with patch.dict(os.environ, env, clear=True):
            cfg = Config()
        assert cfg.cost_threshold_pct == pytest.approx(15.0)

    def test_defaults_aws_region(self):
        from lambda_handler import Config

        env = _mock_env()
        env.pop("AWS_REGION", None)
        with patch.dict(os.environ, env, clear=True):
            cfg = Config()
        assert cfg.aws_region == "us-east-1"


class TestIdempotency:
    """Tests for DynamoDB idempotency helpers."""

    def test_check_returns_true_when_record_exists(self):
        from lambda_handler import _check_idempotency

        mock_table = MagicMock()
        mock_table.get_item.return_value = {"Item": {"execution_date": "2024-01-15"}}

        with patch("lambda_handler.boto3.resource") as mock_resource:
            mock_resource.return_value.Table.return_value = mock_table
            result = _check_idempotency("my-table", "2024-01-15", "us-east-1")

        assert result is True

    def test_check_returns_false_when_no_record(self):
        from lambda_handler import _check_idempotency

        mock_table = MagicMock()
        mock_table.get_item.return_value = {}  # No "Item" key

        with patch("lambda_handler.boto3.resource") as mock_resource:
            mock_resource.return_value.Table.return_value = mock_table
            result = _check_idempotency("my-table", "2024-01-15", "us-east-1")

        assert result is False

    def test_check_returns_false_on_boto_error(self):
        from botocore.exceptions import ClientError
        from lambda_handler import _check_idempotency

        error_response = {"Error": {"Code": "ResourceNotFoundException", "Message": "Table not found"}}
        with patch("lambda_handler.boto3.resource") as mock_resource:
            mock_resource.return_value.Table.side_effect = ClientError(error_response, "Table")
            result = _check_idempotency("missing-table", "2024-01-15", "us-east-1")

        assert result is False

    def test_record_execution_writes_to_dynamo(self):
        from lambda_handler import _record_execution

        mock_table = MagicMock()
        with patch("lambda_handler.boto3.resource") as mock_resource:
            mock_resource.return_value.Table.return_value = mock_table
            _record_execution(
                "my-table",
                "2024-01-15",
                "abc123",
                "us-east-1",
                {"anomaly_detected": True},
            )

        mock_table.put_item.assert_called_once()
        item = mock_table.put_item.call_args[1]["Item"]
        assert item["execution_date"] == "2024-01-15"
        assert item["analysis_id"] == "abc123"

    def test_record_execution_tolerates_boto_error(self):
        from botocore.exceptions import BotoCoreError
        from lambda_handler import _record_execution

        with patch("lambda_handler.boto3.resource") as mock_resource:
            mock_resource.return_value.Table.return_value.put_item.side_effect = BotoCoreError()
            # Should not raise
            _record_execution("table", "2024-01-15", "id", "us-east-1", {})


class TestHandlerIntegration:
    """Integration tests for the Lambda handler function."""

    def _get_handler(self):
        import importlib
        import lambda_handler as lh

        importlib.reload(lh)
        return lh.handler

    def _make_cost_result(self, anomaly_detected: bool = True, pct: float = 20.0):
        from cost_analyzer import CostAnalysisResult

        return CostAnalysisResult(
            anomaly_detected=anomaly_detected,
            cost_delta=20.0 if anomaly_detected else 2.0,
            percentage_increase=pct,
            baseline_cost=100.0,
            yesterday_cost=120.0 if anomaly_detected else 102.0,
            analysis_date="2024-01-15",
            threshold_pct=15.0,
        )

    def _make_bedrock_result(self):
        from bedrock_agent import BedrockAnalysisResult

        return BedrockAnalysisResult(
            anomaly_severity="HIGH",
            probable_root_causes=["EC2 spike"],
            explanation="Explanation",
            recommendations=["Review EC2"],
            input_tokens=300,
            output_tokens=100,
            is_fallback=False,
        )

    def test_returns_200_when_no_anomaly(self):
        env = _mock_env()
        handler = self._get_handler()

        with patch.dict(os.environ, env, clear=True):
            with patch("lambda_handler._check_idempotency", return_value=False):
                with patch("lambda_handler._stage_fetch_historical_costs", return_value=[100.0] * 7):
                    with patch(
                        "lambda_handler.run_cost_analysis",
                        return_value=self._make_cost_result(anomaly_detected=False, pct=5.0),
                    ):
                        with patch("lambda_handler._record_execution"):
                            result = handler({}, MockContext())

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "No anomaly" in body["message"]

    def test_returns_200_when_anomaly_detected_and_alert_sent(self):
        env = _mock_env()
        handler = self._get_handler()

        with patch.dict(os.environ, env, clear=True):
            with patch("lambda_handler._check_idempotency", return_value=False):
                with patch("lambda_handler._stage_fetch_historical_costs", return_value=[100.0] * 7):
                    with patch(
                        "lambda_handler.run_cost_analysis",
                        return_value=self._make_cost_result(anomaly_detected=True),
                    ):
                        with patch(
                            "lambda_handler._stage_fetch_deployment_context",
                            return_value=([], []),
                        ):
                            with patch(
                                "lambda_handler._stage_bedrock_analysis",
                                return_value=self._make_bedrock_result(),
                            ):
                                with patch(
                                    "lambda_handler._stage_send_alert", return_value=True
                                ):
                                    with patch("lambda_handler._record_execution"):
                                        result = handler({}, MockContext())

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["anomaly_detected"] is True
        assert body["slack_alert_sent"] is True

    def test_skips_when_already_ran_today(self):
        env = _mock_env()
        handler = self._get_handler()

        with patch.dict(os.environ, env, clear=True):
            with patch("lambda_handler._check_idempotency", return_value=True):
                result = handler({}, MockContext())

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "already completed" in body["message"]

    def test_returns_500_on_missing_config(self):
        # Missing both required vars
        handler = self._get_handler()

        with patch.dict(os.environ, {"ES_HOST": "", "SLACK_WEBHOOK_URL": ""}, clear=True):
            result = handler({}, MockContext())

        assert result["statusCode"] == 500

    def test_returns_500_on_cost_api_failure(self):
        from cost_analyzer import AWSException

        env = _mock_env()
        handler = self._get_handler()

        with patch.dict(os.environ, env, clear=True):
            with patch("lambda_handler._check_idempotency", return_value=False):
                with patch("lambda_handler._stage_fetch_historical_costs", return_value=[100.0]):
                    with patch(
                        "lambda_handler.run_cost_analysis",
                        side_effect=AWSException("CE API unavailable"),
                    ):
                        result = handler({}, MockContext())

        assert result["statusCode"] == 500

    def test_slack_failure_does_not_stop_pipeline(self):
        """Pipeline completes successfully even when Slack alert fails."""
        env = _mock_env()
        handler = self._get_handler()

        with patch.dict(os.environ, env, clear=True):
            with patch("lambda_handler._check_idempotency", return_value=False):
                with patch("lambda_handler._stage_fetch_historical_costs", return_value=[100.0] * 7):
                    with patch(
                        "lambda_handler.run_cost_analysis",
                        return_value=self._make_cost_result(anomaly_detected=True),
                    ):
                        with patch(
                            "lambda_handler._stage_fetch_deployment_context",
                            return_value=([], []),
                        ):
                            with patch(
                                "lambda_handler._stage_bedrock_analysis",
                                return_value=self._make_bedrock_result(),
                            ):
                                with patch(
                                    "lambda_handler._stage_send_alert", return_value=False
                                ):
                                    with patch("lambda_handler._record_execution"):
                                        result = handler({}, MockContext())

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["slack_alert_sent"] is False

    def test_response_contains_execution_time(self):
        env = _mock_env()
        handler = self._get_handler()

        with patch.dict(os.environ, env, clear=True):
            with patch("lambda_handler._check_idempotency", return_value=False):
                with patch("lambda_handler._stage_fetch_historical_costs", return_value=[100.0] * 7):
                    with patch(
                        "lambda_handler.run_cost_analysis",
                        return_value=self._make_cost_result(anomaly_detected=False),
                    ):
                        with patch("lambda_handler._record_execution"):
                            result = handler({}, MockContext())

        assert "executionTime" in result
        assert isinstance(result["executionTime"], int)
