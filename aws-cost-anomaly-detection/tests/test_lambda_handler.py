"""Unit tests for lambda_handler.py."""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Set required env vars before importing the module
os.environ.setdefault("SLACK_WEBHOOK_URL", "https://hooks.slack.com/test")
os.environ.setdefault("DYNAMODB_TABLE_NAME", "finops-cost-baselines")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class MockContext:
    """Minimal AWS Lambda context mock."""

    aws_request_id = "test-request-id-1234"


def _mock_env(overrides: dict | None = None):
    """Return a minimal valid environment dict for Config."""
    env = {
        "SLACK_WEBHOOK_URL": "https://hooks.slack.com/test",
        "AWS_REGION": "ap-south-1",
        "BEDROCK_MODEL_ID": "amazon.nova-pro-v1:0",
        "COST_THRESHOLD_PCT": "15.0",
        "DYNAMODB_TABLE_NAME": "finops-cost-baselines",
        "CLOUDTRAIL_S3_BUCKET": "my-cloudtrail-bucket",
        "ATHENA_RESULTS_BUCKET": "my-athena-results",
        "ATHENA_DATABASE": "cloudtrail_logs",
        "ATHENA_TABLE": "cloudtrail",
    }
    if overrides:
        env.update(overrides)
    return env


class TestConfig:
    """Tests for Config validation."""

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

    def test_defaults_aws_region_to_ap_south_1(self):
        from lambda_handler import Config

        env = _mock_env()
        env.pop("AWS_REGION", None)
        with patch.dict(os.environ, env, clear=True):
            cfg = Config()
        assert cfg.aws_region == "ap-south-1"

    def test_default_bedrock_model_is_nova_pro(self):
        from lambda_handler import Config

        env = _mock_env()
        env.pop("BEDROCK_MODEL_ID", None)
        with patch.dict(os.environ, env, clear=True):
            cfg = Config()
        assert cfg.bedrock_model_id == "amazon.nova-pro-v1:0"

    def test_default_dynamodb_table_is_finops_baselines(self):
        from lambda_handler import Config

        env = _mock_env()
        env.pop("DYNAMODB_TABLE_NAME", None)
        with patch.dict(os.environ, env, clear=True):
            cfg = Config()
        assert cfg.dynamodb_table == "finops-cost-baselines"

    def test_no_es_host_required(self):
        """The new config must NOT require ES_HOST."""
        from lambda_handler import Config

        env = _mock_env()
        # Explicitly ensure ES_HOST is absent — should not raise
        with patch.dict(os.environ, env, clear=True):
            cfg = Config()
        assert not hasattr(cfg, "es_host")

    def test_athena_results_bucket_normalised_to_s3_uri(self):
        from lambda_handler import Config

        env = _mock_env({"ATHENA_RESULTS_BUCKET": "my-results-bucket"})
        with patch.dict(os.environ, env, clear=True):
            cfg = Config()
        assert cfg.athena_results_bucket.startswith("s3://")


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
            probable_root_causes=["EC2 scale-out detected via CloudTrail"],
            explanation="Nova Pro analysis: cost spike due to EC2 launch events.",
            recommendations=["Review EC2 instance types", "Use Compute Optimizer"],
            input_tokens=300,
            output_tokens=100,
            model_id="amazon.nova-pro-v1:0",
            is_fallback=False,
        )

    def _empty_cloudtrail(self) -> dict:
        return {
            "ec2_launches": [],
            "autoscaling_changes": [],
            "rds_changes": [],
            "iam_changes": [],
            "total_events": 0,
            "query_window_hours": 24,
        }

    def _empty_optimizer(self) -> dict:
        return {
            "ec2": [], "lambda": [], "ebs": [],
            "total_savings_usd": 0.0, "total_recommendations": 0,
        }

    def test_returns_200_when_no_anomaly(self):
        env = _mock_env()
        handler = self._get_handler()

        with patch.dict(os.environ, env, clear=True):
            with patch("lambda_handler.check_idempotency", return_value=False):
                with patch("lambda_handler._stage_fetch_baseline_costs", return_value=[100.0] * 7):
                    with patch(
                        "lambda_handler.run_cost_analysis",
                        return_value=self._make_cost_result(anomaly_detected=False, pct=5.0),
                    ):
                        with patch("lambda_handler.store_cost_baseline"):
                            with patch("lambda_handler.record_idempotency"):
                                result = handler({}, MockContext())

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "No anomaly" in body["message"]

    def test_returns_200_when_anomaly_detected_and_alert_sent(self):
        env = _mock_env()
        handler = self._get_handler()

        with patch.dict(os.environ, env, clear=True):
            with patch("lambda_handler.check_idempotency", return_value=False):
                with patch("lambda_handler._stage_fetch_baseline_costs", return_value=[100.0] * 7):
                    with patch(
                        "lambda_handler.run_cost_analysis",
                        return_value=self._make_cost_result(anomaly_detected=True),
                    ):
                        with patch("lambda_handler.store_cost_baseline"):
                            with patch(
                                "lambda_handler._stage_fetch_cloudtrail_changes",
                                return_value=self._empty_cloudtrail(),
                            ):
                                with patch(
                                    "lambda_handler._stage_fetch_compute_optimizer",
                                    return_value=self._empty_optimizer(),
                                ):
                                    with patch(
                                        "lambda_handler._stage_bedrock_analysis",
                                        return_value=self._make_bedrock_result(),
                                    ):
                                        with patch("lambda_handler.store_anomaly_result"):
                                            with patch(
                                                "lambda_handler._stage_send_alert", return_value=True
                                            ):
                                                with patch("lambda_handler.record_idempotency"):
                                                    result = handler({}, MockContext())

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["anomaly_detected"] is True
        assert body["slack_alert_sent"] is True
        assert body["model_id"] == "amazon.nova-pro-v1:0"

    def test_skips_when_already_ran_today(self):
        env = _mock_env()
        handler = self._get_handler()

        with patch.dict(os.environ, env, clear=True):
            with patch("lambda_handler.check_idempotency", return_value=True):
                result = handler({}, MockContext())

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "already completed" in body["message"]

    def test_returns_500_on_missing_config(self):
        handler = self._get_handler()

        with patch.dict(os.environ, {"SLACK_WEBHOOK_URL": ""}, clear=True):
            result = handler({}, MockContext())

        assert result["statusCode"] == 500

    def test_returns_500_on_cost_api_failure(self):
        from cost_analyzer import AWSException

        env = _mock_env()
        handler = self._get_handler()

        with patch.dict(os.environ, env, clear=True):
            with patch("lambda_handler.check_idempotency", return_value=False):
                with patch("lambda_handler._stage_fetch_baseline_costs", return_value=[100.0]):
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
            with patch("lambda_handler.check_idempotency", return_value=False):
                with patch("lambda_handler._stage_fetch_baseline_costs", return_value=[100.0] * 7):
                    with patch(
                        "lambda_handler.run_cost_analysis",
                        return_value=self._make_cost_result(anomaly_detected=True),
                    ):
                        with patch("lambda_handler.store_cost_baseline"):
                            with patch(
                                "lambda_handler._stage_fetch_cloudtrail_changes",
                                return_value=self._empty_cloudtrail(),
                            ):
                                with patch(
                                    "lambda_handler._stage_fetch_compute_optimizer",
                                    return_value=self._empty_optimizer(),
                                ):
                                    with patch(
                                        "lambda_handler._stage_bedrock_analysis",
                                        return_value=self._make_bedrock_result(),
                                    ):
                                        with patch("lambda_handler.store_anomaly_result"):
                                            with patch(
                                                "lambda_handler._stage_send_alert", return_value=False
                                            ):
                                                with patch("lambda_handler.record_idempotency"):
                                                    result = handler({}, MockContext())

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["slack_alert_sent"] is False

    def test_response_contains_execution_time(self):
        env = _mock_env()
        handler = self._get_handler()

        with patch.dict(os.environ, env, clear=True):
            with patch("lambda_handler.check_idempotency", return_value=False):
                with patch("lambda_handler._stage_fetch_baseline_costs", return_value=[100.0] * 7):
                    with patch(
                        "lambda_handler.run_cost_analysis",
                        return_value=self._make_cost_result(anomaly_detected=False),
                    ):
                        with patch("lambda_handler.store_cost_baseline"):
                            with patch("lambda_handler.record_idempotency"):
                                result = handler({}, MockContext())

        assert "executionTime" in result
        assert isinstance(result["executionTime"], int)

    def test_response_includes_cloudtrail_events_count(self):
        env = _mock_env()
        handler = self._get_handler()
        cloudtrail_with_events = {
            **self._empty_cloudtrail(),
            "ec2_launches": [{"eventtime": "2024-01-15"}],
            "total_events": 1,
        }

        with patch.dict(os.environ, env, clear=True):
            with patch("lambda_handler.check_idempotency", return_value=False):
                with patch("lambda_handler._stage_fetch_baseline_costs", return_value=[100.0] * 7):
                    with patch(
                        "lambda_handler.run_cost_analysis",
                        return_value=self._make_cost_result(anomaly_detected=True),
                    ):
                        with patch("lambda_handler.store_cost_baseline"):
                            with patch(
                                "lambda_handler._stage_fetch_cloudtrail_changes",
                                return_value=cloudtrail_with_events,
                            ):
                                with patch(
                                    "lambda_handler._stage_fetch_compute_optimizer",
                                    return_value=self._empty_optimizer(),
                                ):
                                    with patch(
                                        "lambda_handler._stage_bedrock_analysis",
                                        return_value=self._make_bedrock_result(),
                                    ):
                                        with patch("lambda_handler.store_anomaly_result"):
                                            with patch(
                                                "lambda_handler._stage_send_alert", return_value=True
                                            ):
                                                with patch("lambda_handler.record_idempotency"):
                                                    result = handler({}, MockContext())

        body = json.loads(result["body"])
        assert body["cloudtrail_events"] == 1

    def test_no_elasticsearch_in_handler(self):
        """Verify no Elasticsearch references remain in lambda_handler."""
        import lambda_handler
        import inspect
        source = inspect.getsource(lambda_handler)
        assert "elasticsearch" not in source.lower()
        assert "ES_HOST" not in source
