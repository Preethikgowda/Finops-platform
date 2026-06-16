"""Unit tests for bedrock_agent.py."""

import json
import sys
import os
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from bedrock_agent import (
    BedRockException,
    BedrockAnalysisResult,
    DEFAULT_MODEL_ID,
    _build_analysis_prompt,
    _fallback_response,
    _parse_bedrock_response,
    invoke_bedrock_analysis,
)


SAMPLE_COST_DATA = {
    "yesterday_cost": 150.0,
    "baseline_cost": 100.0,
    "cost_delta": 50.0,
    "percentage_increase": 50.0,
    "analysis_date": "2024-01-15",
}

SAMPLE_DEPLOYMENT_LOGS = [
    {
        "timestamp": "2024-01-15T10:00:00Z",
        "event_type": "deployment",
        "service": "api-gateway",
        "description": "New API version deployed",
    }
]

VALID_BEDROCK_RESPONSE = {
    "anomaly_severity": "HIGH",
    "probable_root_causes": ["New API deployment increased EC2 usage", "Data transfer spike"],
    "explanation": "The 50% cost increase correlates with the API deployment.",
    "recommendations": ["Review EC2 instance types", "Enable Cost Anomaly Detection alerts"],
}


class TestBuildAnalysisPrompt:
    """Tests for _build_analysis_prompt()."""

    def test_includes_cost_data(self):
        prompt = _build_analysis_prompt(SAMPLE_COST_DATA, [])
        assert "$150.00" in prompt
        assert "$100.00" in prompt
        assert "50.0%" in prompt

    def test_includes_deployment_events(self):
        prompt = _build_analysis_prompt(SAMPLE_COST_DATA, SAMPLE_DEPLOYMENT_LOGS)
        assert "api-gateway" in prompt
        assert "New API version deployed" in prompt

    def test_handles_empty_deployment_logs(self):
        prompt = _build_analysis_prompt(SAMPLE_COST_DATA, [])
        assert "No deployment events" in prompt

    def test_caps_events_at_20(self):
        many_events = [
            {"timestamp": f"T{i}", "event_type": "deploy", "service": "svc", "description": "d"}
            for i in range(30)
        ]
        prompt = _build_analysis_prompt(SAMPLE_COST_DATA, many_events)
        # Only 20 events should be included; count occurrences of "svc:"
        assert prompt.count("svc:") == 20

    def test_analysis_date_included(self):
        prompt = _build_analysis_prompt(SAMPLE_COST_DATA, [])
        assert "2024-01-15" in prompt


class TestParseBedrockResponse:
    """Tests for _parse_bedrock_response()."""

    def test_parses_valid_json(self):
        raw = json.dumps(VALID_BEDROCK_RESPONSE)
        result = _parse_bedrock_response(raw)
        assert result["anomaly_severity"] == "HIGH"
        assert len(result["probable_root_causes"]) == 2

    def test_strips_markdown_fences(self):
        raw = f"```json\n{json.dumps(VALID_BEDROCK_RESPONSE)}\n```"
        result = _parse_bedrock_response(raw)
        assert result["anomaly_severity"] == "HIGH"

    def test_raises_on_invalid_json(self):
        with pytest.raises(BedRockException, match="not valid JSON"):
            _parse_bedrock_response("this is not json")

    def test_raises_on_missing_fields(self):
        incomplete = {"anomaly_severity": "HIGH"}
        with pytest.raises(BedRockException, match="missing required fields"):
            _parse_bedrock_response(json.dumps(incomplete))

    def test_severity_normalised_to_uppercase(self):
        data = dict(VALID_BEDROCK_RESPONSE)
        data["anomaly_severity"] = "high"
        result = _parse_bedrock_response(json.dumps(data))
        assert result["anomaly_severity"] == "HIGH"

    def test_invalid_severity_defaults_to_medium(self):
        data = dict(VALID_BEDROCK_RESPONSE)
        data["anomaly_severity"] = "CRITICAL"
        result = _parse_bedrock_response(json.dumps(data))
        assert result["anomaly_severity"] == "MEDIUM"


class TestFallbackResponse:
    """Tests for _fallback_response()."""

    def test_high_severity_over_50_pct(self):
        cost_data = {"percentage_increase": 60.0}
        result = _fallback_response(cost_data, "Bedrock unavailable")
        assert result.anomaly_severity == "HIGH"
        assert result.is_fallback is True

    def test_medium_severity_between_25_and_50(self):
        cost_data = {"percentage_increase": 35.0}
        result = _fallback_response(cost_data, "timeout")
        assert result.anomaly_severity == "MEDIUM"

    def test_low_severity_below_25(self):
        cost_data = {"percentage_increase": 20.0}
        result = _fallback_response(cost_data, "parse error")
        assert result.anomaly_severity == "LOW"

    def test_has_recommendations(self):
        result = _fallback_response({"percentage_increase": 20.0}, "error")
        assert len(result.recommendations) > 0

    def test_has_root_causes(self):
        result = _fallback_response({"percentage_increase": 20.0}, "error")
        assert len(result.probable_root_causes) > 0


class TestInvokeBedrockAnalysis:
    """Tests for invoke_bedrock_analysis()."""

    def _make_mock_client(self) -> MagicMock:
        mock_client = MagicMock()
        mock_client.converse.return_value = {
            "output": {
                "message": {
                    "content": [{"text": json.dumps(VALID_BEDROCK_RESPONSE)}]
                }
            },
            "usage": {"inputTokens": 500, "outputTokens": 200},
        }
        return mock_client

    def test_successful_invocation(self):
        with patch("bedrock_agent._build_bedrock_client") as mock_builder:
            mock_builder.return_value = self._make_mock_client()
            result = invoke_bedrock_analysis(
                cost_data=SAMPLE_COST_DATA,
                deployment_logs=SAMPLE_DEPLOYMENT_LOGS,
            )

        assert isinstance(result, BedrockAnalysisResult)
        assert result.anomaly_severity == "HIGH"
        assert result.is_fallback is False
        assert result.input_tokens == 500
        assert result.output_tokens == 200

    def test_returns_fallback_on_client_error(self):
        from botocore.exceptions import ClientError

        error_response = {
            "Error": {"Code": "AccessDeniedException", "Message": "Access denied"}
        }
        with patch("bedrock_agent._build_bedrock_client") as mock_builder:
            mock_client = MagicMock()
            mock_client.converse.side_effect = ClientError(error_response, "Converse")
            mock_builder.return_value = mock_client

            result = invoke_bedrock_analysis(
                cost_data=SAMPLE_COST_DATA,
                deployment_logs=[],
                max_attempts=1,
            )

        assert result.is_fallback is True

    def test_returns_fallback_on_parse_error(self):
        with patch("bedrock_agent._build_bedrock_client") as mock_builder:
            mock_client = MagicMock()
            mock_client.converse.return_value = {
                "output": {
                    "message": {"content": [{"text": "this is not json"}]}
                },
                "usage": {"inputTokens": 10, "outputTokens": 5},
            }
            mock_builder.return_value = mock_client

            result = invoke_bedrock_analysis(
                cost_data=SAMPLE_COST_DATA,
                deployment_logs=[],
            )

        assert result.is_fallback is True

    def test_retries_on_transient_error(self):
        from botocore.exceptions import BotoCoreError

        valid_response = {
            "output": {
                "message": {"content": [{"text": json.dumps(VALID_BEDROCK_RESPONSE)}]}
            },
            "usage": {"inputTokens": 100, "outputTokens": 50},
        }

        with patch("bedrock_agent._build_bedrock_client") as mock_builder:
            mock_client = MagicMock()
            mock_client.converse.side_effect = [
                BotoCoreError(),
                valid_response,
            ]
            mock_builder.return_value = mock_client

            with patch("bedrock_agent.time.sleep"):
                result = invoke_bedrock_analysis(
                    cost_data=SAMPLE_COST_DATA,
                    deployment_logs=[],
                    max_attempts=3,
                    base_delay=0.01,
                )

        assert result.is_fallback is False
        assert mock_client.converse.call_count == 2

    def test_uses_configured_model_id(self):
        custom_model = "anthropic.claude-3-haiku-20240307-v1:0"
        with patch("bedrock_agent._build_bedrock_client") as mock_builder:
            mock_builder.return_value = self._make_mock_client()
            result = invoke_bedrock_analysis(
                cost_data=SAMPLE_COST_DATA,
                deployment_logs=[],
                model_id=custom_model,
            )

        assert result.model_id == custom_model

    def test_token_usage_tracked(self):
        with patch("bedrock_agent._build_bedrock_client") as mock_builder:
            mock_builder.return_value = self._make_mock_client()
            result = invoke_bedrock_analysis(
                cost_data=SAMPLE_COST_DATA,
                deployment_logs=[],
            )

        assert result.input_tokens > 0
        assert result.output_tokens > 0
