"""Unit tests for elasticsearch_client.py."""

import sys
import os
from unittest.mock import MagicMock, patch, call

import pytest
from elasticsearch.exceptions import NotFoundError, AuthenticationException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _make_meta(status: int = 404) -> MagicMock:
    """Build a minimal ApiResponseMeta mock for elasticsearch 8.x ApiError constructors."""
    meta = MagicMock()
    meta.status = status
    return meta

from elasticsearch_client import (
    ElasticsearchException,
    ElasticsearchHealthCheckError,
    build_client,
    extract_cost_values,
    health_check,
    query_deployment_events,
    query_historical_costs,
    query_infrastructure_changes,
)


class TestBuildClient:
    """Tests for build_client()."""

    def test_creates_client_with_basic_auth(self):
        with patch("elasticsearch_client.Elasticsearch") as mock_es:
            build_client(host="localhost", username="user", password="pass")
            kwargs = mock_es.call_args[1]
            assert kwargs["http_auth"] == ("user", "pass")

    def test_creates_client_with_api_key(self):
        with patch("elasticsearch_client.Elasticsearch") as mock_es:
            build_client(host="localhost", api_key="myapikey")
            kwargs = mock_es.call_args[1]
            assert kwargs["api_key"] == "myapikey"

    def test_api_key_takes_precedence_over_basic_auth(self):
        """When both api_key and username/password are provided, api_key is used."""
        with patch("elasticsearch_client.Elasticsearch") as mock_es:
            build_client(
                host="localhost",
                api_key="myapikey",
                username="user",
                password="pass",
            )
            kwargs = mock_es.call_args[1]
            assert "api_key" in kwargs
            assert "http_auth" not in kwargs

    def test_verify_certs_true_by_default(self):
        with patch("elasticsearch_client.Elasticsearch") as mock_es:
            build_client(host="localhost")
            kwargs = mock_es.call_args[1]
            assert kwargs["verify_certs"] is True

    def test_scheme_included_in_hosts(self):
        with patch("elasticsearch_client.Elasticsearch") as mock_es:
            build_client(host="myhost", port=9200, scheme="https")
            kwargs = mock_es.call_args[1]
            assert kwargs["hosts"][0]["scheme"] == "https"
            assert kwargs["hosts"][0]["host"] == "myhost"

    def test_raises_on_client_creation_failure(self):
        with patch(
            "elasticsearch_client.Elasticsearch", side_effect=Exception("connection refused")
        ):
            with pytest.raises(ElasticsearchException, match="Failed to create"):
                build_client(host="badhost")


class TestHealthCheck:
    """Tests for health_check()."""

    def test_returns_health_dict_on_green(self):
        mock_client = MagicMock()
        mock_client.cluster.health.return_value = {
            "status": "green",
            "cluster_name": "my-cluster",
            "number_of_nodes": 3,
        }
        result = health_check(mock_client)
        assert result["status"] == "green"
        assert result["cluster_name"] == "my-cluster"

    def test_returns_health_dict_on_yellow(self):
        mock_client = MagicMock()
        mock_client.cluster.health.return_value = {
            "status": "yellow",
            "cluster_name": "my-cluster",
        }
        result = health_check(mock_client)
        assert result["status"] == "yellow"

    def test_raises_on_red_status(self):
        mock_client = MagicMock()
        mock_client.cluster.health.return_value = {
            "status": "red",
            "cluster_name": "broken-cluster",
        }
        with pytest.raises(ElasticsearchHealthCheckError, match="RED"):
            health_check(mock_client)

    def test_raises_on_connection_error(self):
        from elasticsearch.exceptions import ConnectionError as ESConnError

        mock_client = MagicMock()
        mock_client.cluster.health.side_effect = ESConnError("Connection refused")
        with pytest.raises(ElasticsearchHealthCheckError, match="Cannot connect"):
            health_check(mock_client)

    def test_raises_on_auth_failure(self):
        mock_client = MagicMock()
        mock_client.cluster.health.side_effect = AuthenticationException(
            "Authentication failed", _make_meta(401), None
        )
        with pytest.raises(ElasticsearchHealthCheckError, match="authentication failed"):
            health_check(mock_client)


class TestQueryDeploymentEvents:
    """Tests for query_deployment_events()."""

    def _make_search_response(self, sources: list) -> dict:
        return {
            "hits": {
                "hits": [{"_source": s} for s in sources],
                "total": {"value": len(sources)},
            }
        }

    def test_returns_sources_from_hits(self):
        mock_client = MagicMock()
        sources = [
            {"event_type": "deployment", "service": "api", "description": "v2"},
            {"event_type": "scaling_event", "service": "ec2", "description": "scale up"},
        ]
        mock_client.search.return_value = self._make_search_response(sources)

        results = query_deployment_events(mock_client, index_prefix="deploy-logs")

        assert len(results) == 2
        assert results[0]["service"] == "api"

    def test_returns_empty_on_index_not_found(self):
        mock_client = MagicMock()
        mock_client.search.side_effect = NotFoundError(
            "index_not_found_exception", _make_meta(404), None
        )

        results = query_deployment_events(mock_client)

        assert results == []

    def test_raises_elasticsearch_exception_on_timeout(self):
        from elasticsearch.exceptions import ConnectionTimeout

        mock_client = MagicMock()
        mock_client.search.side_effect = ConnectionTimeout("timed out")

        with pytest.raises(ElasticsearchException, match="timed out"):
            query_deployment_events(mock_client)

    def test_uses_wildcard_index_pattern(self):
        mock_client = MagicMock()
        mock_client.search.return_value = self._make_search_response([])

        query_deployment_events(mock_client, index_prefix="my-deploys")

        call_kwargs = mock_client.search.call_args[1]
        assert call_kwargs["index"] == "my-deploys-*"


class TestQueryHistoricalCosts:
    """Tests for query_historical_costs()."""

    def _make_search_response(self, sources: list) -> dict:
        return {
            "hits": {
                "hits": [{"_source": s} for s in sources],
                "total": {"value": len(sources)},
            }
        }

    def test_returns_cost_documents(self):
        mock_client = MagicMock()
        sources = [
            {"total_cost_usd": 100.0, "@timestamp": "2024-01-10"},
            {"total_cost_usd": 110.0, "@timestamp": "2024-01-11"},
        ]
        mock_client.search.return_value = self._make_search_response(sources)

        results = query_historical_costs(mock_client, days=7)

        assert len(results) == 2

    def test_returns_empty_on_missing_index(self):
        mock_client = MagicMock()
        mock_client.search.side_effect = NotFoundError(
            "not_found", _make_meta(404), None
        )

        results = query_historical_costs(mock_client)

        assert results == []

    def test_raises_on_auth_error(self):
        mock_client = MagicMock()
        mock_client.search.side_effect = AuthenticationException(
            "auth failed", _make_meta(401), None
        )

        with pytest.raises(ElasticsearchException, match="Authentication failed"):
            query_historical_costs(mock_client)


class TestQueryInfrastructureChanges:
    """Tests for query_infrastructure_changes()."""

    def _make_search_response(self, sources: list) -> dict:
        return {
            "hits": {
                "hits": [{"_source": s} for s in sources],
                "total": {"value": len(sources)},
            }
        }

    def test_returns_infra_change_documents(self):
        mock_client = MagicMock()
        sources = [{"change_type": "auto_scaling", "service": "asg-prod"}]
        mock_client.search.return_value = self._make_search_response(sources)

        results = query_infrastructure_changes(mock_client)

        assert len(results) == 1
        assert results[0]["change_type"] == "auto_scaling"


class TestExtractCostValues:
    """Tests for extract_cost_values()."""

    def test_extracts_float_values(self):
        docs = [
            {"total_cost_usd": 100.0},
            {"total_cost_usd": 120.5},
            {"total_cost_usd": 95.0},
        ]
        values = extract_cost_values(docs)
        assert values == pytest.approx([100.0, 120.5, 95.0])

    def test_skips_missing_field(self):
        docs = [
            {"total_cost_usd": 100.0},
            {"other_field": "irrelevant"},
            {"total_cost_usd": 90.0},
        ]
        values = extract_cost_values(docs)
        assert len(values) == 2

    def test_skips_non_numeric_values(self):
        docs = [{"total_cost_usd": "not-a-number"}, {"total_cost_usd": 50.0}]
        values = extract_cost_values(docs)
        assert values == pytest.approx([50.0])

    def test_empty_list_returns_empty(self):
        assert extract_cost_values([]) == []

    def test_custom_cost_field(self):
        docs = [{"my_cost": 200.0}]
        values = extract_cost_values(docs, cost_field="my_cost")
        assert values == pytest.approx([200.0])

    def test_converts_string_numbers(self):
        docs = [{"total_cost_usd": "123.45"}]
        values = extract_cost_values(docs)
        assert values == pytest.approx([123.45])
