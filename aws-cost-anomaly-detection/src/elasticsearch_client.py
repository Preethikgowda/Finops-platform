"""Elasticsearch Client for Cost Anomaly Detection.

Provides connectivity to Elasticsearch (self-hosted or Elastic Cloud),
health-check verification, and queries for deployment events, infrastructure
changes, and historical cost data.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from elasticsearch import Elasticsearch, AuthenticationException, ConnectionError as ESConnectionError
from elasticsearch.exceptions import ConnectionTimeout, NotFoundError, RequestError, TransportError

logger = logging.getLogger(__name__)


class ElasticsearchException(Exception):
    """Raised for Elasticsearch client errors."""

    pass


class ElasticsearchHealthCheckError(ElasticsearchException):
    """Raised when the Elasticsearch health check fails."""

    pass


def _utcnow() -> datetime:
    """Return the current UTC datetime (extracted for testability)."""
    return datetime.now(tz=timezone.utc)


def build_client(
    host: str,
    port: int = 9200,
    scheme: str = "https",
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    ca_certs: Optional[str] = None,
    verify_certs: bool = True,
    request_timeout: float = 30.0,
    max_retries: int = 3,
    retry_on_timeout: bool = True,
) -> Elasticsearch:
    """Build and return an Elasticsearch client with connection pooling.

    Supports both username/password and API key authentication.
    SSL/TLS certificate verification is enabled by default.

    Args:
        host: Elasticsearch hostname or Elastic Cloud endpoint.
        port: Elasticsearch port (default 9200).
        scheme: Connection scheme — ``'https'`` or ``'http'``.
        username: Basic-auth username (mutually exclusive with api_key).
        password: Basic-auth password (mutually exclusive with api_key).
        api_key: Elastic Cloud / self-hosted API key.
        ca_certs: Path to CA certificate bundle for TLS verification.
        verify_certs: Whether to verify TLS certificates. Set to ``False``
                      only in development environments.
        request_timeout: Socket-level timeout in seconds.
        max_retries: Number of retry attempts on connection errors.
        retry_on_timeout: Retry automatically on timeout errors.

    Returns:
        Configured :class:`Elasticsearch` client instance.

    Raises:
        ElasticsearchException: When the client cannot be created.
    """
    hosts = [{"host": host, "port": port, "scheme": scheme}]

    kwargs: dict[str, Any] = {
        "hosts": hosts,
        "request_timeout": request_timeout,
        "max_retries": max_retries,
        "retry_on_timeout": retry_on_timeout,
        "verify_certs": verify_certs,
    }

    if api_key:
        kwargs["api_key"] = api_key
    elif username and password:
        kwargs["http_auth"] = (username, password)

    if ca_certs:
        kwargs["ca_certs"] = ca_certs

    if not verify_certs:
        logger.warning(
            "TLS certificate verification is DISABLED. Do not use in production."
        )
        kwargs["ssl_show_warn"] = False

    try:
        client = Elasticsearch(**kwargs)
        logger.debug(
            "Elasticsearch client created",
            extra={"host": host, "port": port, "scheme": scheme},
        )
        return client
    except Exception as exc:
        raise ElasticsearchException(
            f"Failed to create Elasticsearch client for {scheme}://{host}:{port}: {exc}"
        ) from exc


def health_check(client: Elasticsearch) -> dict[str, Any]:
    """Verify Elasticsearch cluster is reachable and healthy.

    Args:
        client: Active Elasticsearch client.

    Returns:
        Cluster health response dict (``status``, ``cluster_name``, etc.).

    Raises:
        ElasticsearchHealthCheckError: When the cluster is unreachable or
                                       returns a ``red`` status.
    """
    try:
        health = client.cluster.health(timeout="10s")
        status = health.get("status", "unknown")
        cluster_name = health.get("cluster_name", "unknown")

        logger.info(
            "Elasticsearch health check passed",
            extra={"cluster": cluster_name, "status": status},
        )

        if status == "red":
            raise ElasticsearchHealthCheckError(
                f"Elasticsearch cluster '{cluster_name}' status is RED. "
                "Queries may return incomplete data. Investigate shard allocation."
            )

        return dict(health)

    except (ESConnectionError, ConnectionTimeout) as exc:
        raise ElasticsearchHealthCheckError(
            f"Cannot connect to Elasticsearch: {exc}. "
            "Check ES_HOST, ES_PORT, and network connectivity."
        ) from exc
    except AuthenticationException as exc:
        raise ElasticsearchHealthCheckError(
            f"Elasticsearch authentication failed: {exc}. "
            "Verify ES_USERNAME/ES_PASSWORD or ES_API_KEY."
        ) from exc


def query_deployment_events(
    client: Elasticsearch,
    index_prefix: str = "deployment-logs",
    hours: int = 24,
    max_results: int = 100,
) -> list[dict[str, Any]]:
    """Query recent deployment events from Elasticsearch.

    Retrieves deployment, release, and infrastructure-change events
    created within the specified time window, ordered by timestamp descending.

    Args:
        client: Active Elasticsearch client.
        index_prefix: Index prefix to query (wildcard applied automatically).
        hours: Look-back window in hours.
        max_results: Maximum number of events to return.

    Returns:
        List of deployment event documents (``_source`` contents).

    Raises:
        ElasticsearchException: On query failures.
    """
    since = _utcnow() - timedelta(hours=hours)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": since_iso,
                                "lte": "now",
                            }
                        }
                    }
                ],
                "should": [
                    {"term": {"event_type": "deployment"}},
                    {"term": {"event_type": "release"}},
                    {"term": {"event_type": "infrastructure_change"}},
                    {"term": {"event_type": "scaling_event"}},
                    {"term": {"event_type": "config_update"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": max_results,
    }

    return _execute_search(
        client=client,
        index=f"{index_prefix}-*",
        query=query,
        description=f"deployment events in last {hours}h",
    )


def query_infrastructure_changes(
    client: Elasticsearch,
    index_prefix: str = "infra-events",
    hours: int = 24,
    max_results: int = 200,
) -> list[dict[str, Any]]:
    """Query infrastructure change events (scaling, new instances, config updates).

    Args:
        client: Active Elasticsearch client.
        index_prefix: Index prefix for infrastructure event indices.
        hours: Look-back window in hours.
        max_results: Maximum number of events to return.

    Returns:
        List of infrastructure event documents.

    Raises:
        ElasticsearchException: On query failures.
    """
    since = _utcnow() - timedelta(hours=hours)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": since_iso,
                                "lte": "now",
                            }
                        }
                    },
                    {
                        "terms": {
                            "change_type": [
                                "auto_scaling",
                                "manual_scaling",
                                "instance_launch",
                                "instance_termination",
                                "config_change",
                                "ami_update",
                                "security_group_change",
                            ]
                        }
                    },
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": max_results,
    }

    return _execute_search(
        client=client,
        index=f"{index_prefix}-*",
        query=query,
        description=f"infrastructure changes in last {hours}h",
    )


def query_historical_costs(
    client: Elasticsearch,
    index_prefix: str = "aws-costs",
    days: int = 30,
    max_results: int = 30,
) -> list[dict[str, Any]]:
    """Query historical daily cost records from Elasticsearch.

    Returns daily cost documents ordered chronologically (oldest first) for
    use in rolling-average calculations.

    Args:
        client: Active Elasticsearch client.
        index_prefix: Index prefix for cost data indices.
        days: Number of days of history to retrieve.
        max_results: Maximum number of daily records to return.

    Returns:
        List of cost record documents ordered by date ascending.

    Raises:
        ElasticsearchException: On query failures.
    """
    since = _utcnow() - timedelta(days=days)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": since_iso,
                                "lte": "now",
                            }
                        }
                    }
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "asc"}}],
        "size": max_results,
    }

    return _execute_search(
        client=client,
        index=f"{index_prefix}-*",
        query=query,
        description=f"historical costs over last {days} days",
    )


def extract_cost_values(cost_documents: list[dict[str, Any]], cost_field: str = "total_cost_usd") -> list[float]:
    """Extract numeric cost values from Elasticsearch cost documents.

    Args:
        cost_documents: List of document ``_source`` dicts as returned by
                        :func:`query_historical_costs`.
        cost_field: Field name containing the cost amount.

    Returns:
        List of cost values as floats (documents missing the field are skipped).
    """
    costs: list[float] = []
    for doc in cost_documents:
        raw = doc.get(cost_field)
        if raw is None:
            logger.debug("Document missing field '%s', skipping", cost_field)
            continue
        try:
            costs.append(float(raw))
        except (TypeError, ValueError) as exc:
            logger.warning(
                "Cannot parse cost value '%s' from field '%s': %s",
                raw,
                cost_field,
                exc,
            )
    return costs


def _execute_search(
    client: Elasticsearch,
    index: str,
    query: dict[str, Any],
    description: str,
) -> list[dict[str, Any]]:
    """Execute an Elasticsearch search and return a list of source documents.

    Args:
        client: Active Elasticsearch client.
        index: Index name or wildcard pattern.
        query: Full Elasticsearch query body.
        description: Human-readable description for logging/error messages.

    Returns:
        List of ``_source`` dicts from matching hits.

    Raises:
        ElasticsearchException: On connection, timeout, or query errors.
    """
    logger.debug(
        "Executing Elasticsearch search",
        extra={"index": index, "description": description},
    )

    try:
        response = client.search(index=index, body=query)
        hits = response.get("hits", {}).get("hits", [])
        sources = [hit["_source"] for hit in hits if "_source" in hit]
        total = response.get("hits", {}).get("total", {})
        total_value = total.get("value", len(sources)) if isinstance(total, dict) else total

        logger.info(
            "Elasticsearch search complete",
            extra={
                "index": index,
                "description": description,
                "returned": len(sources),
                "total_matched": total_value,
            },
        )
        return sources

    except NotFoundError:
        logger.warning(
            "Elasticsearch index not found: '%s'. Returning empty result set.",
            index,
        )
        return []

    except ConnectionTimeout as exc:
        raise ElasticsearchException(
            f"Elasticsearch query timed out while fetching {description} from index '{index}'. "
            f"Consider increasing ES_REQUEST_TIMEOUT or optimizing the query. Detail: {exc}"
        ) from exc

    except ESConnectionError as exc:
        raise ElasticsearchException(
            f"Cannot connect to Elasticsearch while fetching {description}: {exc}. "
            "Verify ES_HOST, ES_PORT, and network access."
        ) from exc

    except AuthenticationException as exc:
        raise ElasticsearchException(
            f"Authentication failed for Elasticsearch query ({description}): {exc}. "
            "Verify credentials."
        ) from exc

    except RequestError as exc:
        raise ElasticsearchException(
            f"Invalid Elasticsearch query for {description}: {exc}. "
            "Check query syntax and field mappings."
        ) from exc

    except TransportError as exc:
        raise ElasticsearchException(
            f"Elasticsearch transport error for {description}: {exc}"
        ) from exc
