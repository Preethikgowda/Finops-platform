"""Unit tests for dynamodb_store.py."""

import sys
import os
import json
from decimal import Decimal
from unittest.mock import MagicMock, patch, call
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from dynamodb_store import (
    DynamoDBException,
    _deserialize_decimals,
    _serialize_floats,
    cache_cloudtrail_results,
    check_idempotency,
    get_baseline_costs,
    get_cached_cloudtrail_results,
    get_item,
    put_item,
    query_range,
    record_idempotency,
    store_anomaly_result,
    store_cost_baseline,
)


def _make_mock_table(get_item_return: dict | None = None) -> MagicMock:
    table = MagicMock()
    table.get_item.return_value = get_item_return or {}
    table.put_item.return_value = {}
    table.query.return_value = {"Items": []}
    return table


def _make_mock_resource(table: MagicMock | None = None) -> MagicMock:
    resource = MagicMock()
    resource.Table.return_value = table or _make_mock_table()
    return resource


class TestPutItem:
    """Tests for put_item()."""

    def test_writes_item_with_correct_keys(self):
        mock_table = _make_mock_table()
        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            put_item(
                table_name="finops-cost-baselines",
                execution_date="2024-01-15",
                metric_type="baseline",
                data={"cost_usd": 123.45},
                region="ap-south-1",
            )

        mock_table.put_item.assert_called_once()
        item = mock_table.put_item.call_args[1]["Item"]
        assert item["execution_date"] == "2024-01-15"
        assert item["metric_type"] == "baseline"

    def test_includes_ttl_when_provided(self):
        mock_table = _make_mock_table()
        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            with patch("dynamodb_store._now_epoch", return_value=1000):
                put_item(
                    table_name="finops-cost-baselines",
                    execution_date="2024-01-15",
                    metric_type="baseline",
                    data={},
                    region="ap-south-1",
                    ttl_seconds=3600,
                )

        item = mock_table.put_item.call_args[1]["Item"]
        assert item["expiration_time"] == 4600

    def test_raises_on_dynamodb_error(self):
        from botocore.exceptions import ClientError
        error_resp = {"Error": {"Code": "ResourceNotFoundException", "Message": "Table not found"}}
        mock_table = _make_mock_table()
        mock_table.put_item.side_effect = ClientError(error_resp, "PutItem")

        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            with pytest.raises(DynamoDBException, match="Failed to write item"):
                put_item(
                    table_name="missing-table",
                    execution_date="2024-01-15",
                    metric_type="baseline",
                    data={},
                    region="ap-south-1",
                )

    def test_floats_serialized_to_decimal(self):
        mock_table = _make_mock_table()
        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            put_item(
                table_name="finops-cost-baselines",
                execution_date="2024-01-15",
                metric_type="baseline",
                data={"cost_usd": 123.45},
                region="ap-south-1",
            )

        item = mock_table.put_item.call_args[1]["Item"]
        assert isinstance(item["cost_usd"], Decimal)


class TestGetItem:
    """Tests for get_item()."""

    def test_returns_item_when_found(self):
        mock_item = {"execution_date": "2024-01-15", "metric_type": "baseline", "cost_usd": Decimal("123.45")}
        mock_table = _make_mock_table({"Item": mock_item})

        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            result = get_item("finops-cost-baselines", "2024-01-15", "baseline", "ap-south-1")

        assert result is not None
        assert result["execution_date"] == "2024-01-15"
        assert isinstance(result["cost_usd"], float)

    def test_returns_none_when_not_found(self):
        mock_table = _make_mock_table({})

        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            result = get_item("finops-cost-baselines", "2024-01-15", "baseline", "ap-south-1")

        assert result is None

    def test_raises_on_dynamodb_error(self):
        from botocore.exceptions import BotoCoreError
        mock_table = _make_mock_table()
        mock_table.get_item.side_effect = BotoCoreError()

        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            with pytest.raises(DynamoDBException, match="Failed to get item"):
                get_item("finops-cost-baselines", "2024-01-15", "baseline", "ap-south-1")


class TestStoreCostBaseline:
    """Tests for store_cost_baseline()."""

    def test_stores_baseline_with_correct_data(self):
        mock_table = _make_mock_table()
        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            store_cost_baseline(
                table_name="finops-cost-baselines",
                execution_date="2024-01-15",
                cost_usd=500.0,
                region="ap-south-1",
            )

        mock_table.put_item.assert_called_once()
        item = mock_table.put_item.call_args[1]["Item"]
        assert item["execution_date"] == "2024-01-15"
        assert item["metric_type"] == "baseline"


class TestGetBaselineCosts:
    """Tests for get_baseline_costs()."""

    def test_returns_costs_sorted_by_date(self):
        items = [
            {"execution_date": "2024-01-14", "metric_type": "baseline", "cost_usd": Decimal("100.0")},
            {"execution_date": "2024-01-15", "metric_type": "baseline", "cost_usd": Decimal("120.0")},
        ]
        mock_table = _make_mock_table()
        mock_table.query.return_value = {"Items": items}

        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            costs = get_baseline_costs(
                table_name="finops-cost-baselines",
                start_date="2024-01-08",
                end_date="2024-01-15",
                region="ap-south-1",
            )

        assert costs == pytest.approx([100.0, 120.0])

    def test_returns_empty_list_on_exception(self):
        with patch("dynamodb_store.query_range", side_effect=DynamoDBException("error")):
            costs = get_baseline_costs(
                table_name="finops-cost-baselines",
                start_date="2024-01-08",
                end_date="2024-01-15",
                region="ap-south-1",
            )
        assert costs == []


class TestCheckIdempotency:
    """Tests for check_idempotency()."""

    def test_returns_true_when_record_exists(self):
        mock_item = {"execution_date": "2024-01-15", "metric_type": "idempotency"}
        mock_table = _make_mock_table({"Item": mock_item})

        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            result = check_idempotency("finops-cost-baselines", "2024-01-15", "ap-south-1")

        assert result is True

    def test_returns_false_when_no_record(self):
        mock_table = _make_mock_table({})

        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            result = check_idempotency("finops-cost-baselines", "2024-01-15", "ap-south-1")

        assert result is False

    def test_returns_false_on_exception(self):
        with patch("dynamodb_store.get_item", side_effect=DynamoDBException("error")):
            result = check_idempotency("finops-cost-baselines", "2024-01-15", "ap-south-1")

        assert result is False


class TestRecordIdempotency:
    """Tests for record_idempotency()."""

    def test_writes_idempotency_record(self):
        mock_table = _make_mock_table()
        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            record_idempotency(
                table_name="finops-cost-baselines",
                execution_date="2024-01-15",
                analysis_id="abc123",
                result_summary={"anomaly_detected": True},
                region="ap-south-1",
            )

        mock_table.put_item.assert_called_once()
        item = mock_table.put_item.call_args[1]["Item"]
        assert item["metric_type"] == "idempotency"
        assert item["analysis_id"] == "abc123"

    def test_tolerates_exception(self):
        with patch("dynamodb_store.put_item", side_effect=DynamoDBException("error")):
            # Should not raise
            record_idempotency(
                table_name="finops-cost-baselines",
                execution_date="2024-01-15",
                analysis_id="abc123",
                result_summary={},
                region="ap-south-1",
            )


class TestCacheCloudTrailResults:
    """Tests for cache_cloudtrail_results() and get_cached_cloudtrail_results()."""

    def test_cache_and_retrieve(self):
        results = {"ec2_launches": [{"eventtime": "2024-01-15"}], "total_events": 1}
        cached_json = json.dumps(results)

        mock_table = _make_mock_table({
            "Item": {
                "execution_date": "2024-01-15_cloudtrail",
                "metric_type": "cloudtrail_cache",
                "results_json": cached_json,
                "expiration_time": Decimal("9999999999"),
            }
        })

        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            retrieved = get_cached_cloudtrail_results(
                table_name="finops-cost-baselines",
                cache_key="2024-01-15_cloudtrail",
                region="ap-south-1",
            )

        assert retrieved is not None
        assert retrieved["total_events"] == 1

    def test_returns_none_for_expired_cache(self):
        cached_json = json.dumps({"total_events": 1})
        mock_table = _make_mock_table({
            "Item": {
                "execution_date": "2024-01-15",
                "metric_type": "cloudtrail_cache",
                "results_json": cached_json,
                "expiration_time": Decimal("1"),  # expired
            }
        })

        with patch("dynamodb_store._build_dynamodb_resource", return_value=_make_mock_resource(mock_table)):
            with patch("dynamodb_store._now_epoch", return_value=9999):
                retrieved = get_cached_cloudtrail_results(
                    table_name="finops-cost-baselines",
                    cache_key="2024-01-15",
                    region="ap-south-1",
                )

        assert retrieved is None


class TestSerializationHelpers:
    """Tests for _serialize_floats and _deserialize_decimals."""

    def test_float_converted_to_decimal(self):
        result = _serialize_floats({"amount": 123.45})
        assert isinstance(result["amount"], Decimal)

    def test_nested_floats_converted(self):
        result = _serialize_floats({"nested": {"value": 1.5}})
        assert isinstance(result["nested"]["value"], Decimal)

    def test_list_floats_converted(self):
        result = _serialize_floats([1.0, 2.0])
        assert all(isinstance(v, Decimal) for v in result)

    def test_decimal_converted_to_float(self):
        result = _deserialize_decimals({"amount": Decimal("123.45")})
        assert isinstance(result["amount"], float)
        assert result["amount"] == pytest.approx(123.45)

    def test_non_float_types_unchanged(self):
        result = _serialize_floats({"name": "test", "count": 5})
        assert result["name"] == "test"
        assert result["count"] == 5
