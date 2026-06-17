"""Unit tests for cloudtrail_client.py."""

import sys
import os
from unittest.mock import MagicMock, patch, call
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cloudtrail_client import (
    AthenaQueryTimeout,
    CloudTrailException,
    _run_athena_query,
    format_changes_for_prompt,
    get_autoscaling_changes,
    get_ec2_launches_last_24h,
    get_iam_changes,
    get_rds_changes,
    get_resource_changes_summary,
)


def _make_athena_client(state: str = "SUCCEEDED", rows: list | None = None) -> MagicMock:
    """Build a mock Athena client that returns ``state`` as the query status."""
    if rows is None:
        rows = [
            {"Data": [{"VarCharValue": "eventtime"}, {"VarCharValue": "useridentity_arn"}]},
            {"Data": [{"VarCharValue": "2024-01-15T10:00:00Z"}, {"VarCharValue": "arn:aws:iam::123:user/bot"}]},
        ]

    client = MagicMock()
    client.start_query_execution.return_value = {"QueryExecutionId": "exec-001"}
    client.get_query_execution.return_value = {
        "QueryExecution": {"Status": {"State": state, "StateChangeReason": "ok"}}
    }
    client.get_query_results.return_value = {
        "ResultSet": {"Rows": rows}
    }
    return client


class TestRunAthenaQuery:
    """Tests for _run_athena_query()."""

    def test_returns_rows_on_success(self):
        mock_client = _make_athena_client()
        with patch("cloudtrail_client.time.sleep"):
            results = _run_athena_query(
                athena_client=mock_client,
                query="SELECT * FROM cloudtrail",
                database="cloudtrail_logs",
                results_bucket="s3://my-results",
            )

        assert len(results) == 1
        assert results[0]["eventtime"] == "2024-01-15T10:00:00Z"
        assert results[0]["useridentity_arn"] == "arn:aws:iam::123:user/bot"

    def test_raises_on_failed_query(self):
        mock_client = _make_athena_client(state="FAILED")
        with patch("cloudtrail_client.time.sleep"):
            with pytest.raises(CloudTrailException, match="FAILED"):
                _run_athena_query(
                    athena_client=mock_client,
                    query="SELECT * FROM cloudtrail",
                    database="cloudtrail_logs",
                    results_bucket="s3://my-results",
                )

    def test_raises_on_cancelled_query(self):
        mock_client = _make_athena_client(state="CANCELLED")
        with patch("cloudtrail_client.time.sleep"):
            with pytest.raises(CloudTrailException, match="CANCELLED"):
                _run_athena_query(
                    athena_client=mock_client,
                    query="SELECT * FROM cloudtrail",
                    database="cloudtrail_logs",
                    results_bucket="s3://my-results",
                )

    def test_raises_timeout_when_query_stuck_running(self):
        mock_client = _make_athena_client(state="RUNNING")
        with patch("cloudtrail_client.time.sleep"):
            with pytest.raises(AthenaQueryTimeout):
                _run_athena_query(
                    athena_client=mock_client,
                    query="SELECT * FROM cloudtrail",
                    database="cloudtrail_logs",
                    results_bucket="s3://my-results",
                    max_wait_s=0.01,  # instant timeout for test
                )

    def test_returns_empty_list_on_no_rows(self):
        mock_client = _make_athena_client(rows=[])
        with patch("cloudtrail_client.time.sleep"):
            results = _run_athena_query(
                athena_client=mock_client,
                query="SELECT * FROM cloudtrail",
                database="cloudtrail_logs",
                results_bucket="s3://my-results",
            )

        assert results == []

    def test_raises_on_start_query_failure(self):
        from botocore.exceptions import ClientError
        error_resp = {"Error": {"Code": "InvalidRequestException", "Message": "Bad SQL"}}
        mock_client = MagicMock()
        mock_client.start_query_execution.side_effect = ClientError(error_resp, "StartQuery")

        with pytest.raises(CloudTrailException, match="Failed to start Athena query"):
            _run_athena_query(
                athena_client=mock_client,
                query="INVALID SQL",
                database="cloudtrail_logs",
                results_bucket="s3://my-results",
            )


class TestGetEc2Launches:
    """Tests for get_ec2_launches_last_24h()."""

    def test_returns_events_on_success(self):
        mock_athena = _make_athena_client()
        with patch("cloudtrail_client._build_athena_client", return_value=mock_athena):
            with patch("cloudtrail_client.time.sleep"):
                results = get_ec2_launches_last_24h(
                    region="ap-south-1",
                    cloudtrail_database="cloudtrail_logs",
                    cloudtrail_table="cloudtrail",
                    results_bucket="s3://my-results",
                )

        assert len(results) == 1
        assert results[0]["eventtime"] == "2024-01-15T10:00:00Z"

    def test_returns_empty_list_on_exception(self):
        with patch("cloudtrail_client._build_athena_client") as mock_builder:
            mock_builder.side_effect = Exception("Connection error")
            results = get_ec2_launches_last_24h(
                region="ap-south-1",
                cloudtrail_database="cloudtrail_logs",
                cloudtrail_table="cloudtrail",
                results_bucket="s3://my-results",
            )

        assert results == []


class TestGetAutoscalingChanges:
    """Tests for get_autoscaling_changes()."""

    def test_returns_events_on_success(self):
        asg_rows = [
            {"Data": [{"VarCharValue": "eventtime"}, {"VarCharValue": "eventname"}]},
            {"Data": [{"VarCharValue": "2024-01-15T11:00:00Z"}, {"VarCharValue": "SetDesiredCapacity"}]},
        ]
        mock_athena = _make_athena_client(rows=asg_rows)
        with patch("cloudtrail_client._build_athena_client", return_value=mock_athena):
            with patch("cloudtrail_client.time.sleep"):
                results = get_autoscaling_changes(
                    region="ap-south-1",
                    cloudtrail_database="cloudtrail_logs",
                    cloudtrail_table="cloudtrail",
                    results_bucket="s3://my-results",
                )

        assert len(results) == 1
        assert results[0]["eventname"] == "SetDesiredCapacity"

    def test_returns_empty_list_on_failure(self):
        with patch("cloudtrail_client._build_athena_client", side_effect=Exception("error")):
            results = get_autoscaling_changes(
                region="ap-south-1",
                cloudtrail_database="cloudtrail_logs",
                cloudtrail_table="cloudtrail",
                results_bucket="s3://my-results",
            )
        assert results == []


class TestGetRdsChanges:
    """Tests for get_rds_changes()."""

    def test_returns_empty_when_no_rds_changes(self):
        mock_athena = _make_athena_client(rows=[])
        with patch("cloudtrail_client._build_athena_client", return_value=mock_athena):
            with patch("cloudtrail_client.time.sleep"):
                results = get_rds_changes(
                    region="ap-south-1",
                    cloudtrail_database="cloudtrail_logs",
                    cloudtrail_table="cloudtrail",
                    results_bucket="s3://my-results",
                )
        assert results == []


class TestGetIamChanges:
    """Tests for get_iam_changes()."""

    def test_returns_iam_events(self):
        iam_rows = [
            {"Data": [{"VarCharValue": "eventtime"}, {"VarCharValue": "eventname"}, {"VarCharValue": "useridentity_arn"}]},
            {"Data": [{"VarCharValue": "2024-01-15T09:00:00Z"}, {"VarCharValue": "CreateRole"}, {"VarCharValue": "arn:aws:iam::123:user/admin"}]},
        ]
        mock_athena = _make_athena_client(rows=iam_rows)
        with patch("cloudtrail_client._build_athena_client", return_value=mock_athena):
            with patch("cloudtrail_client.time.sleep"):
                results = get_iam_changes(
                    region="ap-south-1",
                    cloudtrail_database="cloudtrail_logs",
                    cloudtrail_table="cloudtrail",
                    results_bucket="s3://my-results",
                )

        assert len(results) == 1
        assert results[0]["eventname"] == "CreateRole"


class TestGetResourceChangesSummary:
    """Tests for get_resource_changes_summary()."""

    def test_consolidates_all_change_types(self):
        ec2_events = [{"eventtime": "2024-01-15T10:00:00Z"}]
        asg_events = [{"eventtime": "2024-01-15T11:00:00Z", "eventname": "SetDesiredCapacity"}]

        with patch("cloudtrail_client.get_ec2_launches_last_24h", return_value=ec2_events):
            with patch("cloudtrail_client.get_autoscaling_changes", return_value=asg_events):
                with patch("cloudtrail_client.get_rds_changes", return_value=[]):
                    with patch("cloudtrail_client.get_iam_changes", return_value=[]):
                        summary = get_resource_changes_summary(
                            region="ap-south-1",
                            cloudtrail_database="cloudtrail_logs",
                            cloudtrail_table="cloudtrail",
                            results_bucket="s3://my-results",
                        )

        assert summary["total_events"] == 2
        assert len(summary["ec2_launches"]) == 1
        assert len(summary["autoscaling_changes"]) == 1
        assert summary["rds_changes"] == []
        assert summary["iam_changes"] == []

    def test_total_events_is_sum_of_all_categories(self):
        with patch("cloudtrail_client.get_ec2_launches_last_24h", return_value=[{}, {}]):
            with patch("cloudtrail_client.get_autoscaling_changes", return_value=[{}]):
                with patch("cloudtrail_client.get_rds_changes", return_value=[{}]):
                    with patch("cloudtrail_client.get_iam_changes", return_value=[]):
                        summary = get_resource_changes_summary(
                            region="ap-south-1",
                            cloudtrail_database="cloudtrail_logs",
                            cloudtrail_table="cloudtrail",
                            results_bucket="s3://my-results",
                        )

        assert summary["total_events"] == 4


class TestFormatChangesForPrompt:
    """Tests for format_changes_for_prompt()."""

    def test_includes_header(self):
        summary = {
            "ec2_launches": [],
            "autoscaling_changes": [],
            "rds_changes": [],
            "iam_changes": [],
            "total_events": 0,
            "query_window_hours": 24,
        }
        text = format_changes_for_prompt(summary)
        assert "CloudTrail Resource Changes" in text

    def test_shows_ec2_launch_events(self):
        summary = {
            "ec2_launches": [
                {"eventtime": "2024-01-15T10:00:00Z", "useridentity_arn": "arn:aws:iam::123:user/bot", "requestparameters": "m5.xlarge"}
            ],
            "autoscaling_changes": [],
            "rds_changes": [],
            "iam_changes": [],
            "total_events": 1,
            "query_window_hours": 24,
        }
        text = format_changes_for_prompt(summary)
        assert "EC2 Launches" in text
        assert "2024-01-15T10:00:00Z" in text

    def test_shows_none_detected_for_empty_categories(self):
        summary = {
            "ec2_launches": [],
            "autoscaling_changes": [],
            "rds_changes": [],
            "iam_changes": [],
            "total_events": 0,
            "query_window_hours": 24,
        }
        text = format_changes_for_prompt(summary)
        assert "None detected" in text
