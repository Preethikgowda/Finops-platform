"""Tests for utilization_analyzer.py.

Covers:
- EC2 instance CPU < 20% detection
- RDS low CPU + connections detection
- Lambda oversized memory detection
- Network underutilisation detection
- DynamoDB caching behaviour
- Error handling and graceful degradation
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

import utilization_analyzer
from utilization_analyzer import (
    get_network_underutilization,
    get_oversized_lambda_functions,
    get_underutilized_ec2_instances,
    get_underutilized_rds_instances,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def running_ec2_instance():
    """A single running EC2 instance with no special tags."""
    return {
        "InstanceId": "i-0abc123456def",
        "InstanceType": "m5.xlarge",
        "LaunchTime": datetime.now(tz=timezone.utc) - timedelta(days=10),
        "Tags": [{"Key": "Name", "Value": "payment-service-prod"}],
    }


@pytest.fixture
def recently_launched_instance():
    """An EC2 instance launched less than 24 hours ago."""
    return {
        "InstanceId": "i-new999",
        "InstanceType": "t3.large",
        "LaunchTime": datetime.now(tz=timezone.utc) - timedelta(hours=2),
        "Tags": [],
    }


@pytest.fixture
def scheduled_scaling_instance():
    """An EC2 instance tagged with ScheduledScaling=true."""
    return {
        "InstanceId": "i-scheduled",
        "InstanceType": "c5.xlarge",
        "LaunchTime": datetime.now(tz=timezone.utc) - timedelta(days=30),
        "Tags": [{"Key": "ScheduledScaling", "Value": "true"}],
    }


@pytest.fixture
def mock_ec2_paginator(running_ec2_instance):
    """Mock EC2 paginator returning one instance."""
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"Reservations": [{"Instances": [running_ec2_instance]}]}
    ]
    return paginator


@pytest.fixture
def low_cpu_datapoint():
    """CloudWatch datapoint with 10% CPU average."""
    return {"Average": 10.0, "Timestamp": datetime.now(tz=timezone.utc)}


@pytest.fixture
def high_cpu_datapoint():
    """CloudWatch datapoint with 80% CPU average."""
    return {"Average": 80.0, "Timestamp": datetime.now(tz=timezone.utc)}


# ---------------------------------------------------------------------------
# EC2 tests
# ---------------------------------------------------------------------------

class TestGetUnderutilizedEc2Instances:
    def test_low_cpu_instance_flagged(self, running_ec2_instance, low_cpu_datapoint):
        """Instances with avg CPU < 20% should be included in results."""
        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._ec2_client") as mock_ec2, \
             patch("utilization_analyzer._cloudwatch_client") as mock_cw:

            ec2_instance = mock_ec2.return_value
            ec2_instance.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [running_ec2_instance]}]}
            ]

            cw_instance = mock_cw.return_value
            cw_instance.get_metric_statistics.return_value = {
                "Datapoints": [low_cpu_datapoint]
            }

            results = get_underutilized_ec2_instances(region="ap-south-1")

        assert len(results) == 1
        assert results[0]["instance_id"] == "i-0abc123456def"
        assert results[0]["avg_cpu"] == 10.0
        assert results[0]["current_type"] == "m5.xlarge"

    def test_high_cpu_instance_excluded(self, running_ec2_instance, high_cpu_datapoint):
        """Instances above the CPU threshold should not appear in results."""
        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._ec2_client") as mock_ec2, \
             patch("utilization_analyzer._cloudwatch_client") as mock_cw:

            ec2_instance = mock_ec2.return_value
            ec2_instance.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [running_ec2_instance]}]}
            ]

            cw_instance = mock_cw.return_value
            cw_instance.get_metric_statistics.return_value = {
                "Datapoints": [high_cpu_datapoint]
            }

            results = get_underutilized_ec2_instances(region="ap-south-1")

        assert len(results) == 0

    def test_recently_launched_instance_skipped(
        self, recently_launched_instance, low_cpu_datapoint
    ):
        """Instances launched less than 24 hours ago should be skipped."""
        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._ec2_client") as mock_ec2, \
             patch("utilization_analyzer._cloudwatch_client"):

            ec2_instance = mock_ec2.return_value
            ec2_instance.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [recently_launched_instance]}]}
            ]

            results = get_underutilized_ec2_instances(region="ap-south-1")

        assert len(results) == 0

    def test_scheduled_scaling_instance_skipped(
        self, scheduled_scaling_instance, low_cpu_datapoint
    ):
        """Instances tagged ScheduledScaling=true should be skipped."""
        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._ec2_client") as mock_ec2, \
             patch("utilization_analyzer._cloudwatch_client"):

            ec2_instance = mock_ec2.return_value
            ec2_instance.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [scheduled_scaling_instance]}]}
            ]

            results = get_underutilized_ec2_instances(region="ap-south-1")

        assert len(results) == 0

    def test_no_cloudwatch_data_skipped(self, running_ec2_instance):
        """Instances with no CloudWatch metrics should be gracefully skipped."""
        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._ec2_client") as mock_ec2, \
             patch("utilization_analyzer._cloudwatch_client") as mock_cw:

            mock_ec2.return_value.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [running_ec2_instance]}]}
            ]
            mock_cw.return_value.get_metric_statistics.return_value = {"Datapoints": []}

            results = get_underutilized_ec2_instances(region="ap-south-1")

        assert results == []

    def test_cache_hit_returns_cached_data(self):
        """Should return cached data without making AWS API calls."""
        cached = [{"instance_id": "i-cached", "avg_cpu": 5.0}]
        with patch("utilization_analyzer._get_cache", return_value=cached), \
             patch("utilization_analyzer._ec2_client") as mock_ec2:

            results = get_underutilized_ec2_instances(region="ap-south-1")

        mock_ec2.assert_not_called()
        assert results == cached

    def test_api_error_returns_empty_list(self):
        """ClientError from EC2 API should result in empty list (non-fatal)."""
        from botocore.exceptions import ClientError

        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._ec2_client") as mock_ec2:

            mock_ec2.return_value.get_paginator.side_effect = ClientError(
                {"Error": {"Code": "UnauthorizedAccess", "Message": "Denied"}}, "DescribeInstances"
            )

            results = get_underutilized_ec2_instances(region="ap-south-1")

        assert results == []

    def test_recommended_type_populated(self, running_ec2_instance, low_cpu_datapoint):
        """Should include recommended_type from the downsize map."""
        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._ec2_client") as mock_ec2, \
             patch("utilization_analyzer._cloudwatch_client") as mock_cw:

            mock_ec2.return_value.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [running_ec2_instance]}]}
            ]
            mock_cw.return_value.get_metric_statistics.return_value = {
                "Datapoints": [low_cpu_datapoint]
            }

            results = get_underutilized_ec2_instances(region="ap-south-1")

        assert results[0]["recommended_type"] == utilization_analyzer._EC2_DOWNSIZE_MAP["m5.xlarge"]
        assert results[0]["estimated_savings"] > 0


# ---------------------------------------------------------------------------
# RDS tests
# ---------------------------------------------------------------------------

class TestGetUnderutilizedRdsInstances:
    @pytest.fixture
    def available_db_instance(self):
        return {
            "DBInstanceIdentifier": "mydb-prod",
            "DBInstanceClass": "db.m5.xlarge",
            "DBInstanceStatus": "available",
            "Engine": "mysql",
            "MultiAZ": False,
        }

    def test_low_cpu_low_connections_flagged(self, available_db_instance):
        """RDS instances with low CPU and few connections are flagged."""
        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._rds_client") as mock_rds, \
             patch("utilization_analyzer._cloudwatch_client") as mock_cw:

            mock_rds.return_value.get_paginator.return_value.paginate.return_value = [
                {"DBInstances": [available_db_instance]}
            ]
            # First call = CPUUtilization (5%), second call = DatabaseConnections (2)
            mock_cw.return_value.get_metric_statistics.side_effect = [
                {"Datapoints": [{"Average": 5.0}]},   # CPUUtilization — below 20%
                {"Datapoints": [{"Average": 2.0}]},   # DatabaseConnections — below 5
            ]

            results = get_underutilized_rds_instances(region="ap-south-1")

        assert len(results) == 1
        assert results[0]["instance_id"] == "mydb-prod"
        assert results[0]["avg_cpu"] == 5.0

    def test_high_connections_excluded(self, available_db_instance):
        """RDS instances with many connections should not be flagged."""
        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._rds_client") as mock_rds, \
             patch("utilization_analyzer._cloudwatch_client") as mock_cw:

            mock_rds.return_value.get_paginator.return_value.paginate.return_value = [
                {"DBInstances": [available_db_instance]}
            ]
            # First call returns low CPU, second returns high connections
            mock_cw.return_value.get_metric_statistics.side_effect = [
                {"Datapoints": [{"Average": 5.0}]},  # CPUUtilization
                {"Datapoints": [{"Average": 50.0}]},  # DatabaseConnections (above threshold)
            ]

            results = get_underutilized_rds_instances(region="ap-south-1")

        assert len(results) == 0

    def test_unavailable_instance_skipped(self):
        """RDS instances not in 'available' state are skipped."""
        stopped_db = {
            "DBInstanceIdentifier": "stopped-db",
            "DBInstanceClass": "db.t3.medium",
            "DBInstanceStatus": "stopped",
            "Engine": "postgres",
            "MultiAZ": False,
        }
        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._rds_client") as mock_rds, \
             patch("utilization_analyzer._cloudwatch_client"):

            mock_rds.return_value.get_paginator.return_value.paginate.return_value = [
                {"DBInstances": [stopped_db]}
            ]

            results = get_underutilized_rds_instances(region="ap-south-1")

        assert results == []

    def test_cache_hit_returns_cached_data(self):
        cached = [{"instance_id": "cached-db", "avg_cpu": 3.0}]
        with patch("utilization_analyzer._get_cache", return_value=cached), \
             patch("utilization_analyzer._rds_client") as mock_rds:

            results = get_underutilized_rds_instances(region="ap-south-1")

        mock_rds.assert_not_called()
        assert results == cached


# ---------------------------------------------------------------------------
# Lambda tests
# ---------------------------------------------------------------------------

class TestGetOversizedLambdaFunctions:
    def test_oversized_function_flagged(self):
        """Lambda functions with low p95 duration relative to memory are flagged."""
        fn = {
            "FunctionName": "process-orders",
            "FunctionArn": "arn:aws:lambda:ap-south-1:123:function:process-orders",
            "MemorySize": 1024,
            "Runtime": "python3.11",
        }

        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._lambda_client") as mock_lam, \
             patch("utilization_analyzer._cloudwatch_client") as mock_cw:

            mock_lam.return_value.get_paginator.return_value.paginate.return_value = [
                {"Functions": [fn]}
            ]
            mock_cw.return_value.get_metric_statistics.return_value = {
                "Datapoints": [
                    {
                        "Maximum": 200.0,
                        "ExtendedStatistics": {"p95": 150.0},
                        "Timestamp": datetime.now(tz=timezone.utc),
                    }
                ]
            }

            results = get_oversized_lambda_functions(region="ap-south-1")

        assert len(results) == 1
        assert results[0]["function_name"] == "process-orders"
        assert results[0]["allocated_memory"] == 1024
        assert results[0]["recommended_memory"] < 1024

    def test_no_metrics_skipped(self):
        """Functions with no CloudWatch data are gracefully skipped."""
        fn = {
            "FunctionName": "idle-fn",
            "FunctionArn": "arn:aws:lambda:ap-south-1:123:function:idle-fn",
            "MemorySize": 512,
            "Runtime": "python3.11",
        }

        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._lambda_client") as mock_lam, \
             patch("utilization_analyzer._cloudwatch_client") as mock_cw:

            mock_lam.return_value.get_paginator.return_value.paginate.return_value = [
                {"Functions": [fn]}
            ]
            mock_cw.return_value.get_metric_statistics.return_value = {"Datapoints": []}

            results = get_oversized_lambda_functions(region="ap-south-1")

        assert results == []


# ---------------------------------------------------------------------------
# Network underutilisation tests
# ---------------------------------------------------------------------------

class TestGetNetworkUnderutilization:
    def test_low_network_instance_flagged(self, running_ec2_instance):
        """Instances with low network traffic (<1 GB/day) should be flagged."""
        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._ec2_client") as mock_ec2, \
             patch("utilization_analyzer._cloudwatch_client") as mock_cw:

            mock_ec2.return_value.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [running_ec2_instance]}]}
            ]
            # 10 MB/day total — below 1 GB threshold
            mock_cw.return_value.get_metric_statistics.return_value = {
                "Datapoints": [{"Average": 5_000_000.0}]
            }

            results = get_network_underutilization(region="ap-south-1")

        assert len(results) == 1
        assert results[0]["instance_id"] == "i-0abc123456def"
        assert results[0]["total_daily_bytes"] < 1_073_741_824  # < 1 GB

    def test_high_network_instance_excluded(self, running_ec2_instance):
        """Instances with high network traffic should not be flagged."""
        with patch("utilization_analyzer._get_cache", return_value=None), \
             patch("utilization_analyzer._set_cache"), \
             patch("utilization_analyzer._ec2_client") as mock_ec2, \
             patch("utilization_analyzer._cloudwatch_client") as mock_cw:

            mock_ec2.return_value.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [running_ec2_instance]}]}
            ]
            # 1 GB each direction = 2 GB total — above threshold
            mock_cw.return_value.get_metric_statistics.return_value = {
                "Datapoints": [{"Average": 1_073_741_824.0}]
            }

            results = get_network_underutilization(region="ap-south-1")

        assert results == []
