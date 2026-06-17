"""Tests for s3_lifecycle_optimizer.py.

Covers:
- S3 access pattern analysis
- Lifecycle policy existence check
- Terraform HCL generation for S3 lifecycle
- CloudTrail fallback for activity detection
- Caching behaviour
- Error handling
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from s3_lifecycle_optimizer import (
    analyze_s3_access_patterns,
    check_lifecycle_policy_exists,
    generate_s3_lifecycle_policy_terraform,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_bucket():
    return {"Name": "my-company-logs", "CreationDate": datetime(2023, 1, 1, tzinfo=timezone.utc)}


@pytest.fixture
def large_cw_metrics():
    """CloudWatch metrics showing 100 GB of storage."""
    def _get_metric_statistics(**kwargs):
        if "BucketSizeBytes" in str(kwargs):
            return {"Datapoints": [{"Average": 100 * (1024 ** 3)}]}
        return {"Datapoints": [{"Average": 1000}]}
    return _get_metric_statistics


# ---------------------------------------------------------------------------
# check_lifecycle_policy_exists
# ---------------------------------------------------------------------------

class TestCheckLifecyclePolicyExists:
    def test_bucket_without_lifecycle_flagged(self, sample_bucket):
        with patch("s3_lifecycle_optimizer._get_cache", return_value=None), \
             patch("s3_lifecycle_optimizer._set_cache"), \
             patch("s3_lifecycle_optimizer._s3_client") as mock_s3:

            s3 = mock_s3.return_value
            s3.list_buckets.return_value = {"Buckets": [sample_bucket]}
            s3.get_bucket_lifecycle_configuration.side_effect = ClientError(
                {"Error": {"Code": "NoSuchLifecycleConfiguration", "Message": "None"}},
                "GetBucketLifecycleConfiguration",
            )

            results = check_lifecycle_policy_exists(region="ap-south-1")

        assert len(results) == 1
        assert results[0]["bucket_name"] == "my-company-logs"
        assert "lifecycle" in results[0]["recommendation"].lower()

    def test_bucket_with_lifecycle_not_flagged(self, sample_bucket):
        with patch("s3_lifecycle_optimizer._get_cache", return_value=None), \
             patch("s3_lifecycle_optimizer._set_cache"), \
             patch("s3_lifecycle_optimizer._s3_client") as mock_s3:

            s3 = mock_s3.return_value
            s3.list_buckets.return_value = {"Buckets": [sample_bucket]}
            s3.get_bucket_lifecycle_configuration.return_value = {
                "Rules": [{"ID": "existing-rule", "Status": "Enabled"}]
            }

            results = check_lifecycle_policy_exists(region="ap-south-1")

        assert results == []

    def test_cache_hit_avoids_api_calls(self):
        cached = [{"bucket_name": "cached-bucket"}]
        with patch("s3_lifecycle_optimizer._get_cache", return_value=cached), \
             patch("s3_lifecycle_optimizer._s3_client") as mock_s3:

            results = check_lifecycle_policy_exists(region="ap-south-1")

        mock_s3.assert_not_called()
        assert results == cached

    def test_multiple_buckets_only_unprotected_returned(self):
        buckets = [
            {"Name": "bucket-with-policy", "CreationDate": datetime(2023, 1, 1, tzinfo=timezone.utc)},
            {"Name": "bucket-without-policy", "CreationDate": datetime(2023, 1, 1, tzinfo=timezone.utc)},
        ]
        with patch("s3_lifecycle_optimizer._get_cache", return_value=None), \
             patch("s3_lifecycle_optimizer._set_cache"), \
             patch("s3_lifecycle_optimizer._s3_client") as mock_s3:

            s3 = mock_s3.return_value
            s3.list_buckets.return_value = {"Buckets": buckets}

            def lifecycle_side_effect(Bucket):
                if Bucket == "bucket-with-policy":
                    return {"Rules": []}
                raise ClientError(
                    {"Error": {"Code": "NoSuchLifecycleConfiguration", "Message": "None"}},
                    "GetBucketLifecycleConfiguration",
                )

            s3.get_bucket_lifecycle_configuration.side_effect = lifecycle_side_effect

            results = check_lifecycle_policy_exists(region="ap-south-1")

        assert len(results) == 1
        assert results[0]["bucket_name"] == "bucket-without-policy"

    def test_api_failure_returns_empty(self):
        with patch("s3_lifecycle_optimizer._get_cache", return_value=None), \
             patch("s3_lifecycle_optimizer._s3_client") as mock_s3:

            mock_s3.return_value.list_buckets.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "D"}}, "ListBuckets"
            )

            results = check_lifecycle_policy_exists(region="ap-south-1")

        assert results == []


# ---------------------------------------------------------------------------
# analyze_s3_access_patterns
# ---------------------------------------------------------------------------

class TestAnalyzeS3AccessPatterns:
    def test_inactive_bucket_with_large_storage_flagged(self, sample_bucket):
        with patch("s3_lifecycle_optimizer._get_cache", return_value=None), \
             patch("s3_lifecycle_optimizer._set_cache"), \
             patch("s3_lifecycle_optimizer._s3_client") as mock_s3, \
             patch("boto3.client") as mock_boto_cw, \
             patch("s3_lifecycle_optimizer._estimate_inactive_objects_via_cloudtrail", return_value=-1):

            s3 = mock_s3.return_value
            s3.list_buckets.return_value = {"Buckets": [sample_bucket]}
            s3.list_bucket_inventory_configurations.side_effect = ClientError(
                {"Error": {"Code": "NoSuchBucket", "Message": ""}}, "ListBucketInventory"
            )

            cw = MagicMock()
            cw.get_metric_statistics.side_effect = [
                {"Datapoints": [{"Average": 200 * (1024 ** 3)}]},  # BucketSizeBytes
                {"Datapoints": [{"Average": 5000}]},               # NumberOfObjects
            ]
            mock_boto_cw.return_value = cw

            results = analyze_s3_access_patterns(region="ap-south-1")

        assert len(results) >= 1
        bucket = next((r for r in results if r["bucket_name"] == "my-company-logs"), None)
        assert bucket is not None
        assert bucket["monthly_savings"] > 0

    def test_active_bucket_excluded(self, sample_bucket):
        with patch("s3_lifecycle_optimizer._get_cache", return_value=None), \
             patch("s3_lifecycle_optimizer._set_cache"), \
             patch("s3_lifecycle_optimizer._s3_client") as mock_s3, \
             patch("boto3.client") as mock_boto_cw, \
             patch("s3_lifecycle_optimizer._estimate_inactive_objects_via_cloudtrail", return_value=0):

            s3 = mock_s3.return_value
            s3.list_buckets.return_value = {"Buckets": [sample_bucket]}
            s3.list_bucket_inventory_configurations.side_effect = ClientError(
                {"Error": {"Code": "NoSuchBucket", "Message": ""}}, ""
            )

            cw = MagicMock()
            cw.get_metric_statistics.side_effect = [
                {"Datapoints": [{"Average": 200 * (1024 ** 3)}]},
                {"Datapoints": [{"Average": 5000}]},
            ]
            mock_boto_cw.return_value = cw

            results = analyze_s3_access_patterns(region="ap-south-1")

        assert results == []

    def test_small_buckets_excluded(self):
        """Buckets with < 1 GB storage should be skipped."""
        tiny_bucket = {"Name": "tiny-bucket", "CreationDate": datetime(2023, 1, 1, tzinfo=timezone.utc)}
        with patch("s3_lifecycle_optimizer._get_cache", return_value=None), \
             patch("s3_lifecycle_optimizer._set_cache"), \
             patch("s3_lifecycle_optimizer._s3_client") as mock_s3, \
             patch("boto3.client") as mock_boto_cw:

            mock_s3.return_value.list_buckets.return_value = {"Buckets": [tiny_bucket]}

            cw = MagicMock()
            cw.get_metric_statistics.return_value = {
                "Datapoints": [{"Average": 500 * 1024}]  # 500 KB
            }
            mock_boto_cw.return_value = cw

            results = analyze_s3_access_patterns(region="ap-south-1")

        assert results == []

    def test_cache_hit_avoids_api_calls(self):
        cached = [{"bucket_name": "cached"}]
        with patch("s3_lifecycle_optimizer._get_cache", return_value=cached), \
             patch("s3_lifecycle_optimizer._s3_client") as mock_s3:

            results = analyze_s3_access_patterns(region="ap-south-1")

        mock_s3.assert_not_called()
        assert results == cached

    def test_results_sorted_by_savings_descending(self):
        buckets = [
            {"Name": "small-savings", "CreationDate": datetime(2023, 1, 1, tzinfo=timezone.utc)},
            {"Name": "big-savings", "CreationDate": datetime(2023, 1, 1, tzinfo=timezone.utc)},
        ]

        with patch("s3_lifecycle_optimizer._get_cache", return_value=None), \
             patch("s3_lifecycle_optimizer._set_cache"), \
             patch("s3_lifecycle_optimizer._s3_client") as mock_s3, \
             patch("boto3.client") as mock_boto_cw, \
             patch(
                 "s3_lifecycle_optimizer._estimate_inactive_objects_via_cloudtrail",
                 return_value=-1,
             ):

            s3 = mock_s3.return_value
            s3.list_buckets.return_value = {"Buckets": buckets}
            s3.list_bucket_inventory_configurations.side_effect = ClientError(
                {"Error": {"Code": "NoSuchBucket", "Message": ""}}, ""
            )

            call_idx = [0]
            def cw_side_effect(**kwargs):
                # Return different sizes for different buckets
                metric = kwargs.get("MetricName", "")
                if "BucketSizeBytes" in metric or metric == "BucketSizeBytes":
                    size = 500 * (1024 ** 3) if call_idx[0] % 2 == 0 else 100 * (1024 ** 3)
                    call_idx[0] += 1
                    return {"Datapoints": [{"Average": size}]}
                return {"Datapoints": [{"Average": 1000}]}

            cw = MagicMock()
            cw.get_metric_statistics.side_effect = cw_side_effect
            mock_boto_cw.return_value = cw

            results = analyze_s3_access_patterns(region="ap-south-1")

        for i in range(len(results) - 1):
            assert results[i]["monthly_savings"] >= results[i + 1]["monthly_savings"]


# ---------------------------------------------------------------------------
# Terraform generation
# ---------------------------------------------------------------------------

class TestGenerateS3LifecyclePolicyTerraform:
    def test_generates_valid_hcl(self):
        recommendations = [
            {"bucket_name": "my-logs", "unused_storage_gb": 200.0, "monthly_savings": 4.0}
        ]
        tf = generate_s3_lifecycle_policy_terraform(recommendations)
        assert "aws_s3_bucket_lifecycle_configuration" in tf
        assert "GLACIER" in tf
        assert "my-logs" in tf

    def test_multiple_buckets_all_generated(self):
        recommendations = [
            {"bucket_name": "bucket-a", "unused_storage_gb": 10.0, "monthly_savings": 0.19},
            {"bucket_name": "bucket-b", "unused_storage_gb": 500.0, "monthly_savings": 9.50},
        ]
        tf = generate_s3_lifecycle_policy_terraform(recommendations)
        assert "bucket-a" in tf
        assert "bucket-b" in tf
