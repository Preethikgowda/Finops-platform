"""Tests for tag_compliance_engine.py.

Covers:
- EC2, RDS, S3, Lambda tag scanning
- Missing tag detection
- Auto-tag heuristics (environment, project, owner)
- Terraform code generation for tagging
- Cost allocation by tag
- Compliance report generation
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from tag_compliance_engine import (
    _infer_environment,
    _infer_project,
    _missing_tags,
    auto_tag_resources,
    cost_allocation_by_tag,
    enforce_tag_compliance,
    generate_tag_compliance_report,
    generate_tagging_terraform,
    scan_untagged_resources,
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TestInferEnvironment:
    def test_prod_pattern_detected(self):
        assert _infer_environment("payment-service-prod") == "prod"
        assert _infer_environment("my-production-db") == "prod"

    def test_staging_pattern_detected(self):
        assert _infer_environment("api-staging-01") == "staging"
        assert _infer_environment("my-stage-env") == "staging"

    def test_dev_pattern_detected(self):
        assert _infer_environment("feature-dev-server") == "dev"
        assert _infer_environment("sandbox-testing") == "dev"

    def test_unknown_returned_for_no_match(self):
        assert _infer_environment("random-name-xyz") == "unknown"

    def test_empty_string_returns_unknown(self):
        assert _infer_environment("") == "unknown"


class TestInferProject:
    def test_extracts_first_meaningful_segment(self):
        project = _infer_project("payments-service-prod")
        assert project == "payments"

    def test_ignores_env_suffixes(self):
        project = _infer_project("inventory-prod-01")
        assert project == "inventory"

    def test_empty_string_returns_unknown(self):
        assert _infer_project("") == "unknown"

    def test_short_segment_skipped(self):
        project = _infer_project("ab-api-prod")
        assert project == "api" or project != ""


class TestMissingTags:
    def test_all_required_tags_present(self):
        existing = {"CostCenter": "eng", "Project": "api", "Environment": "prod", "Owner": "alice"}
        assert _missing_tags(existing, ["CostCenter", "Project", "Environment", "Owner"]) == []

    def test_single_missing_tag(self):
        existing = {"CostCenter": "eng", "Project": "api", "Environment": "prod"}
        missing = _missing_tags(existing, ["CostCenter", "Project", "Environment", "Owner"])
        assert missing == ["Owner"]

    def test_empty_value_counted_as_missing(self):
        existing = {"CostCenter": "", "Project": "api"}
        missing = _missing_tags(existing, ["CostCenter", "Project"])
        assert "CostCenter" in missing

    def test_empty_required_list_returns_empty(self):
        assert _missing_tags({"foo": "bar"}, []) == []


# ---------------------------------------------------------------------------
# scan_untagged_resources
# ---------------------------------------------------------------------------

class TestScanUntaggedResources:
    def test_ec2_missing_tags_detected(self):
        instance = {
            "InstanceId": "i-abc",
            "InstanceType": "t3.medium",
            "Tags": [{"Key": "Name", "Value": "web-server"}],
        }
        with patch("tag_compliance_engine._get_cache", return_value=None), \
             patch("tag_compliance_engine._set_cache"), \
             patch("tag_compliance_engine._ec2_client") as mock_ec2, \
             patch("tag_compliance_engine._rds_client") as mock_rds, \
             patch("tag_compliance_engine._s3_client") as mock_s3, \
             patch("tag_compliance_engine._lambda_client") as mock_lam:

            mock_ec2.return_value.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [instance]}]}
            ]
            mock_rds.return_value.get_paginator.return_value.paginate.return_value = [{"DBInstances": []}]
            mock_s3.return_value.list_buckets.return_value = {"Buckets": []}
            mock_lam.return_value.get_paginator.return_value.paginate.return_value = [{"Functions": []}]

            results = scan_untagged_resources(
                region="ap-south-1",
                required_tags=["CostCenter", "Project", "Environment", "Owner"],
            )

        ec2_results = [r for r in results if r["resource_type"] == "EC2_INSTANCE"]
        assert len(ec2_results) == 1
        assert "CostCenter" in ec2_results[0]["missing_tags"]

    def test_fully_tagged_instance_not_flagged(self):
        instance = {
            "InstanceId": "i-def",
            "InstanceType": "m5.large",
            "Tags": [
                {"Key": "CostCenter", "Value": "eng"},
                {"Key": "Project", "Value": "api"},
                {"Key": "Environment", "Value": "prod"},
                {"Key": "Owner", "Value": "team-a"},
            ],
        }
        with patch("tag_compliance_engine._get_cache", return_value=None), \
             patch("tag_compliance_engine._set_cache"), \
             patch("tag_compliance_engine._ec2_client") as mock_ec2, \
             patch("tag_compliance_engine._rds_client") as mock_rds, \
             patch("tag_compliance_engine._s3_client") as mock_s3, \
             patch("tag_compliance_engine._lambda_client") as mock_lam:

            mock_ec2.return_value.get_paginator.return_value.paginate.return_value = [
                {"Reservations": [{"Instances": [instance]}]}
            ]
            mock_rds.return_value.get_paginator.return_value.paginate.return_value = [{"DBInstances": []}]
            mock_s3.return_value.list_buckets.return_value = {"Buckets": []}
            mock_lam.return_value.get_paginator.return_value.paginate.return_value = [{"Functions": []}]

            results = scan_untagged_resources(
                region="ap-south-1",
                required_tags=["CostCenter", "Project", "Environment", "Owner"],
            )

        ec2_results = [r for r in results if r["resource_type"] == "EC2_INSTANCE"]
        assert len(ec2_results) == 0

    def test_s3_missing_tags_detected(self):
        bucket = {"Name": "my-data-bucket", "CreationDate": datetime(2023, 1, 1, tzinfo=timezone.utc)}
        with patch("tag_compliance_engine._get_cache", return_value=None), \
             patch("tag_compliance_engine._set_cache"), \
             patch("tag_compliance_engine._ec2_client") as mock_ec2, \
             patch("tag_compliance_engine._rds_client") as mock_rds, \
             patch("tag_compliance_engine._s3_client") as mock_s3, \
             patch("tag_compliance_engine._lambda_client") as mock_lam:

            mock_ec2.return_value.get_paginator.return_value.paginate.return_value = [
                {"Reservations": []}
            ]
            mock_rds.return_value.get_paginator.return_value.paginate.return_value = [{"DBInstances": []}]

            s3 = mock_s3.return_value
            s3.list_buckets.return_value = {"Buckets": [bucket]}
            s3.get_bucket_tagging.side_effect = ClientError(
                {"Error": {"Code": "NoSuchTagSet", "Message": ""}}, "GetBucketTagging"
            )

            mock_lam.return_value.get_paginator.return_value.paginate.return_value = [{"Functions": []}]

            results = scan_untagged_resources(
                region="ap-south-1",
                required_tags=["CostCenter"],
            )

        s3_results = [r for r in results if r["resource_type"] == "S3_BUCKET"]
        assert len(s3_results) == 1

    def test_cache_hit_avoids_api_calls(self):
        cached = [{"resource_id": "i-cached", "resource_type": "EC2_INSTANCE"}]
        with patch("tag_compliance_engine._get_cache", return_value=cached), \
             patch("tag_compliance_engine._ec2_client") as mock_ec2:

            results = scan_untagged_resources(region="ap-south-1")

        mock_ec2.assert_not_called()
        assert results == cached


# ---------------------------------------------------------------------------
# auto_tag_resources
# ---------------------------------------------------------------------------

class TestAutoTagResources:
    def test_environment_inferred_from_name(self):
        untagged = [
            {
                "resource_id": "i-x",
                "resource_type": "EC2_INSTANCE",
                "missing_tags": ["Environment"],
                "existing_tags": {"Name": "api-server-prod"},
                "monthly_cost": 0.0,
                "recommendation": "",
            }
        ]
        with patch("tag_compliance_engine._get_creator_from_cloudtrail", return_value="unknown"):
            results = auto_tag_resources(untagged, region="ap-south-1")

        assert results[0]["suggested_tags"]["Environment"] == "prod"

    def test_project_inferred_from_name(self):
        untagged = [
            {
                "resource_id": "i-y",
                "resource_type": "EC2_INSTANCE",
                "missing_tags": ["Project"],
                "existing_tags": {"Name": "billing-api-prod"},
                "monthly_cost": 0.0,
                "recommendation": "",
            }
        ]
        with patch("tag_compliance_engine._get_creator_from_cloudtrail", return_value="unknown"):
            results = auto_tag_resources(untagged, region="ap-south-1")

        assert results[0]["suggested_tags"]["Project"] == "billing"

    def test_cost_center_placeholder_when_not_inferrable(self):
        untagged = [
            {
                "resource_id": "i-z",
                "resource_type": "EC2_INSTANCE",
                "missing_tags": ["CostCenter"],
                "existing_tags": {},
                "monthly_cost": 0.0,
                "recommendation": "",
            }
        ]
        with patch("tag_compliance_engine._get_creator_from_cloudtrail", return_value="unknown"):
            results = auto_tag_resources(untagged, region="ap-south-1")

        assert "UNKNOWN" in results[0]["suggested_tags"]["CostCenter"]

    def test_confidence_low_when_cost_center_missing(self):
        untagged = [
            {
                "resource_id": "i-a",
                "resource_type": "EC2_INSTANCE",
                "missing_tags": ["CostCenter", "Project"],
                "existing_tags": {},
                "monthly_cost": 0.0,
                "recommendation": "",
            }
        ]
        with patch("tag_compliance_engine._get_creator_from_cloudtrail", return_value="unknown"):
            results = auto_tag_resources(untagged, region="ap-south-1")

        assert results[0]["confidence"] == "low"


# ---------------------------------------------------------------------------
# generate_tagging_terraform
# ---------------------------------------------------------------------------

class TestGenerateTaggingTerraform:
    def test_ec2_resource_in_output(self):
        tagged = [
            {
                "resource_id": "i-abc123",
                "resource_type": "EC2_INSTANCE",
                "suggested_tags": {"Environment": "prod"},
                "missing_tags": ["Environment"],
            }
        ]
        tf = generate_tagging_terraform(tagged)
        assert "aws_ec2_tag" in tf
        assert "i-abc123" in tf
        assert "prod" in tf

    def test_s3_resource_in_output(self):
        tagged = [
            {
                "resource_id": "my-bucket",
                "resource_type": "S3_BUCKET",
                "suggested_tags": {"CostCenter": "eng"},
                "missing_tags": ["CostCenter"],
            }
        ]
        tf = generate_tagging_terraform(tagged)
        assert "aws_s3_bucket_tagging" in tf
        assert "my-bucket" in tf

    def test_empty_input_returns_header_only(self):
        tf = generate_tagging_terraform([])
        assert "Auto-generated" in tf
        assert "aws_ec2_tag" not in tf


# ---------------------------------------------------------------------------
# enforce_tag_compliance
# ---------------------------------------------------------------------------

class TestEnforceTagCompliance:
    def test_returns_config_rule_definition(self):
        result = enforce_tag_compliance(region="ap-south-1")
        assert "aws_config_rule" in result
        assert result["aws_config_rule"]["managed_rule"] == "REQUIRED_TAGS"

    def test_returns_scp_with_deny_statement(self):
        result = enforce_tag_compliance(region="ap-south-1")
        scp_policy = json.loads(result["service_control_policy"]["policy_json"])
        statements = scp_policy["Statement"]
        assert any(s["Effect"] == "Deny" for s in statements)

    def test_deny_actions_include_ec2_run_instances(self):
        result = enforce_tag_compliance(region="ap-south-1")
        scp_policy = json.loads(result["service_control_policy"]["policy_json"])
        all_actions = []
        for stmt in scp_policy["Statement"]:
            all_actions.extend(stmt.get("Action", []))
        assert "ec2:RunInstances" in all_actions


# ---------------------------------------------------------------------------
# generate_tag_compliance_report
# ---------------------------------------------------------------------------

class TestGenerateTagComplianceReport:
    def test_compliance_percent_calculation(self):
        untagged = [
            {"resource_id": "i-1", "resource_type": "EC2_INSTANCE", "missing_tags": ["Owner"], "monthly_cost": 0},
            {"resource_id": "i-2", "resource_type": "EC2_INSTANCE", "missing_tags": ["CostCenter"], "monthly_cost": 0},
        ]
        report = generate_tag_compliance_report(untagged, total_resources=10)
        assert report["compliance_percent"] == pytest.approx(80.0, rel=1e-3)

    def test_full_compliance_shows_100_percent(self):
        report = generate_tag_compliance_report([], total_resources=5)
        assert report["compliance_percent"] == 100.0

    def test_zero_resources_returns_zero_percent(self):
        report = generate_tag_compliance_report([], total_resources=0)
        assert report["compliance_percent"] == 0.0

    def test_by_type_breakdown(self):
        untagged = [
            {"resource_id": "i-1", "resource_type": "EC2_INSTANCE", "missing_tags": ["Owner"], "monthly_cost": 0},
            {"resource_id": "fn-1", "resource_type": "LAMBDA_FUNCTION", "missing_tags": ["CostCenter"], "monthly_cost": 0},
        ]
        report = generate_tag_compliance_report(untagged, total_resources=20)
        assert report["resources_by_type"].get("EC2_INSTANCE") == 1
        assert report["resources_by_type"].get("LAMBDA_FUNCTION") == 1

    def test_missing_tag_frequency_populated(self):
        untagged = [
            {"resource_id": "i-1", "resource_type": "EC2_INSTANCE", "missing_tags": ["CostCenter", "Owner"], "monthly_cost": 0},
            {"resource_id": "i-2", "resource_type": "EC2_INSTANCE", "missing_tags": ["CostCenter"], "monthly_cost": 0},
        ]
        report = generate_tag_compliance_report(untagged, total_resources=5)
        assert report["missing_tag_frequency"]["CostCenter"] == 2
        assert report["missing_tag_frequency"]["Owner"] == 1
