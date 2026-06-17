# ---------------------------------------------------------------------------
# CloudTrail — Management Events Trail
# Enables tracking of API calls for cost anomaly correlation.
# ---------------------------------------------------------------------------

resource "aws_cloudtrail" "finops" {
  name                          = "${var.project_name}-${var.environment}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-trail"
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail
  ]
}
