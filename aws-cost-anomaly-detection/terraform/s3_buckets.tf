# ---------------------------------------------------------------------------
# S3 Buckets — CloudTrail Logs & Athena Query Results
# ---------------------------------------------------------------------------

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  cloudtrail_bucket_name  = "finops-cloudtrail-${local.account_id}"
  athena_results_bucket_name = "finops-athena-results-${local.account_id}"
}

# ---------------------------------------------------------------------------
# S3 Bucket — CloudTrail Logs
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = local.cloudtrail_bucket_name
  force_destroy = true

  tags = {
    Name        = local.cloudtrail_bucket_name
    Description = "CloudTrail logs for FinOps cost anomaly correlation"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

locals {
  # CloudTrail trail ARN is predictable from project name, env, account, and region
  cloudtrail_trail_name = "${var.project_name}-${var.environment}-trail"
  cloudtrail_trail_arn  = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.cloudtrail_trail_name}"
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.cloudtrail_trail_arn
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "aws:SourceArn" = local.cloudtrail_trail_arn
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail]
}

# ---------------------------------------------------------------------------
# S3 Bucket — Athena Query Results
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "athena_results" {
  bucket        = local.athena_results_bucket_name
  force_destroy = true

  tags = {
    Name        = local.athena_results_bucket_name
    Description = "Athena query results for FinOps CloudTrail analysis"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    id     = "expire-query-results"
    status = "Enabled"

    filter {}

    expiration {
      days = 7
    }
  }
}
