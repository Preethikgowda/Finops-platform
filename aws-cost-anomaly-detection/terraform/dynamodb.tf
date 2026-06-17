# ---------------------------------------------------------------------------
# DynamoDB Table — FinOps Cost Baselines, Idempotency, and Cache
#
# Composite key schema:
#   PK: execution_date (YYYY-MM-DD)  — date of the cost record
#   SK: metric_type                  — one of: baseline, anomaly,
#                                      cloudtrail_cache, idempotency
#
# GSI for querying by metric_type across date ranges:
#   PK: metric_type
#   SK: execution_date
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "finops_baselines" {
  name         = var.dynamodb_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "execution_date"
  range_key    = "metric_type"

  attribute {
    name = "execution_date"
    type = "S"
  }

  attribute {
    name = "metric_type"
    type = "S"
  }

  # TTL for automatic cleanup of cache entries and old records
  ttl {
    attribute_name = "expiration_time"
    enabled        = true
  }

  # Enable Point-in-Time Recovery for baseline data durability
  point_in_time_recovery {
    enabled = true
  }

  # GSI for querying all records of a given metric_type across date ranges
  global_secondary_index {
    name               = "metric_type-execution_date-index"
    hash_key           = "metric_type"
    range_key          = "execution_date"
    projection_type    = "ALL"
  }

  tags = {
    Name = var.dynamodb_table_name
  }
}

# ---------------------------------------------------------------------------
# CloudWatch Alarm — DynamoDB throttling
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "dynamodb_throttling" {
  alarm_name          = "${var.project_name}-${var.environment}-dynamodb-throttles"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SystemErrors"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "DynamoDB throttling detected on finops-cost-baselines table"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = aws_dynamodb_table.finops_baselines.name
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-dynamodb-alarm"
  }
}
