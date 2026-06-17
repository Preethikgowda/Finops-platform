variable "aws_region" {
  description = "AWS region for all resources. Default is ap-south-1 (Asia Pacific - Mumbai)."
  type        = string
  default     = "ap-south-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS region (e.g. ap-south-1, us-east-1)."
  }
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)."
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "project_name" {
  description = "Base name used for all resources. Must be lowercase alphanumeric with hyphens."
  type        = string
  default     = "cost-anomaly-detector"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "project_name must be lowercase alphanumeric characters and hyphens only."
  }
}

# ---------------------------------------------------------------------------
# Lambda configuration
# ---------------------------------------------------------------------------

variable "lambda_timeout_seconds" {
  description = "Lambda function timeout in seconds."
  type        = number
  default     = 120

  validation {
    condition     = var.lambda_timeout_seconds >= 10 && var.lambda_timeout_seconds <= 900
    error_message = "Lambda timeout must be between 10 and 900 seconds."
  }
}

variable "lambda_memory_mb" {
  description = "Lambda function memory allocation in MB."
  type        = number
  default     = 512

  validation {
    condition     = var.lambda_memory_mb >= 128 && var.lambda_memory_mb <= 10240
    error_message = "Lambda memory must be between 128 and 10240 MB."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log group retention in days."
  type        = number
  default     = 7

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365], var.log_retention_days)
    error_message = "log_retention_days must be a valid CloudWatch retention period."
  }
}

variable "log_level" {
  description = "Python logging level (DEBUG, INFO, WARNING, ERROR)."
  type        = string
  default     = "INFO"

  validation {
    condition     = contains(["DEBUG", "INFO", "WARNING", "ERROR"], var.log_level)
    error_message = "log_level must be one of: DEBUG, INFO, WARNING, ERROR."
  }
}

# ---------------------------------------------------------------------------
# Schedule
# ---------------------------------------------------------------------------

variable "schedule_hour" {
  description = "UTC hour (0-23) at which the Lambda is triggered daily."
  type        = number
  default     = 8

  validation {
    condition     = var.schedule_hour >= 0 && var.schedule_hour <= 23
    error_message = "schedule_hour must be between 0 and 23."
  }
}

# ---------------------------------------------------------------------------
# CloudTrail + Athena
# ---------------------------------------------------------------------------

variable "cloudtrail_s3_bucket" {
  description = "S3 bucket where CloudTrail logs are stored."
  type        = string
  default     = ""
}

variable "cloudtrail_s3_prefix" {
  description = "S3 key prefix for CloudTrail logs (e.g. AWSLogs/)."
  type        = string
  default     = "AWSLogs/"
}

variable "athena_results_bucket" {
  description = "S3 bucket for Athena query results (must already exist)."
  type        = string
  default     = ""
}

variable "athena_database" {
  description = "Athena database name for CloudTrail log queries."
  type        = string
  default     = "cloudtrail_logs"
}

variable "athena_table" {
  description = "Athena table name for CloudTrail logs."
  type        = string
  default     = "cloudtrail"
}

# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------

variable "dynamodb_table_name" {
  description = "Name of the DynamoDB table for cost baselines, idempotency, and cache."
  type        = string
  default     = "finops-cost-baselines"
}

# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

variable "slack_webhook_url" {
  description = "Slack incoming webhook URL for anomaly alerts."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^https://hooks\\.slack\\.com/", var.slack_webhook_url))
    error_message = "slack_webhook_url must be a valid Slack webhook URL starting with https://hooks.slack.com/."
  }
}

variable "cost_dashboard_url" {
  description = "Optional URL to your AWS cost dashboard (included in Slack alerts)."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------------------
# Bedrock — Amazon Nova Pro
# ---------------------------------------------------------------------------

variable "bedrock_model_id" {
  description = "Amazon Bedrock model ID. Defaults to Amazon Nova Pro."
  type        = string
  default     = "amazon.nova-pro-v1:0"
}

# ---------------------------------------------------------------------------
# Cost analysis thresholds
# ---------------------------------------------------------------------------

variable "cost_threshold_pct" {
  description = "Percentage increase above the rolling average that triggers an anomaly alert."
  type        = number
  default     = 15.0

  validation {
    condition     = var.cost_threshold_pct > 0 && var.cost_threshold_pct <= 100
    error_message = "cost_threshold_pct must be between 0 (exclusive) and 100."
  }
}

variable "rolling_window_days" {
  description = "Number of days in the rolling average baseline window."
  type        = number
  default     = 7

  validation {
    condition     = var.rolling_window_days >= 1 && var.rolling_window_days <= 90
    error_message = "rolling_window_days must be between 1 and 90."
  }
}
