variable "aws_region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.aws_region))
    error_message = "aws_region must be a valid AWS region (e.g. us-east-1, eu-west-2)."
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
  default     = 60

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
# Elasticsearch
# ---------------------------------------------------------------------------

variable "es_host" {
  description = "Elasticsearch cluster hostname or Elastic Cloud endpoint."
  type        = string
}

variable "es_port" {
  description = "Elasticsearch port number."
  type        = number
  default     = 9200
}

variable "es_scheme" {
  description = "Elasticsearch connection scheme (https or http)."
  type        = string
  default     = "https"

  validation {
    condition     = contains(["http", "https"], var.es_scheme)
    error_message = "es_scheme must be 'http' or 'https'."
  }
}

variable "es_index_prefix" {
  description = "Elasticsearch index prefix for cost data."
  type        = string
  default     = "aws-costs"
}

variable "es_deploy_index_prefix" {
  description = "Elasticsearch index prefix for deployment event logs."
  type        = string
  default     = "deployment-logs"
}

variable "es_infra_index_prefix" {
  description = "Elasticsearch index prefix for infrastructure change events."
  type        = string
  default     = "infra-events"
}

variable "es_verify_certs" {
  description = "Whether to verify TLS certificates for Elasticsearch connections."
  type        = bool
  default     = true
}

variable "es_historical_days" {
  description = "Number of days of historical cost data to query from Elasticsearch."
  type        = number
  default     = 30
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
# Bedrock
# ---------------------------------------------------------------------------

variable "bedrock_model_id" {
  description = "Amazon Bedrock model ID to use for cost analysis."
  type        = string
  default     = "anthropic.claude-3-5-sonnet-20241022-v2:0"
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
