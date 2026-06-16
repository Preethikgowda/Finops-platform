terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # Uncomment and configure for remote state
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "cost-anomaly-detection/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-lock"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "cost-anomaly-detection"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# Lambda deployment package
# ---------------------------------------------------------------------------

data "archive_file" "lambda_package" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/../dist/lambda_package.zip"

  excludes = [
    "__pycache__",
    "*.pyc",
    "*.pyo",
    ".pytest_cache",
  ]
}

# ---------------------------------------------------------------------------
# IAM Role for Lambda
# ---------------------------------------------------------------------------

resource "aws_iam_role" "lambda_exec" {
  name = "${var.project_name}-${var.environment}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-${var.environment}-lambda-role"
  }
}

# ---------------------------------------------------------------------------
# IAM Policies — least-privilege
# ---------------------------------------------------------------------------

resource "aws_iam_role_policy" "cost_explorer" {
  name = "cost-explorer-read"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CostExplorerRead"
        Effect = "Allow"
        Action = [
          "ce:GetCostAndUsage",
          "ce:GetCostForecast",
          "ce:GetDimensionValues",
          "ce:GetUsageForecast",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "bedrock_invoke" {
  name = "bedrock-model-invoke"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BedrockModelInvoke"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "bedrock:Converse",
          "bedrock:ConverseStream",
        ]
        Resource = [
          "arn:aws:bedrock:${var.aws_region}::foundation-model/${var.bedrock_model_id}",
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudwatch_logs" {
  name = "cloudwatch-logs-write"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogsWrite"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
        ]
        Resource = [
          aws_cloudwatch_log_group.lambda_logs.arn,
          "${aws_cloudwatch_log_group.lambda_logs.arn}:*",
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "xray" {
  name = "xray-write"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "XRayWrite"
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets",
          "xray:GetSamplingStatisticSummaries",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "dynamodb" {
  name = "dynamodb-idempotency"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBIdempotency"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DescribeTable",
        ]
        Resource = aws_dynamodb_table.idempotency.arn
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# CloudWatch Log Group
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.project_name}-${var.environment}"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-${var.environment}-logs"
  }
}

# ---------------------------------------------------------------------------
# Lambda Function
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "cost_anomaly_detector" {
  function_name    = "${var.project_name}-${var.environment}"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "lambda_handler.handler"
  runtime          = "python3.11"
  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256
  timeout          = var.lambda_timeout_seconds
  memory_size      = var.lambda_memory_mb

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      AWS_REGION          = var.aws_region
      ES_HOST             = var.es_host
      ES_PORT             = tostring(var.es_port)
      ES_SCHEME           = var.es_scheme
      ES_INDEX_PREFIX     = var.es_index_prefix
      ES_DEPLOY_INDEX_PREFIX = var.es_deploy_index_prefix
      ES_INFRA_INDEX_PREFIX  = var.es_infra_index_prefix
      ES_VERIFY_CERTS     = tostring(var.es_verify_certs)
      SLACK_WEBHOOK_URL   = var.slack_webhook_url
      BEDROCK_MODEL_ID    = var.bedrock_model_id
      COST_THRESHOLD_PCT  = tostring(var.cost_threshold_pct)
      COST_DASHBOARD_URL  = var.cost_dashboard_url
      DYNAMODB_TABLE      = aws_dynamodb_table.idempotency.name
      ROLLING_WINDOW_DAYS = tostring(var.rolling_window_days)
      ES_HISTORICAL_DAYS  = tostring(var.es_historical_days)
      LOG_LEVEL           = var.log_level
    }
  }

  depends_on = [
    aws_iam_role_policy.cloudwatch_logs,
    aws_cloudwatch_log_group.lambda_logs,
  ]

  tags = {
    Name = "${var.project_name}-${var.environment}"
  }
}

# ---------------------------------------------------------------------------
# DynamoDB Table — Idempotency
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "idempotency" {
  name         = "${var.project_name}-${var.environment}-idempotency"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "execution_date"

  attribute {
    name = "execution_date"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-idempotency"
  }
}

# ---------------------------------------------------------------------------
# EventBridge (CloudWatch Events) — Daily Schedule
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "daily_trigger" {
  name                = "${var.project_name}-${var.environment}-daily"
  description         = "Trigger cost anomaly detection daily at ${var.schedule_hour}:00 UTC"
  schedule_expression = "cron(0 ${var.schedule_hour} * * ? *)"
  state               = "ENABLED"

  tags = {
    Name = "${var.project_name}-${var.environment}-schedule"
  }
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.daily_trigger.name
  target_id = "CostAnomalyLambda"
  arn       = aws_lambda_function.cost_anomaly_detector.arn
}

resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cost_anomaly_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_trigger.arn
}

# ---------------------------------------------------------------------------
# CloudWatch Alarms — Lambda health monitoring
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.project_name}-${var.environment}-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Cost anomaly detector Lambda function encountered errors"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.cost_anomaly_detector.function_name
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-error-alarm"
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  alarm_name          = "${var.project_name}-${var.environment}-duration"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Average"
  # Alert when average duration exceeds 50 seconds (out of 60s timeout)
  threshold          = 50000
  alarm_description  = "Cost anomaly detector Lambda approaching timeout limit"
  treat_missing_data = "notBreaching"
  unit               = "Milliseconds"

  dimensions = {
    FunctionName = aws_lambda_function.cost_anomaly_detector.function_name
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-duration-alarm"
  }
}
