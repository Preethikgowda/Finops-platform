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
  #   region         = "ap-south-1"
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
  name = "bedrock-nova-pro-invoke"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BedrockNovaProInvoke"
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
  name = "dynamodb-finops-state"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBFinOpsState"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query",
          "dynamodb:DeleteItem",
          "dynamodb:DescribeTable",
        ]
        Resource = [
          aws_dynamodb_table.finops_baselines.arn,
          "${aws_dynamodb_table.finops_baselines.arn}/index/*",
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_athena" {
  name = "cloudtrail-athena-query"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudTrailLookup"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:GetTrailStatus",
        ]
        Resource = "*"
      },
      {
        Sid    = "AthenaQueryExecution"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution",
          "athena:GetWorkGroup",
        ]
        Resource = "*"
      },
      {
        Sid    = "S3CloudTrailRead"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Resource = var.cloudtrail_s3_bucket != "" ? [
          "arn:aws:s3:::${var.cloudtrail_s3_bucket}",
          "arn:aws:s3:::${var.cloudtrail_s3_bucket}/*",
        ] : ["arn:aws:s3:::placeholder-bucket"]
      },
      {
        Sid    = "S3AthenaResults"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
        ]
        Resource = var.athena_results_bucket != "" ? [
          "arn:aws:s3:::${var.athena_results_bucket}",
          "arn:aws:s3:::${var.athena_results_bucket}/*",
        ] : ["arn:aws:s3:::placeholder-results-bucket"]
      },
      {
        Sid    = "GlueReadForAthena"
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetPartitions",
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy" "compute_optimizer" {
  name = "compute-optimizer-read"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ComputeOptimizerRead"
        Effect = "Allow"
        Action = [
          "compute-optimizer:GetEC2InstanceRecommendations",
          "compute-optimizer:GetLambdaFunctionRecommendations",
          "compute-optimizer:GetEBSVolumeRecommendations",
          "compute-optimizer:GetEnrollmentStatus",
        ]
        Resource = "*"
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
      AWS_REGION              = var.aws_region
      BEDROCK_MODEL_ID        = var.bedrock_model_id
      SLACK_WEBHOOK_URL       = var.slack_webhook_url
      COST_THRESHOLD_PCT      = tostring(var.cost_threshold_pct)
      COST_DASHBOARD_URL      = var.cost_dashboard_url
      DYNAMODB_TABLE_NAME     = aws_dynamodb_table.finops_baselines.name
      ROLLING_WINDOW_DAYS     = tostring(var.rolling_window_days)
      CLOUDTRAIL_S3_BUCKET    = var.cloudtrail_s3_bucket
      CLOUDTRAIL_S3_PREFIX    = var.cloudtrail_s3_prefix
      ATHENA_RESULTS_BUCKET   = var.athena_results_bucket
      ATHENA_DATABASE         = var.athena_database
      ATHENA_TABLE            = var.athena_table
      LOG_LEVEL               = var.log_level
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
  # Alert when average duration exceeds 100 seconds (out of 120s timeout)
  threshold          = 100000
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
