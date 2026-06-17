terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
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
# Pre-built zip includes src/ + all pip dependencies (requests, python-dotenv, etc.)
# Build with: pip install -r requirements.txt --target dist/python_deps && make build
# ---------------------------------------------------------------------------

locals {
  lambda_package_path = "${path.module}/../dist/lambda_package.zip"
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
        Resource = [
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*",
        ]
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
        Resource = [
          aws_s3_bucket.athena_results.arn,
          "${aws_s3_bucket.athena_results.arn}/*",
        ]
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

resource "aws_iam_role_policy" "cloudwatch_metrics" {
  name = "cloudwatch-metrics-read"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchMetricsRead"
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:GetMetricData",
          "cloudwatch:ListMetrics",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ec2_rds_read" {
  name = "ec2-rds-describe"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2DescribeForUtilization"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeReservedInstances",
          "ec2:DescribeReservedInstancesOfferings",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
        ]
        Resource = "*"
      },
      {
        Sid    = "RDSDescribeForUtilization"
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
          "rds:ListTagsForResource",
          "rds:DescribeReservedDBInstances",
          "rds:DescribeReservedDBInstancesOfferings",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_s3_read" {
  name = "lambda-s3-tag-compliance"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LambdaListForTagCompliance"
        Effect = "Allow"
        Action = [
          "lambda:ListFunctions",
          "lambda:ListTags",
          "lambda:GetFunctionConfiguration",
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ListForTagCompliance"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:ListBuckets",
          "s3:GetBucketTagging",
          "s3:GetBucketLocation",
          "s3:GetBucketLifecycleConfiguration",
          "s3:GetBucketLogging",
          "s3:GetObjectTagging",
          "s3:ListBucket",
          "s3:ListObjects",
          "s3:ListObjectsV2",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "pricing_api" {
  name = "pricing-api-read"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PricingAPIRead"
        Effect = "Allow"
        Action = [
          "pricing:GetProducts",
          "pricing:DescribeServices",
          "pricing:GetAttributeValues",
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
  filename         = local.lambda_package_path
  source_code_hash = filebase64sha256(local.lambda_package_path)
  timeout          = var.lambda_timeout_seconds
  memory_size      = var.lambda_memory_mb

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      BEDROCK_MODEL_ID        = var.bedrock_model_id
      SLACK_WEBHOOK_URL       = var.slack_webhook_url
      COST_THRESHOLD_PCT      = tostring(var.cost_threshold_pct)
      COST_DASHBOARD_URL      = var.cost_dashboard_url
      DYNAMODB_TABLE_NAME     = aws_dynamodb_table.finops_baselines.name
      ROLLING_WINDOW_DAYS     = tostring(var.rolling_window_days)
      CLOUDTRAIL_S3_BUCKET    = aws_s3_bucket.cloudtrail.id
      CLOUDTRAIL_S3_PREFIX    = var.cloudtrail_s3_prefix
      ATHENA_RESULTS_BUCKET   = aws_s3_bucket.athena_results.id
      ATHENA_DATABASE         = aws_glue_catalog_database.cloudtrail.name
      ATHENA_TABLE            = aws_glue_catalog_table.cloudtrail_logs.name
      LOG_LEVEL               = var.log_level
      # CS-07 extended configuration
      WEEKLY_DIGEST_ENABLED   = tostring(var.weekly_digest_enabled)
      WEEKLY_DIGEST_DAY       = tostring(var.weekly_digest_day)
      COST_CENTER_TAG_NAME    = var.cost_center_tag_name
      REQUIRED_TAG_LIST       = join(",", var.required_tag_list)
      TF_PR_MIN_RECOMMENDATIONS = tostring(var.tf_pr_min_recommendations)
      TF_PR_REVIEWERS         = var.tf_pr_reviewers
      GITHUB_TOKEN            = var.github_token
      GITHUB_REPO             = var.github_repo
      GITHUB_BRANCH_MAIN      = var.github_branch_main
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
