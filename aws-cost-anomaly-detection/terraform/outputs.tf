output "lambda_function_name" {
  description = "Name of the deployed Lambda function."
  value       = aws_lambda_function.cost_anomaly_detector.function_name
}

output "lambda_function_arn" {
  description = "ARN of the deployed Lambda function."
  value       = aws_lambda_function.cost_anomaly_detector.arn
}

output "lambda_role_arn" {
  description = "ARN of the IAM execution role attached to the Lambda function."
  value       = aws_iam_role.lambda_exec.arn
}

output "cloudwatch_log_group" {
  description = "CloudWatch Log Group name for Lambda logs."
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule that triggers daily analysis."
  value       = aws_cloudwatch_event_rule.daily_trigger.arn
}

output "dynamodb_table_name" {
  description = "Name of the DynamoDB table for cost baselines, idempotency, and cache."
  value       = aws_dynamodb_table.finops_baselines.name
}

output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB FinOps baselines table."
  value       = aws_dynamodb_table.finops_baselines.arn
}

output "athena_workgroup_name" {
  description = "Name of the Athena workgroup for CloudTrail queries."
  value       = aws_athena_workgroup.finops_cloudtrail.name
}

output "cloudtrail_s3_bucket" {
  description = "S3 bucket name where CloudTrail logs are stored."
  value       = aws_s3_bucket.cloudtrail.id
}

output "athena_results_s3_bucket" {
  description = "S3 bucket name for Athena query results."
  value       = aws_s3_bucket.athena_results.id
}

output "cloudtrail_trail_arn" {
  description = "ARN of the CloudTrail trail."
  value       = aws_cloudtrail.finops.arn
}

output "glue_database_name" {
  description = "Name of the Glue database for CloudTrail Athena queries."
  value       = aws_glue_catalog_database.cloudtrail.name
}

output "glue_table_name" {
  description = "Name of the Glue table for CloudTrail logs."
  value       = aws_glue_catalog_table.cloudtrail_logs.name
}

output "account_id" {
  description = "AWS account ID where resources are deployed."
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "AWS region where resources are deployed."
  value       = data.aws_region.current.name
}
