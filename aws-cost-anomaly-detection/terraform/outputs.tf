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
  description = "Name of the DynamoDB table used for idempotency tracking."
  value       = aws_dynamodb_table.idempotency.name
}

output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB idempotency table."
  value       = aws_dynamodb_table.idempotency.arn
}

output "account_id" {
  description = "AWS account ID where resources are deployed."
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "AWS region where resources are deployed."
  value       = data.aws_region.current.name
}
