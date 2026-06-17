# ---------------------------------------------------------------------------
# Athena Setup for CloudTrail Log Queries
#
# CloudTrail logs are stored in S3 and queried through Athena. This file
# defines the Athena workgroup and saved named queries for common lookups.
#
# PREREQUISITES (manual setup required before apply):
#   1. Enable CloudTrail with S3 logging in your account.
#   2. Create the Athena database + CloudTrail table using the AWS Console
#      CloudTrail integration or the AWS Glue crawler.
#   3. Populate var.cloudtrail_s3_bucket and var.athena_results_bucket.
# ---------------------------------------------------------------------------

# Dedicated Athena workgroup for FinOps CloudTrail queries
resource "aws_athena_workgroup" "finops_cloudtrail" {
  name        = "${var.project_name}-${var.environment}-cloudtrail"
  description = "FinOps CloudTrail query workgroup"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = var.athena_results_bucket != "" ? "s3://${var.athena_results_bucket}/cloudtrail/" : "s3://your-results-bucket/cloudtrail/"
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-cloudtrail-wg"
  }
}

# ---------------------------------------------------------------------------
# Named Queries — saved for reference and manual execution
# ---------------------------------------------------------------------------

resource "aws_athena_named_query" "ec2_launches_24h" {
  name        = "${var.project_name}-ec2-launches-24h"
  workgroup   = aws_athena_workgroup.finops_cloudtrail.id
  database    = var.athena_database
  description = "EC2 instance launches in the last 24 hours"

  query = <<-SQL
    SELECT
        eventtime,
        useridentity.arn AS useridentity_arn,
        requestparameters,
        sourceipaddress,
        useragent,
        awsregion
    FROM ${var.athena_table}
    WHERE eventname = 'RunInstances'
      AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
    ORDER BY eventtime DESC
    LIMIT 100;
  SQL
}

resource "aws_athena_named_query" "autoscaling_changes_24h" {
  name        = "${var.project_name}-autoscaling-changes-24h"
  workgroup   = aws_athena_workgroup.finops_cloudtrail.id
  database    = var.athena_database
  description = "Auto Scaling group changes in the last 24 hours"

  query = <<-SQL
    SELECT
        eventtime,
        eventname,
        useridentity.arn AS useridentity_arn,
        requestparameters,
        sourceipaddress,
        awsregion
    FROM ${var.athena_table}
    WHERE eventsource = 'autoscaling.amazonaws.com'
      AND eventname IN (
          'CreateAutoScalingGroup',
          'UpdateAutoScalingGroup',
          'SetDesiredCapacity',
          'ExecutePolicy',
          'PutScalingPolicy'
      )
      AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
    ORDER BY eventtime DESC
    LIMIT 100;
  SQL
}

resource "aws_athena_named_query" "rds_changes_24h" {
  name        = "${var.project_name}-rds-changes-24h"
  workgroup   = aws_athena_workgroup.finops_cloudtrail.id
  database    = var.athena_database
  description = "RDS instance creation and modification events in the last 24 hours"

  query = <<-SQL
    SELECT
        eventtime,
        eventname,
        useridentity.arn AS useridentity_arn,
        requestparameters,
        sourceipaddress,
        awsregion
    FROM ${var.athena_table}
    WHERE eventsource = 'rds.amazonaws.com'
      AND eventname IN (
          'CreateDBInstance',
          'ModifyDBInstance',
          'RestoreDBInstanceFromDBSnapshot',
          'CreateDBCluster',
          'ModifyDBCluster'
      )
      AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
    ORDER BY eventtime DESC
    LIMIT 50;
  SQL
}

resource "aws_athena_named_query" "cost_correlation_summary" {
  name        = "${var.project_name}-cost-correlation-summary"
  workgroup   = aws_athena_workgroup.finops_cloudtrail.id
  database    = var.athena_database
  description = "Summary of all resource changes correlated to cost spikes"

  query = <<-SQL
    SELECT
        DATE(eventtime) AS event_date,
        eventsource,
        eventname,
        COUNT(*) AS event_count,
        COUNT(DISTINCT useridentity.arn) AS unique_actors
    FROM ${var.athena_table}
    WHERE eventtime >= to_iso8601(current_timestamp - interval '7' day)
      AND eventname NOT IN ('Describe%', 'List%', 'Get%')
    GROUP BY 1, 2, 3
    ORDER BY event_date DESC, event_count DESC
    LIMIT 200;
  SQL
}
