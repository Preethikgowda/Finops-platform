# AWS FinOps Cost Anomaly Detection Platform

Serverless AWS cost monitoring system that detects daily cost anomalies,
correlates them with CloudTrail resource changes, and delivers AI-powered
root-cause analysis via Amazon Nova Pro — all without Elasticsearch.

---

## Architecture

```
┌─────────────────┐
│  CloudWatch     │
│   Events        │  (Triggers daily at 8 AM UTC)
└────────┬────────┘
         │
         ▼
┌──────────────────────────────────────┐
│   AWS Lambda (120 sec timeout)       │
│   Region: ap-south-1 (Mumbai)        │
├──────────────────────────────────────┤
│ 1. Cost Explorer API                 │
│    (yesterday's cost)                │
│                                      │
│ 2. DynamoDB                          │
│    (7-day baseline + idempotency)    │
│                                      │
│ 3. CloudTrail → Athena               │
│    (EC2, ASG, RDS, IAM changes)      │
│                                      │
│ 4. Compute Optimizer API             │
│    (rightsizing recommendations)     │
│                                      │
│ 5. Bedrock Amazon Nova Pro           │
│    (root cause analysis)             │
│                                      │
│ 6. Slack Webhook                     │
│    (enriched alert with findings)    │
│                                      │
│ 7. DynamoDB                          │
│    (store baseline + record run)     │
└──────────────────────────────────────┘
```

### Key Design Decisions

| Component | Choice | Reason |
|---|---|---|
| AI model | Amazon Nova Pro (`amazon.nova-pro-v1:0`) | AWS-native, lower cost/token than Claude, supports Converse API, optimised for AWS analysis |
| Event correlation | CloudTrail + Athena | Serverless, no infra to manage, accurate source-of-truth for all AWS API calls |
| State management | DynamoDB | Handles baselines, idempotency, and 30-min CloudTrail result cache |
| Cost rightsizing | Compute Optimizer | Native AWS API, no extra tooling |
| Baseline window | 7 days stored in DynamoDB | Removes Elasticsearch dependency entirely |

---

## Why Amazon Nova Pro?

- **Cost-effective**: Lower price per token compared to Claude models
- **Fast inference**: Well-suited for daily scheduled Lambda tasks
- **AWS-native**: No cross-vendor API dependencies; runs in your AWS account
- **Converse API**: Same API interface as Claude — drop-in migration
- **AWS-aware**: Trained on AWS documentation; understands service-level context
- **Agent-ready**: Supports Amazon Bedrock Agents for future Phase 2 automation

Model pricing: <https://aws.amazon.com/bedrock/pricing/>

---

## Project Structure

```
aws-cost-anomaly-detection/
├── src/
│   ├── lambda_handler.py          # Orchestration pipeline entry point
│   ├── cost_analyzer.py           # Cost Explorer + anomaly detection
│   ├── cloudtrail_client.py       # CloudTrail queries via Athena
│   ├── bedrock_agent.py           # Amazon Nova Pro analysis
│   ├── compute_optimizer_client.py# Rightsizing recommendations
│   ├── dynamodb_store.py          # State management + caching
│   ├── slack_notifier.py          # Slack Block Kit alert formatting
│   └── utils.py                   # Date helpers and shared utilities
├── tests/
│   ├── conftest.py
│   ├── test_cost_analyzer.py
│   ├── test_cloudtrail_client.py
│   ├── test_bedrock_agent.py
│   ├── test_compute_optimizer_client.py
│   ├── test_dynamodb_store.py
│   ├── test_lambda_handler.py
│   └── test_slack_notifier.py
├── terraform/
│   ├── main.tf                    # Lambda, IAM, EventBridge, CloudWatch
│   ├── dynamodb.tf                # DynamoDB table + GSI + alarms
│   ├── cloudtrail_queries.tf      # Athena workgroup + named queries
│   ├── variables.tf
│   └── outputs.tf
├── requirements.txt               # boto3 only — no elasticsearch
├── Makefile
└── .env.example
```

---

## Prerequisites

1. **AWS Account** in `ap-south-1` (Mumbai) — or update `AWS_REGION`
2. **Cost Explorer** enabled in your AWS account
3. **CloudTrail** enabled and logging to an S3 bucket
4. **Athena** database + table set up for CloudTrail logs (see below)
5. **Amazon Bedrock** access to `amazon.nova-pro-v1:0` in `ap-south-1`
6. **AWS Compute Optimizer** enrolled (free; enable in the console)
7. **Slack Incoming Webhook** URL configured

---

## Quick Start

### 1. Install dependencies

```bash
make install
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your values
```

### 3. Set up CloudTrail → Athena

Create the Athena database and table using the AWS Console:

1. Open **Athena** in the AWS Console
2. Create database: `CREATE DATABASE cloudtrail_logs;`
3. Create the CloudTrail table using the [AWS CloudTrail Athena query wizard](https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html)
4. Set `ATHENA_DATABASE=cloudtrail_logs` and `ATHENA_TABLE=cloudtrail` in your `.env`

### 4. Deploy with Terraform

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars
terraform init
terraform plan
terraform apply
```

### 5. Run tests

```bash
make test
```

---

## Configuration Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `AWS_REGION` | No | `ap-south-1` | AWS region |
| `SLACK_WEBHOOK_URL` | **Yes** | — | Slack incoming webhook URL |
| `BEDROCK_MODEL_ID` | No | `amazon.nova-pro-v1:0` | Bedrock model identifier |
| `DYNAMODB_TABLE_NAME` | No | `finops-cost-baselines` | DynamoDB table name |
| `CLOUDTRAIL_S3_BUCKET` | No | — | S3 bucket with CloudTrail logs |
| `CLOUDTRAIL_S3_PREFIX` | No | `AWSLogs/` | CloudTrail S3 key prefix |
| `ATHENA_RESULTS_BUCKET` | No | — | S3 bucket for Athena results |
| `ATHENA_DATABASE` | No | `cloudtrail_logs` | Athena database name |
| `ATHENA_TABLE` | No | `cloudtrail` | Athena table name |
| `COST_THRESHOLD_PCT` | No | `15.0` | % increase to trigger alert |
| `ROLLING_WINDOW_DAYS` | No | `7` | Days in baseline window |
| `COST_DASHBOARD_URL` | No | — | Dashboard URL in Slack alert |
| `LOG_LEVEL` | No | `INFO` | Python log level |

---

## DynamoDB Table Schema

Table: `finops-cost-baselines` (configurable)

| Attribute | Type | Description |
|---|---|---|
| `execution_date` (PK) | String | ISO date `YYYY-MM-DD` |
| `metric_type` (SK) | String | `baseline` / `anomaly` / `cloudtrail_cache` / `idempotency` |
| `cost_usd` | Number | Daily cost (baseline records) |
| `analysis_id` | String | Unique analysis run ID |
| `expiration_time` | Number | Unix epoch TTL (auto-deleted by DynamoDB) |
| `updated_at` | String | ISO 8601 timestamp |

GSI: `metric_type-execution_date-index` — enables date-range queries by metric type.

---

## CloudTrail Queries

The platform queries CloudTrail via Athena for the following event types in the past 24 hours:

| Category | Events Tracked |
|---|---|
| EC2 Launches | `RunInstances` |
| Auto Scaling | `CreateAutoScalingGroup`, `UpdateAutoScalingGroup`, `SetDesiredCapacity`, `ExecutePolicy` |
| RDS Changes | `CreateDBInstance`, `ModifyDBInstance`, `CreateDBCluster`, `ModifyDBCluster` |
| IAM Changes | `CreateRole`, `AttachRolePolicy`, `PutRolePolicy`, `CreatePolicy` |

CloudTrail query results are cached in DynamoDB for 30 minutes to avoid duplicate Athena charges.

---

## Example Slack Alert

```
🔴 AWS Cost Anomaly Detected — HIGH Severity

Analysis Date: 2024-01-15  |  Analysis ID: ab12cd34
Yesterday's Cost: $625.00  |  7-Day Baseline: $500.00
Cost Delta: +$125.00       |  Increase: +25.0%

🔍 Root Cause Analysis (Amazon Nova Pro)
The cost increase correlates with infrastructure scale-out events
detected in CloudTrail. 3x m5.xlarge instances were launched.

💡 Probable Root Causes
• 3x m5.xlarge EC2 instances launched in production
• Auto Scaling group scaled from 3 to 8 instances

☁️ CloudTrail Resource Changes (Last 24h)
EC2 Launches (3 instances):
  • [2024-01-15T10:00:00Z] by deploy-bot
Auto Scaling Changes (2 events):
  • [2024-01-15T11:00:00Z] SetDesiredCapacity

📋 Recommended Actions
1. Review EC2 instance types for right-sizing (save $95/month)
2. Enable Reserved Instances for predictable workloads
3. Review Auto Scaling policies and target capacities

💰 Compute Optimizer Opportunities
Estimated monthly savings: $145.00

🕐 2024-01-15T08:05:00Z UTC  |  ID: ab12cd34  |  Model: amazon.nova-pro-v1:0
```

---

## IAM Permissions Required

The Lambda execution role needs:

```
ce:GetCostAndUsage
bedrock:InvokeModel, bedrock:Converse  (for amazon.nova-pro-v1:0)
dynamodb:GetItem, PutItem, Query, DeleteItem
cloudtrail:LookupEvents
athena:StartQueryExecution, GetQueryExecution, GetQueryResults
s3:GetObject, ListBucket  (CloudTrail and Athena results buckets)
glue:GetDatabase, GetTable, GetPartitions  (for Athena)
compute-optimizer:GetEC2InstanceRecommendations
compute-optimizer:GetLambdaFunctionRecommendations
compute-optimizer:GetEBSVolumeRecommendations
logs:CreateLogGroup, CreateLogStream, PutLogEvents
xray:PutTraceSegments, PutTelemetryRecords
```

All permissions are provisioned by `terraform/main.tf`.

---

## Makefile Reference

| Target | Description |
|---|---|
| `make install` | Install production dependencies |
| `make install-dev` | Install dev + test dependencies |
| `make test` | Run test suite |
| `make test-cov` | Run tests with ≥80% coverage report |
| `make lint` | Run ruff linter |
| `make format` | Auto-format with black/ruff |
| `make build` | Package Lambda zip |
| `make deploy` | Terraform apply |
| `make invoke` | Invoke Lambda manually |
| `make logs` | Tail CloudWatch logs |

---

## Local Development

```bash
# Install dev dependencies
make install-dev

# Run all tests with coverage
make test-cov

# Run specific test module
pytest tests/test_cloudtrail_client.py -v

# Lint
make lint
```

---

## Monitoring

- **Lambda errors**: CloudWatch alarm triggers when `Errors ≥ 1`
- **Lambda duration**: CloudWatch alarm triggers when average duration > 100s
- **DynamoDB throttling**: CloudWatch alarm on `SystemErrors ≥ 5`
- **Structured logs**: All Lambda logs are JSON-structured for CloudWatch Insights
- **Token tracking**: Nova Pro input/output tokens logged for cost monitoring

---

## Migration from Elasticsearch

This project replaces Elasticsearch with:

| Old (ES) | New |
|---|---|
| `elasticsearch_client.py` | `cloudtrail_client.py` |
| Historical cost data in ES | DynamoDB baseline storage |
| Deployment events in ES | CloudTrail + Athena queries |
| Claude Sonnet 4.6 | Amazon Nova Pro (`amazon.nova-pro-v1:0`) |
| `ES_HOST`, `ES_PORT`, etc. | `CLOUDTRAIL_S3_BUCKET`, `DYNAMODB_TABLE_NAME`, etc. |

Benefits:
- No ES cluster to manage or pay for
- CloudTrail provides authoritative, tamper-proof AWS event history
- DynamoDB is cheaper and simpler than ES for time-series key lookups
- Nova Pro is more cost-effective per token than Claude Sonnet
