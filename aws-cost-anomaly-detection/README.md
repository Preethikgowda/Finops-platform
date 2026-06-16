# AWS Cost Anomaly Detector

An automated AWS cost anomaly detection system that runs daily as a Lambda function.
It fetches your AWS spend via Cost Explorer, compares it against a 7-day rolling average,
and — when costs spike above a configurable threshold — uses Amazon Bedrock Claude Sonnet 3.5
to analyze probable root causes (correlated with deployment events from Elasticsearch) and
send a rich Slack alert.

---

## What It Does

```
EventBridge (daily @ 08:00 UTC)
        │
        ▼
┌───────────────────┐
│  Lambda Handler   │◄──── DynamoDB (idempotency)
└───────┬───────────┘
        │
        ├─► Cost Explorer API ──► yesterday's cost
        │
        ├─► Elasticsearch ──────► 7-day historical costs
        │                          deployment events (24h)
        │                          infrastructure changes (24h)
        │
        ├─► Anomaly Detection ──► > 15% above baseline?
        │                            (configurable threshold)
        │
        ├─► Bedrock Claude 3.5 ► root cause analysis
        │                         severity classification
        │                         recommendations
        │
        └─► Slack Webhook ──────► rich alert with blocks
```

---

## Architecture

| Component | Technology |
|---|---|
| Compute | AWS Lambda (Python 3.11, 512 MB, 60s timeout) |
| Scheduler | Amazon EventBridge (cron, configurable hour) |
| Cost data | AWS Cost Explorer API |
| Historical data + logs | Elasticsearch 8.x (cloud or self-hosted) |
| AI analysis | Amazon Bedrock — Claude Sonnet 3.5 via Converse API |
| Alerting | Slack incoming webhook (Block Kit) |
| Idempotency | Amazon DynamoDB |
| Observability | CloudWatch Logs + X-Ray tracing |
| Infrastructure | Terraform ≥ 1.5 |

---

## AWS Prerequisites

Before deploying, ensure the following are configured in your AWS account:

1. **Cost Explorer enabled** — go to [Billing > Cost Explorer](https://console.aws.amazon.com/cost-management/home) and click "Enable Cost Explorer". Changes take up to 24 hours to propagate.

2. **Bedrock model access** — request access to Claude Sonnet 3.5 in [Bedrock Model Access](https://console.aws.amazon.com/bedrock/home#/modelaccess). Must be in a region where Bedrock is available (e.g. `us-east-1`, `us-west-2`, `eu-west-3`).

3. **Elasticsearch cluster** — a reachable cluster (Elastic Cloud, self-hosted, or Amazon OpenSearch). The Lambda must have network access (VPC peering or public endpoint).

4. **Slack App** — create an app at [api.slack.com](https://api.slack.com/apps), enable "Incoming Webhooks", and copy the webhook URL.

5. **AWS CLI configured** — run `aws configure` or use an IAM role/instance profile.

---

## Quick Start

### 1. Clone and install

```bash
git clone <repo-url>
cd aws-cost-anomaly-detection
make install-dev
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — fill in ES_HOST, SLACK_WEBHOOK_URL, etc.
```

### 3. Run tests

```bash
make test
# or with coverage report:
make test-cov
```

### 4. Run locally

```bash
make run-local
```

### 5. Deploy to AWS

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
cd ..
make deploy
```

---

## Project Structure

```
aws-cost-anomaly-detection/
├── src/
│   ├── cost_analyzer.py          # Cost Explorer API + anomaly detection
│   ├── bedrock_agent.py          # Bedrock Claude Sonnet 3.5 integration
│   ├── elasticsearch_client.py   # ES connectivity + queries
│   ├── slack_notifier.py         # Slack Block Kit alerts
│   └── lambda_handler.py         # Lambda entry point + orchestration
├── tests/
│   ├── test_cost_analyzer.py
│   ├── test_bedrock_agent.py
│   ├── test_elasticsearch_client.py
│   ├── test_slack_notifier.py
│   └── test_lambda_handler.py
├── terraform/
│   ├── main.tf                   # Lambda, IAM, DynamoDB, EventBridge, alarms
│   ├── variables.tf              # All configurable inputs
│   ├── outputs.tf                # Deployment outputs
│   └── terraform.tfvars.example  # Template for your values
├── .env.example                  # Local development config template
├── requirements.txt              # Production dependencies (pinned)
├── requirements-dev.txt          # Dev/test dependencies
├── Makefile                      # make install, test, deploy, logs, …
└── README.md
```

---

## Configuration Reference

All configuration is via environment variables (or `.env` for local dev).

| Variable | Required | Default | Description |
|---|---|---|---|
| `AWS_REGION` | No | `us-east-1` | AWS region for all API calls |
| `ES_HOST` | **Yes** | — | Elasticsearch hostname |
| `ES_PORT` | No | `9200` | Elasticsearch port |
| `ES_SCHEME` | No | `https` | `http` or `https` |
| `ES_USERNAME` | No | — | Basic-auth username |
| `ES_PASSWORD` | No | — | Basic-auth password |
| `ES_API_KEY` | No | — | Elasticsearch API key (preferred over basic auth) |
| `ES_CA_CERTS` | No | — | Path to CA bundle for TLS |
| `ES_VERIFY_CERTS` | No | `true` | Set to `false` only in dev |
| `ES_INDEX_PREFIX` | No | `aws-costs` | Cost data index prefix |
| `ES_DEPLOY_INDEX_PREFIX` | No | `deployment-logs` | Deployment events index prefix |
| `ES_INFRA_INDEX_PREFIX` | No | `infra-events` | Infrastructure changes index prefix |
| `ES_HISTORICAL_DAYS` | No | `30` | Days of history to query from ES |
| `SLACK_WEBHOOK_URL` | **Yes** | — | Slack incoming webhook URL |
| `COST_DASHBOARD_URL` | No | — | Optional cost dashboard URL for Slack button |
| `BEDROCK_MODEL_ID` | No | `anthropic.claude-3-5-sonnet-20241022-v2:0` | Bedrock model |
| `COST_THRESHOLD_PCT` | No | `15.0` | Anomaly threshold (% above rolling average) |
| `ROLLING_WINDOW_DAYS` | No | `7` | Days in rolling average baseline |
| `DYNAMODB_TABLE` | No | `cost-anomaly-idempotency` | DynamoDB idempotency table |
| `LOG_LEVEL` | No | `INFO` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` |

---

## Elasticsearch Index Schemas

### Cost data index (`aws-costs-*`)

```json
{
  "@timestamp": "2024-01-14T00:00:00Z",
  "total_cost_usd": 123.45,
  "service": "AmazonEC2",
  "account_id": "123456789012",
  "region": "us-east-1"
}
```

### Deployment events index (`deployment-logs-*`)

```json
{
  "@timestamp": "2024-01-15T10:30:00Z",
  "event_type": "deployment",
  "service": "api-gateway",
  "description": "Deployed v2.1.0 to production",
  "author": "ci-pipeline",
  "environment": "prod"
}
```

Valid `event_type` values: `deployment`, `release`, `infrastructure_change`, `scaling_event`, `config_update`

### Infrastructure changes index (`infra-events-*`)

```json
{
  "@timestamp": "2024-01-15T11:00:00Z",
  "change_type": "auto_scaling",
  "service": "ec2-asg-prod",
  "description": "Scaled from 3 to 8 instances",
  "region": "us-east-1"
}
```

Valid `change_type` values: `auto_scaling`, `manual_scaling`, `instance_launch`, `instance_termination`, `config_change`, `ami_update`, `security_group_change`

---

## Example Elasticsearch Queries

Query yesterday's cost data:

```bash
curl -X GET "https://your-es-host:9200/aws-costs-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "range": {
        "@timestamp": {
          "gte": "now-1d/d",
          "lte": "now/d"
        }
      }
    },
    "sort": [{"@timestamp": {"order": "desc"}}],
    "size": 1
  }'
```

Query recent deployments:

```bash
curl -X GET "https://your-es-host:9200/deployment-logs-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "bool": {
        "must": [
          {"range": {"@timestamp": {"gte": "now-24h"}}},
          {"term": {"event_type": "deployment"}}
        ]
      }
    },
    "size": 20
  }'
```

---

## Example Slack Alert

```
🔴 AWS Cost Anomaly — HIGH Severity
─────────────────────────────────────
Analysis Date    │ 2024-01-15
Analysis ID      │ a3f9b12c
Yesterday's Cost │ $1,423.50
7-Day Baseline   │ $982.00
Cost Delta       │ +$441.50
Increase         │ +44.9%
─────────────────────────────────────
🔍 Root Cause Analysis
The 44.9% cost increase correlates strongly with the API Gateway v2.1.0
deployment at 10:30 UTC. The new version introduced an additional Lambda
invocation per request and increased DynamoDB provisioned capacity.

💡 Probable Root Causes
• API Gateway Lambda integration change doubled invocation count
• DynamoDB capacity autoscaling triggered by new access patterns
• Data transfer increase due to larger response payloads

🚀 Recent Deployment Events (Last 24h)
• 2024-01-15T10:30:00Z deployment — api-gateway: Deployed v2.1.0
• 2024-01-15T11:00:00Z auto_scaling — ec2-asg-prod: Scaled to 8 instances

📋 Recommended Actions
1. Review Lambda invocation count in CloudWatch for the api-gateway function
2. Check DynamoDB capacity units consumed vs provisioned before/after deployment
3. Consider reverting v2.1.0 if cost impact is unacceptable
4. Enable AWS Cost Anomaly Detection for automated baseline alerts

[📊 Open Cost Dashboard]

🕐 Generated at 2024-01-15T08:05:23Z UTC | Analysis ID: a3f9b12c
```

---

## Makefile Reference

| Command | Description |
|---|---|
| `make install` | Install production dependencies |
| `make install-dev` | Install all dependencies (includes dev/test tools) |
| `make test` | Run all unit tests |
| `make test-cov` | Run tests with coverage report (fails below 80%) |
| `make lint` | Run flake8 linter |
| `make format` | Auto-format with black |
| `make typecheck` | Run mypy type checking |
| `make build` | Package Lambda source into a zip |
| `make deploy` | Full Terraform deploy (init + plan + apply) |
| `make tf-plan` | Show Terraform plan without applying |
| `make invoke` | Manually invoke the Lambda via AWS CLI |
| `make logs` | Tail live CloudWatch logs |
| `make logs-last` | Show the last 60 minutes of logs |
| `make run-local` | Run the handler locally (requires `.env`) |
| `make env-check` | Validate `.env` against `.env.example` |
| `make clean` | Remove build artifacts |

---

## IAM Permissions

The Lambda execution role is granted least-privilege access to:

| Service | Actions |
|---|---|
| Cost Explorer | `GetCostAndUsage`, `GetCostForecast`, `GetDimensionValues`, `GetUsageForecast` |
| Bedrock | `InvokeModel`, `Converse` (scoped to the configured model ARN) |
| CloudWatch Logs | `CreateLogGroup`, `CreateLogStream`, `PutLogEvents` |
| X-Ray | `PutTraceSegments`, `PutTelemetryRecords` |
| DynamoDB | `GetItem`, `PutItem`, `DescribeTable` (scoped to idempotency table) |

---

## Error Handling & Graceful Degradation

| Failure | Behavior |
|---|---|
| AWS Cost Explorer down | Returns 500; pipeline aborted (cost data is required) |
| Elasticsearch unreachable | Historical costs default to empty list; analysis continues with Cost Explorer data only |
| Bedrock unavailable | Fallback response used with heuristic severity; Slack alert still sent |
| Slack webhook failure | Logged as error; Lambda returns 200 (alert failure is non-fatal) |
| DynamoDB idempotency table missing | Warning logged; pipeline proceeds without idempotency guarantee |

---

## Local Development

1. Copy `.env.example` → `.env` and fill in values.
2. Configure AWS credentials via `aws configure` or environment variables.
3. Run `make install-dev` to install all dependencies.
4. Run `make test` to validate everything works.
5. Run `make run-local` to simulate a Lambda invocation.

For integration testing against a real Elasticsearch cluster, set `ES_HOST` and credentials in `.env`.

---

## Monitoring

- **CloudWatch Logs**: all Lambda output is written to `/aws/lambda/{function-name}` in structured JSON format compatible with CloudWatch Insights.
- **CloudWatch Alarms**: two alarms are deployed automatically:
  - Error alarm: fires when any Lambda invocation returns an error.
  - Duration alarm: fires when average execution time exceeds 50 seconds.
- **X-Ray**: active tracing is enabled; view traces in the [X-Ray console](https://console.aws.amazon.com/xray/home).

### Sample CloudWatch Insights Query

```
fields @timestamp, level, message, anomaly_detected, yesterday_cost_usd, percentage_increase
| filter logger = "lambda_handler"
| sort @timestamp desc
| limit 20
```
