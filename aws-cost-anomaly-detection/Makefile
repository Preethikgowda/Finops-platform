.PHONY: install install-dev test test-cov lint format typecheck clean build deploy logs invoke help

PYTHON      := python3
PIP         := pip3
SRC_DIR     := src
TEST_DIR    := tests
DIST_DIR    := dist
TF_DIR      := terraform
FUNCTION    := $(shell cd $(TF_DIR) && terraform output -raw lambda_function_name 2>/dev/null || echo "cost-anomaly-detector-prod")
AWS_REGION  := $(shell grep '^aws_region' $(TF_DIR)/terraform.tfvars 2>/dev/null | awk -F'"' '{print $$2}' || echo "us-east-1")

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

install: ## Install production dependencies
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

install-dev: ## Install all dependencies including dev/test tools
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements-dev.txt

# ---------------------------------------------------------------------------
# Code quality
# ---------------------------------------------------------------------------

lint: ## Run flake8 linter
	flake8 $(SRC_DIR) $(TEST_DIR) --max-line-length=110 --extend-ignore=E203,W503

format: ## Auto-format code with black
	black $(SRC_DIR) $(TEST_DIR) --line-length=110

format-check: ## Check formatting without modifying files
	black $(SRC_DIR) $(TEST_DIR) --check --line-length=110

typecheck: ## Run mypy type checking
	mypy $(SRC_DIR) --ignore-missing-imports --python-version=3.11

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test: ## Run all unit tests
	PYTHONPATH=$(SRC_DIR) pytest $(TEST_DIR) -v --tb=short

test-cov: ## Run tests with HTML coverage report (must be ≥80%)
	PYTHONPATH=$(SRC_DIR) pytest $(TEST_DIR) \
		--cov=$(SRC_DIR) \
		--cov-report=term-missing \
		--cov-report=html:htmlcov \
		--cov-fail-under=80 \
		-v

test-unit: ## Run tests for a specific module (e.g. make test-unit MOD=cost_analyzer)
	PYTHONPATH=$(SRC_DIR) pytest $(TEST_DIR)/test_$(MOD).py -v --tb=long

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

build: ## Package Lambda function source into a zip file
	@mkdir -p $(DIST_DIR)
	@echo "Building Lambda deployment package..."
	$(PIP) install -r requirements.txt --target $(DIST_DIR)/python_deps --upgrade --quiet
	cd $(DIST_DIR)/python_deps && zip -r9q ../../$(DIST_DIR)/lambda_package.zip . 2>/dev/null || true
	cd $(SRC_DIR) && zip -r9q ../$(DIST_DIR)/lambda_package.zip .
	@echo "Build complete: $(DIST_DIR)/lambda_package.zip"
	@ls -lh $(DIST_DIR)/lambda_package.zip

# ---------------------------------------------------------------------------
# Terraform / Deploy
# ---------------------------------------------------------------------------

tf-init: ## Initialise Terraform working directory
	cd $(TF_DIR) && terraform init

tf-plan: ## Show Terraform execution plan
	cd $(TF_DIR) && terraform plan -out=tfplan

tf-apply: ## Apply Terraform plan (prompts for confirmation)
	cd $(TF_DIR) && terraform apply tfplan

deploy: tf-init tf-plan tf-apply ## Full deployment: init → plan → apply

tf-destroy: ## Destroy all Terraform-managed resources (dangerous!)
	@echo "WARNING: This will destroy all resources. Press Ctrl+C to abort."
	@sleep 5
	cd $(TF_DIR) && terraform destroy

# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

invoke: ## Manually invoke the Lambda function (requires AWS credentials)
	aws lambda invoke \
		--function-name $(FUNCTION) \
		--region $(AWS_REGION) \
		--payload '{}' \
		--cli-binary-format raw-in-base64-out \
		/tmp/lambda_response.json && \
	cat /tmp/lambda_response.json | python3 -m json.tool

logs: ## Tail live CloudWatch logs for the Lambda function
	aws logs tail /aws/lambda/$(FUNCTION) \
		--region $(AWS_REGION) \
		--follow \
		--format short

logs-last: ## Show the last 60 minutes of Lambda logs
	aws logs filter-log-events \
		--log-group-name /aws/lambda/$(FUNCTION) \
		--region $(AWS_REGION) \
		--start-time $$(date -d '-60 minutes' +%s000 2>/dev/null || date -v-60M +%s000) \
		--query 'events[].message' \
		--output text

# ---------------------------------------------------------------------------
# Local development
# ---------------------------------------------------------------------------

run-local: ## Run the Lambda handler locally (requires .env file)
	PYTHONPATH=$(SRC_DIR) $(PYTHON) -c "\
import json, sys; \
sys.path.insert(0, '$(SRC_DIR)'); \
from lambda_handler import handler; \
result = handler({}, type('Ctx', (), {'aws_request_id': 'local-test'})());\
print(json.dumps(json.loads(result['body']), indent=2))"

env-check: ## Validate .env file against .env.example
	@echo "Checking .env against .env.example..."
	@python3 -c "\
import re, sys; \
required = [l.split('=')[0].strip() for l in open('.env.example') \
  if l.strip() and not l.startswith('#') and '=' in l]; \
try: \
  current = [l.split('=')[0].strip() for l in open('.env') \
    if l.strip() and not l.startswith('#') and '=' in l] \
except FileNotFoundError: \
  print('ERROR: .env file not found. Copy .env.example to .env'); sys.exit(1); \
missing = [v for v in required if v not in current]; \
print(f'Missing variables: {missing}') if missing else print('All required variables present.');"

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

clean: ## Remove build artifacts and cached files
	rm -rf $(DIST_DIR) htmlcov .coverage .mypy_cache .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	@echo "Cleaned."
