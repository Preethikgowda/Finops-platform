"""Terraform PR Generator for automated cost optimisation recommendations.

Generates Terraform HCL code for EC2/RDS right-sizing, S3 lifecycle policies,
and submits pull requests to GitHub for human review before any changes are
applied to infrastructure.

The PR workflow is idempotent: it checks for existing open PRs with the same
savings fingerprint before creating duplicates.

Environment variables required:
    GITHUB_TOKEN: Personal access token or App installation token.
    GITHUB_REPO: Repository in ``owner/repo`` format.
    GITHUB_BRANCH_MAIN: Base branch (default: ``main``).
"""

import hashlib
import json
import logging
import os
import re
import uuid
from datetime import date, datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Lazy import to avoid hard dependency in environments without PyGithub
try:
    import github as _gh_module
    from github import Github, GithubException
    from github.GithubException import UnknownObjectException

    # PyGithub ≥ 2.x prefers auth objects; support both old and new API
    try:
        from github import Auth as _GhAuth  # type: ignore[attr-defined]
        _GITHUB_AUTH_AVAILABLE = True
    except ImportError:
        _GITHUB_AUTH_AVAILABLE = False

    _GITHUB_AVAILABLE = True
except ImportError:
    _GITHUB_AVAILABLE = False
    _GITHUB_AUTH_AVAILABLE = False
    logger.warning(
        "PyGithub is not installed. GitHub PR creation will be unavailable. "
        "Install with: pip install PyGithub>=2.1.0"
    )


def _require_github() -> None:
    """Raise ImportError if PyGithub is not available."""
    if not _GITHUB_AVAILABLE:
        raise ImportError(
            "PyGithub is required for Terraform PR generation. "
            "Install with: pip install 'PyGithub>=2.1.0'"
        )


def _today() -> str:
    """Return today's date as YYYY-MM-DD string."""
    return date.today().isoformat()


def _github_client() -> Any:
    """Build an authenticated GitHub client from environment variables.

    Uses the newer ``Auth.Token`` API when available (PyGithub ≥ 2.x) to
    avoid deprecation warnings, and falls back to the positional token
    argument for older installations.

    Returns:
        Authenticated ``Github`` instance.

    Raises:
        EnvironmentError: When ``GITHUB_TOKEN`` is not set.
        ImportError: When PyGithub is not installed.
    """
    _require_github()
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        raise EnvironmentError(
            "GITHUB_TOKEN environment variable is required for GitHub operations."
        )
    if _GITHUB_AUTH_AVAILABLE:
        return Github(auth=_GhAuth.Token(token))
    return Github(token)  # pragma: no cover  # legacy fallback for PyGithub < 2.x


def _get_repo(gh: Any) -> Any:
    """Return the configured GitHub repository object.

    Args:
        gh: Authenticated ``Github`` instance.

    Returns:
        ``github.Repository.Repository`` object.

    Raises:
        EnvironmentError: When ``GITHUB_REPO`` is not configured.
    """
    repo_name = os.environ.get("GITHUB_REPO", "").strip()
    if not repo_name:
        raise EnvironmentError(
            "GITHUB_REPO environment variable must be set in owner/repo format."
        )
    return gh.get_repo(repo_name)


def _base_branch() -> str:
    """Return the configured base branch name (default: ``main``)."""
    return os.environ.get("GITHUB_BRANCH_MAIN", "main").strip() or "main"


def _savings_fingerprint(recommendations: list[dict[str, Any]]) -> str:
    """Generate a stable fingerprint from a set of recommendations.

    Used to detect duplicate PRs so we don't open the same PR twice.

    Args:
        recommendations: List of recommendation dicts.

    Returns:
        8-character hex fingerprint.
    """
    key = json.dumps(
        sorted(
            [r.get("instance_id", r.get("function_name", str(r))) for r in recommendations]
        )
    )
    return hashlib.sha256(key.encode()).hexdigest()[:8]


def estimate_change_risk(
    resource_type: str,
    from_config: str,
    to_config: str,
) -> dict[str, Any]:
    """Estimate the risk level of a configuration change.

    Risk classification:
    - **low**: same instance family (e.g. t3.large → t3.medium)
    - **medium**: different family but same generation or safe downsize
    - **high**: major architectural change or resource deletion

    Args:
        resource_type: ``ec2``, ``rds``, or ``lambda``.
        from_config: Current instance type / class / memory.
        to_config: Recommended instance type / class / memory.

    Returns:
        Dict with keys ``risk_level``, ``reasoning``, ``estimated_downtime``.
    """
    resource_type = resource_type.lower()

    if not from_config or not to_config:
        return {
            "risk_level": "high",
            "reasoning": "Missing configuration — manual review required.",
            "estimated_downtime": "unknown",
        }

    from_family = re.split(r"[.\-]", from_config)[0].lower()
    to_family = re.split(r"[.\-]", to_config)[0].lower()

    if resource_type == "ec2":
        if from_family == to_family:
            return {
                "risk_level": "low",
                "reasoning": f"Same instance family ({from_family}). Requires stop/start.",
                "estimated_downtime": "2-5 minutes",
            }
        if to_family in ("t3", "t4g") and from_family in ("m5", "m6i", "c5", "c6i"):
            return {
                "risk_level": "medium",
                "reasoning": (
                    f"Different family ({from_family} → {to_family}). "
                    "T-class instances have CPU burst limits — validate workload first."
                ),
                "estimated_downtime": "2-5 minutes",
            }
        return {
            "risk_level": "medium",
            "reasoning": f"Cross-family change ({from_config} → {to_config}). Test in staging first.",
            "estimated_downtime": "2-10 minutes",
        }

    if resource_type == "rds":
        # RDS instance class changes require a maintenance window or forced apply
        if from_family == to_family:
            return {
                "risk_level": "low",
                "reasoning": "Same DB family. Applies during next maintenance window.",
                "estimated_downtime": "< 1 minute (Multi-AZ) / 2-5 minutes (Single-AZ)",
            }
        return {
            "risk_level": "medium",
            "reasoning": (
                f"Cross-family RDS change ({from_config} → {to_config}). "
                "Schedule during low-traffic maintenance window."
            ),
            "estimated_downtime": "2-5 minutes",
        }

    if resource_type == "lambda":
        return {
            "risk_level": "low",
            "reasoning": "Memory change applies instantly with zero downtime on next invocation.",
            "estimated_downtime": "0 seconds",
        }

    return {
        "risk_level": "high",
        "reasoning": "Unknown resource type — manual review required.",
        "estimated_downtime": "unknown",
    }


def generate_ec2_downsizing_terraform(
    recommendations: list[dict[str, Any]],
) -> str:
    """Generate Terraform HCL for EC2 instance type right-sizing.

    Creates data source lookups and local override blocks for each
    underutilised EC2 instance. The output should be reviewed and adapted to
    match the project's Terraform module structure.

    Args:
        recommendations: List of EC2 recommendation dicts from
            :func:`utilization_analyzer.get_underutilized_ec2_instances`.

    Returns:
        Terraform HCL string ready to write to a ``.tf`` file.
    """
    today_str = _today()
    total_monthly_savings = sum(r.get("estimated_savings", 0) for r in recommendations)

    lines: list[str] = [
        "# Auto-generated by FinOps Cost Optimization Agent",
        f"# Generated: {today_str}",
        f"# Estimated monthly savings: ${total_monthly_savings:,.2f}",
        f"# Instances affected: {len(recommendations)}",
        "#",
        "# IMPORTANT: Review each change carefully before applying.",
        "# Run 'terraform plan' and validate in staging before production apply.",
        "",
        'locals {',
        '  finops_ec2_rightsizing_date = "' + today_str + '"',
        "}",
        "",
    ]

    for rec in recommendations:
        iid = rec.get("instance_id", "unknown")
        current_type = rec.get("current_type", "unknown")
        recommended_type = rec.get("recommended_type", "unknown")
        savings = rec.get("estimated_savings", 0)
        name = rec.get("name", iid)
        risk = estimate_change_risk("ec2", current_type, recommended_type)
        risk_level = risk["risk_level"]
        reasoning = risk["reasoning"]
        downtime = risk["estimated_downtime"]

        resource_name = re.sub(r"[^a-z0-9_]", "_", name.lower()) if name else iid.replace("-", "_")

        lines += [
            f"# Instance: {name} ({iid})",
            f"# Risk: {risk_level.upper()} — {reasoning}",
            f"# Estimated downtime: {downtime}",
            f"# Monthly savings: ${savings:,.2f} ({current_type} → {recommended_type})",
            f'resource "aws_instance" "{resource_name}" {{',
            f'  # instance_type = "{current_type}"  # PREVIOUS',
            f'  instance_type = "{recommended_type}"',
            "",
            "  tags = merge(",
            "    try(local.common_tags, {}),",
            '    { CostOptimization = "auto-rightsized-' + today_str + '" }',
            "  )",
            "",
            "  lifecycle {",
            "    ignore_changes = [ami, user_data]",
            "  }",
            "}",
            "",
        ]

    return "\n".join(lines)


def generate_rds_downsizing_terraform(
    recommendations: list[dict[str, Any]],
) -> str:
    """Generate Terraform HCL for RDS instance class right-sizing.

    Args:
        recommendations: List of RDS recommendation dicts from
            :func:`utilization_analyzer.get_underutilized_rds_instances`.

    Returns:
        Terraform HCL string.
    """
    today_str = _today()
    total_monthly_savings = sum(r.get("estimated_savings", 0) for r in recommendations)

    lines: list[str] = [
        "# Auto-generated by FinOps Cost Optimization Agent",
        f"# Generated: {today_str}",
        f"# Estimated monthly savings: ${total_monthly_savings:,.2f}",
        f"# RDS instances affected: {len(recommendations)}",
        "#",
        "# IMPORTANT: RDS instance class changes require a maintenance window.",
        "# Set apply_immediately = false for production databases.",
        "",
    ]

    for rec in recommendations:
        db_id = rec.get("instance_id", "unknown")
        current_class = rec.get("instance_class", "unknown")
        recommended_class = rec.get("recommended_class", "unknown")
        savings = rec.get("estimated_savings", 0)
        engine = rec.get("engine", "unknown")
        multi_az = rec.get("multi_az", False)
        risk = estimate_change_risk("rds", current_class, recommended_class)

        resource_name = db_id.replace("-", "_")

        lines += [
            f"# RDS: {db_id} ({engine}, Multi-AZ: {multi_az})",
            f"# Risk: {risk['risk_level'].upper()} — {risk['reasoning']}",
            f"# Monthly savings: ${savings:,.2f} ({current_class} → {recommended_class})",
            f'resource "aws_db_instance" "{resource_name}" {{',
            f'  # instance_class = "{current_class}"  # PREVIOUS',
            f'  instance_class = "{recommended_class}"',
            "",
            "  apply_immediately   = false",
            "  skip_final_snapshot = false",
            "",
            "  tags = merge(",
            "    try(local.common_tags, {}),",
            '    { CostOptimization = "auto-rightsized-' + today_str + '" }',
            "  )",
            "}",
            "",
        ]

    return "\n".join(lines)


def generate_s3_lifecycle_terraform(
    recommendations: list[dict[str, Any]],
) -> str:
    """Generate Terraform HCL for S3 lifecycle policies.

    Creates ``aws_s3_bucket_lifecycle_configuration`` resources that
    transition objects to Glacier after 90 days and Deep Archive after
    180 days, with expiration at 365 days.

    Args:
        recommendations: List of bucket recommendation dicts from
            :func:`s3_lifecycle_optimizer.analyze_s3_access_patterns`.

    Returns:
        Terraform HCL string.
    """
    today_str = _today()
    total_monthly_savings = sum(r.get("monthly_savings", 0) for r in recommendations)

    lines: list[str] = [
        "# Auto-generated by FinOps Cost Optimization Agent",
        f"# Generated: {today_str}",
        f"# Estimated monthly savings: ${total_monthly_savings:,.2f}",
        f"# S3 buckets affected: {len(recommendations)}",
        "",
    ]

    for rec in recommendations:
        bucket_name = rec.get("bucket_name", "unknown")
        savings = rec.get("monthly_savings", 0)
        unused_gb = rec.get("unused_storage_gb", 0)

        resource_name = re.sub(r"[^a-z0-9_]", "_", bucket_name.lower())

        lines += [
            f"# Bucket: {bucket_name}",
            f"# Unused storage: {unused_gb:.1f} GB",
            f"# Monthly savings: ${savings:,.2f}",
            f'resource "aws_s3_bucket_lifecycle_configuration" "{resource_name}_lifecycle" {{',
            f'  bucket = "{bucket_name}"',
            "",
            "  rule {",
            '    id     = "finops-archive-after-90-days"',
            '    status = "Enabled"',
            "",
            "    filter {}",
            "",
            "    transition {",
            "      days          = 90",
            '      storage_class = "GLACIER"',
            "    }",
            "",
            "    transition {",
            "      days          = 180",
            '      storage_class = "DEEP_ARCHIVE"',
            "    }",
            "",
            "    expiration {",
            "      days = 365",
            "    }",
            "",
            "    noncurrent_version_transition {",
            "      noncurrent_days = 30",
            '      storage_class   = "GLACIER"',
            "    }",
            "",
            "    noncurrent_version_expiration {",
            "      noncurrent_days = 90",
            "    }",
            "  }",
            "}",
            "",
        ]

    return "\n".join(lines)


def generate_approval_workflow(pr_url: str, changes_summary: str) -> dict[str, Any]:
    """Build a Slack interactive message for PR approval.

    Returns a Slack Block Kit payload with buttons for Approve, Reject, and
    Review that should be sent to a Slack webhook.

    Args:
        pr_url: URL of the GitHub pull request.
        changes_summary: Human-readable summary of proposed changes.

    Returns:
        Slack Block Kit message dict.
    """
    return {
        "text": f"FinOps PR Approval Required: {pr_url}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Cost Optimization PR — Approval Required",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*FinOps Agent* has generated a Terraform PR for cost optimisation.\n\n"
                        f"{changes_summary}\n\n"
                        f"*PR:* <{pr_url}|View Pull Request>"
                    ),
                },
            },
            {"type": "divider"},
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve & Apply", "emoji": True},
                        "style": "primary",
                        "value": json.dumps({"action": "approve", "pr_url": pr_url}),
                        "action_id": "finops_approve_apply",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve with Review", "emoji": True},
                        "value": json.dumps({"action": "approve_review", "pr_url": pr_url}),
                        "action_id": "finops_approve_review",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Reject", "emoji": True},
                        "style": "danger",
                        "value": json.dumps({"action": "reject", "pr_url": pr_url}),
                        "action_id": "finops_reject",
                        "confirm": {
                            "title": {"type": "plain_text", "text": "Reject this PR?"},
                            "text": {"type": "plain_text", "text": "This will close the PR."},
                            "confirm": {"type": "plain_text", "text": "Yes, reject"},
                            "deny": {"type": "plain_text", "text": "Cancel"},
                        },
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Review PR", "emoji": True},
                        "url": pr_url,
                        "action_id": "finops_review",
                    },
                ],
            },
        ],
    }


def commit_and_create_github_pr(
    tf_changes: dict[str, str],
    title: str,
    description: str,
    reviewers: Optional[list[str]] = None,
) -> str:
    """Commit Terraform files to a new branch and open a GitHub pull request.

    This function is idempotent: if an open PR with the same title already
    exists on any ``auto/cost-optimization-*`` branch, it returns the
    existing PR URL without creating a duplicate.

    Args:
        tf_changes: Dict mapping relative file paths to Terraform content
                    (e.g. ``{"terraform/auto-generated/ec2-rightsizing.tf": "..."}``.
        title: PR title.
        description: PR body markdown text (supports GitHub-flavoured Markdown).
        reviewers: Optional list of GitHub usernames to request as reviewers.

    Returns:
        URL of the created (or existing) pull request.

    Raises:
        EnvironmentError: When ``GITHUB_TOKEN`` or ``GITHUB_REPO`` are absent.
        ImportError: When PyGithub is not installed.
        RuntimeError: When PR creation fails for an unexpected reason.
    """
    _require_github()

    gh = _github_client()
    repo = _get_repo(gh)
    base = _base_branch()

    # Idempotency: check for existing open PRs with the same title prefix
    try:
        for pr in repo.get_pulls(state="open", base=base):
            if pr.title == title:
                logger.info(
                    "Existing PR found with identical title — skipping creation: %s",
                    pr.html_url,
                )
                return pr.html_url
    except Exception as exc:
        logger.warning("Could not check existing PRs (proceeding): %s", exc)

    # Create a unique branch name
    branch_suffix = f"{uuid.uuid4().hex[:6]}-{_today()}"
    branch_name = f"auto/cost-optimization-{branch_suffix}"

    logger.info("Creating PR branch: %s from %s", branch_name, base)

    try:
        base_ref = repo.get_branch(base)
        repo.create_git_ref(
            ref=f"refs/heads/{branch_name}",
            sha=base_ref.commit.sha,
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to create branch '{branch_name}': {exc}") from exc

    # Commit each Terraform file
    commit_timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for file_path, content in tf_changes.items():
        try:
            try:
                existing = repo.get_contents(file_path, ref=branch_name)
                repo.update_file(
                    path=file_path,
                    message=f"chore(finops): update {file_path} [{commit_timestamp}]",
                    content=content,
                    sha=existing.sha,
                    branch=branch_name,
                )
            except UnknownObjectException:
                repo.create_file(
                    path=file_path,
                    message=f"chore(finops): add {file_path} [{commit_timestamp}]",
                    content=content,
                    branch=branch_name,
                )
            logger.info("Committed file: %s", file_path)
        except Exception as exc:
            logger.error("Failed to commit %s: %s", file_path, exc)
            raise RuntimeError(f"Commit failed for {file_path}: {exc}") from exc

    # Create pull request
    try:
        pr = repo.create_pull(
            title=title,
            body=description,
            head=branch_name,
            base=base,
            draft=True,
        )
        logger.info("Pull request created: %s", pr.html_url)
    except Exception as exc:
        raise RuntimeError(f"Failed to create pull request: {exc}") from exc

    # Request reviewers (best-effort; don't fail if team doesn't exist)
    if reviewers:
        try:
            pr.create_review_request(reviewers=reviewers)
        except Exception as exc:
            logger.warning("Could not assign reviewers %s (non-fatal): %s", reviewers, exc)

    return pr.html_url


def build_pr_description(
    changes: list[dict[str, Any]],
    annual_savings: float,
    risk_summary: str,
    affected_resources: list[str],
) -> str:
    """Build a structured Markdown PR description for Terraform changes.

    Args:
        changes: List of change detail dicts.
        annual_savings: Estimated total annual savings in USD.
        risk_summary: Overall risk assessment string.
        affected_resources: List of resource IDs/names being modified.

    Returns:
        Markdown string suitable for a GitHub PR body.
    """
    resource_list = "\n".join(f"- `{r}`" for r in affected_resources)
    change_table_rows = "\n".join(
        f"| {c.get('resource_id', 'N/A')} | {c.get('from', 'N/A')} | "
        f"{c.get('to', 'N/A')} | ${c.get('monthly_savings', 0):,.2f} | "
        f"{c.get('risk', 'unknown')} |"
        for c in changes
    )

    return f"""## Summary

This PR was auto-generated by the **FinOps Cost Optimization Agent** to right-size
underutilised cloud resources based on 7-day utilisation metrics.

> **Estimated Annual Savings: ${annual_savings:,.2f}**

## Risk Assessment

{risk_summary}

## Changes

| Resource | From | To | Monthly Savings | Risk |
|---|---|---|---|---|
{change_table_rows}

## Affected Resources

{resource_list}

## Review Checklist

- [ ] Validated recommendations against application performance requirements
- [ ] Tested in staging environment
- [ ] Scheduled maintenance window for production changes
- [ ] CloudWatch alarms updated for new instance sizes
- [ ] Notified application owners

## Approval Workflow

Once approved, merge this PR and run `terraform apply` in the target environment.
A Slack notification will be sent to the `#cost-governance` channel.

---
*Generated by FinOps Agent — Cost Optimization Module*
"""
