#!/usr/bin/env python3
"""
setup-aws.py — Seeds AWS Secrets Manager with Pagos secrets and creates IAM policies/roles.

Usage:
    python aws/setup-aws.py                          # Create secrets + policies
    python aws/setup-aws.py --create-test-user       # Also create IAM user for local testing
    python aws/setup-aws.py --profile admin-won-dev  # Use named AWS profile
    python aws/setup-aws.py --region us-west-2       # Specify region

Requirements:
    pip install boto3

AWS credentials are read from the environment (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY),
~/.aws/credentials, or EC2/ECS instance role. Never hardcode credentials here.
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

DEFINITIONS_FILE = Path(__file__).parent / "secrets-definitions.json"
POLICIES_DIR = Path(__file__).parent / "iam-policies"
ACCOUNT_ALIAS = "pagos-demo"


def get_account_id(session: boto3.Session) -> str:
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]


def create_or_update_secret(
    sm_client, name: str, description: str, value: dict, tags: dict
) -> None:
    """Create a secret in AWS Secrets Manager, or update it if it already exists."""
    tag_list = [{"Key": k, "Value": v} for k, v in tags.items()]
    secret_string = json.dumps(value)

    try:
        sm_client.describe_secret(SecretId=name)
        # Secret exists — update value
        sm_client.put_secret_value(SecretId=name, SecretString=secret_string)
        sm_client.tag_resource(SecretId=name, Tags=tag_list)
        log.info(f"  Updated secret: {name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            # Secret doesn't exist — create it
            sm_client.create_secret(
                Name=name,
                Description=description,
                SecretString=secret_string,
                Tags=tag_list,
            )
            log.info(f"  Created secret: {name}")
        else:
            raise


def create_or_update_policy(
    iam_client, policy_name: str, policy_document: dict, account_id: str
) -> str:
    """Create an IAM policy or update it with a new version. Returns policy ARN."""
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    policy_json = json.dumps(policy_document, indent=2)

    try:
        iam_client.get_policy(PolicyArn=policy_arn)
        # Policy exists — create new version (max 5 versions, delete oldest if needed)
        versions = iam_client.list_policy_versions(PolicyArn=policy_arn)["Versions"]
        non_default = [v for v in versions if not v["IsDefaultVersion"]]
        if len(versions) >= 5:
            oldest = sorted(non_default, key=lambda v: v["CreateDate"])[0]
            iam_client.delete_policy_version(
                PolicyArn=policy_arn, VersionId=oldest["VersionId"]
            )
        iam_client.create_policy_version(
            PolicyArn=policy_arn, PolicyDocument=policy_json, SetAsDefault=True
        )
        log.info(f"  Updated policy: {policy_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchEntity", "NoSuchEntityException"):
            iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=policy_json,
                Description=f"Pagos DevSecOps — {policy_name}",
            )
            log.info(f"  Created policy: {policy_name}")
        else:
            raise

    return policy_arn


def create_service_role(
    iam_client, role_name: str, policy_arn: str, description: str
) -> None:
    """Create an IAM role with EC2/ECS trust and attach the given policy."""
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": ["ec2.amazonaws.com", "ecs-tasks.amazonaws.com"]},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )

    try:
        iam_client.get_role(RoleName=role_name)
        log.info(f"  Role already exists: {role_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=trust_policy,
                Description=description,
                Tags=[{"Key": "Project", "Value": "pagos-devsecops"}],
            )
            log.info(f"  Created role: {role_name}")
        else:
            raise

    # Attach policy (idempotent)
    try:
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        log.info(f"  Attached {policy_arn} to {role_name}")
    except ClientError as e:
        if "already attached" not in str(e).lower():
            raise


def create_test_user(iam_client, username: str, policy_arns: list[str]) -> None:
    """Create an IAM user for local testing (not for production)."""
    log.warning(f"Creating IAM test user: {username} (NOT for production use)")
    try:
        iam_client.create_user(
            UserName=username,
            Tags=[
                {"Key": "Project", "Value": "pagos-devsecops"},
                {"Key": "Purpose", "Value": "local-testing-only"},
            ],
        )
        log.info(f"  Created user: {username}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            log.info(f"  User already exists: {username}")
        else:
            raise

    for arn in policy_arns:
        iam_client.attach_user_policy(UserName=username, PolicyArn=arn)
        log.info(f"  Attached {arn} to {username}")

    # Create access keys for local testing
    keys = iam_client.create_access_key(UserName=username)["AccessKey"]
    log.info(f"  Access Key ID: {keys['AccessKeyId']}")
    log.warning(f"  SECRET KEY (shown once): {keys['SecretAccessKey']}")
    log.warning("  Store this in your .env file immediately — it cannot be retrieved again!")


def main() -> None:
    parser = argparse.ArgumentParser(description="Set up AWS resources for Pagos demo")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument(
        "--create-test-user",
        action="store_true",
        help="Create IAM test user for local development (NOT for production)",
    )
    args = parser.parse_args()

    # Build session
    session_kwargs: dict = {"region_name": args.region}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    session = boto3.Session(**session_kwargs)

    account_id = get_account_id(session)
    log.info(f"AWS Account: {account_id}, Region: {args.region}")

    sm_client = session.client("secretsmanager")
    iam_client = session.client("iam")

    # ----------------------------------------------------------------
    # 1. Create secrets
    # ----------------------------------------------------------------
    log.info("\n==> Creating/updating secrets in AWS Secrets Manager...")
    definitions = json.loads(DEFINITIONS_FILE.read_text())
    for secret_def in definitions["secrets"]:
        if secret_def.get("_comment"):
            continue
        create_or_update_secret(
            sm_client,
            name=secret_def["name"],
            description=secret_def["description"],
            value=secret_def["value"],
            tags=secret_def.get("tags", {}),
        )

    # ----------------------------------------------------------------
    # 2. Create IAM policies
    # ----------------------------------------------------------------
    log.info("\n==> Creating/updating IAM policies...")
    policy_arns: dict[str, str] = {}

    for policy_file in sorted(POLICIES_DIR.glob("*.json")):
        policy_doc = json.loads(policy_file.read_text())
        if "_comment" in policy_doc:
            del policy_doc["_comment"]
        policy_name = f"pagos-{policy_file.stem}"
        arn = create_or_update_policy(iam_client, policy_name, policy_doc, account_id)
        policy_arns[policy_file.stem] = arn

    # ----------------------------------------------------------------
    # 3. Create IAM roles
    # ----------------------------------------------------------------
    log.info("\n==> Creating IAM roles...")
    roles = [
        ("pagos-payments-api", policy_arns.get("payments-api-policy"), "Pagos payments-api service role"),
        ("pagos-webhooks-service", policy_arns.get("webhooks-service-policy"), "Pagos webhooks-service role"),
        ("pagos-rotation-agent", policy_arns.get("rotation-agent-policy"), "Pagos rotation-agent role"),
    ]
    for role_name, policy_arn, description in roles:
        if policy_arn:
            create_service_role(iam_client, role_name, policy_arn, description)

    # ----------------------------------------------------------------
    # 4. Optionally create test user
    # ----------------------------------------------------------------
    if args.create_test_user:
        log.info("\n==> Creating test IAM user...")
        all_policy_arns = list(policy_arns.values())
        create_test_user(iam_client, "pagos-local-test", all_policy_arns)

    log.info("\n==> AWS setup complete!")
    log.info("    Run 'python rotation/rotate.py --backend aws' to test rotation.")
    log.info("    CloudTrail audit: AWS Console → CloudTrail → Event history → filter by pagos/")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.error(f"Setup failed: {e}")
        sys.exit(1)
