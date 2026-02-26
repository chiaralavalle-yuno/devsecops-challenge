"""
rotation/backends/aws_backend.py — AWS Secrets Manager backend using boto3.

This is the PRIMARY PRODUCTION backend.

Authentication: boto3 credential chain (SSO, instance role, env vars, ~/.aws/credentials)
Versioning: uses AWSCURRENT / AWSPREVIOUS staging labels
Rollback: promotes AWSPREVIOUS stage to AWSCURRENT
Audit: writes to audit/audit.log + CloudWatch Logs /pagos/rotation-audit

Why AWS Secrets Manager for PCI-DSS:
  - KMS encryption at rest (Req 3.5)
  - TLS in transit (Req 4.1)
  - IAM role-based access (Req 8.2 — unique credentials per service)
  - CloudTrail captures every GetSecretValue call (Req 10.2)
  - Native versioning for rotation rollback
"""
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None  # type: ignore
    ClientError = Exception  # type: ignore

from rotation.backends import SecretsBackend

log = logging.getLogger(__name__)

AUDIT_LOG_PATH = Path(__file__).parent.parent.parent / "audit" / "audit.log"
CLOUDWATCH_LOG_GROUP = "/pagos/rotation-audit"
CLOUDWATCH_LOG_STREAM = "rotation-script"


class AWSBackend(SecretsBackend):
    """
    AWS Secrets Manager backend.

    Reads credentials from the boto3 credential chain:
      1. Environment: AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
      2. AWS SSO profile
      3. EC2/ECS instance role
      4. ~/ .aws/credentials (never for production workloads)
    """

    def __init__(self, region: str | None = None, profile: str | None = None) -> None:
        if boto3 is None:
            raise ImportError("boto3 is required for AWSBackend: pip install boto3")

        self._region = region or os.environ.get("AWS_REGION", "us-east-1")
        session_kwargs: dict[str, Any] = {"region_name": self._region}
        if profile:
            session_kwargs["profile_name"] = profile

        self._session = boto3.Session(**session_kwargs)
        self._sm = self._session.client("secretsmanager")
        self._logs: Any = None  # Lazy init for CloudWatch

    def get_secret(self, path: str) -> dict[str, Any]:
        try:
            resp = self._sm.get_secret_value(SecretId=path)
            return json.loads(resp["SecretString"])
        except ClientError as e:
            raise RuntimeError(f"Failed to get secret {path}: {e}") from e

    def put_secret(self, path: str, data: dict[str, Any]) -> None:
        try:
            self._sm.put_secret_value(
                SecretId=path,
                SecretString=json.dumps(data),
                VersionStages=["AWSCURRENT"],
            )
        except ClientError as e:
            raise RuntimeError(f"Failed to put secret {path}: {e}") from e

    def get_previous_version(self, path: str) -> dict[str, Any] | None:
        """Fetch the AWSPREVIOUS staged version of a secret."""
        try:
            versions = self._sm.list_secret_version_ids(SecretId=path)["Versions"]
            for version in versions:
                if "AWSPREVIOUS" in version.get("VersionStages", []):
                    resp = self._sm.get_secret_value(
                        SecretId=path, VersionId=version["VersionId"]
                    )
                    return json.loads(resp["SecretString"])
            return None
        except ClientError as e:
            log.warning(f"Could not fetch previous version for {path}: {e}")
            return None

    def rollback_secret(self, path: str) -> None:
        """Promote AWSPREVIOUS to AWSCURRENT via version stage manipulation."""
        try:
            versions = self._sm.list_secret_version_ids(SecretId=path)["Versions"]

            current_version_id = None
            previous_version_id = None

            for version in versions:
                stages = version.get("VersionStages", [])
                if "AWSCURRENT" in stages:
                    current_version_id = version["VersionId"]
                if "AWSPREVIOUS" in stages:
                    previous_version_id = version["VersionId"]

            if not previous_version_id:
                raise RuntimeError(f"No AWSPREVIOUS version found for {path} — cannot rollback")

            # Promote AWSPREVIOUS to AWSCURRENT
            self._sm.update_secret_version_stage(
                SecretId=path,
                VersionStage="AWSCURRENT",
                MoveToVersionId=previous_version_id,
                RemoveFromVersionId=current_version_id,
            )
            log.info(f"Rolled back {path}: promoted {previous_version_id} to AWSCURRENT")
        except ClientError as e:
            raise RuntimeError(f"Failed to rollback secret {path}: {e}") from e

    def write_audit_event(self, event: dict[str, Any]) -> None:
        """Write audit event to audit/audit.log and CloudWatch Logs."""
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "backend" not in event:
            event["backend"] = "aws"

        # Write to local audit log
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")

        # Write to CloudWatch Logs (best-effort — don't fail rotation on CW error)
        self._write_to_cloudwatch(event)

    def _write_to_cloudwatch(self, event: dict[str, Any]) -> None:
        """Push event to CloudWatch Logs (best-effort)."""
        try:
            if self._logs is None:
                self._logs = self._session.client("logs")
                # Ensure log group exists
                try:
                    self._logs.create_log_group(logGroupName=CLOUDWATCH_LOG_GROUP)
                except ClientError as e:
                    if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
                        raise
                try:
                    self._logs.create_log_stream(
                        logGroupName=CLOUDWATCH_LOG_GROUP,
                        logStreamName=CLOUDWATCH_LOG_STREAM,
                    )
                except ClientError as e:
                    if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
                        raise

            self._logs.put_log_events(
                logGroupName=CLOUDWATCH_LOG_GROUP,
                logStreamName=CLOUDWATCH_LOG_STREAM,
                logEvents=[
                    {
                        "timestamp": int(
                            datetime.now(timezone.utc).timestamp() * 1000
                        ),
                        "message": json.dumps(event),
                    }
                ],
            )
        except Exception as e:
            # CloudWatch failure should not abort rotation
            log.warning(f"CloudWatch audit write failed (non-fatal): {e}")
