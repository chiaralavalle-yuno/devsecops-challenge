"""
rotation/backends/vault_backend.py — HashiCorp Vault backend using hvac.

This is the LOCAL DEMO backend. Production uses aws_backend.py.

Authentication: AppRole (role_id + secret_id from environment variables)
Secret engine: KV v2 at mount point "secret"
Rollback: writes previous version's data as a new KV entry

Note: Vault's own audit device captures all API-level operations independently.
This backend additionally writes structured events to audit/audit.log in the
unified format for cross-backend SIEM forwarding.
"""
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import hvac  # type: ignore
except ImportError:
    hvac = None  # type: ignore

from rotation.backends import SecretsBackend

log = logging.getLogger(__name__)

AUDIT_LOG_PATH = Path(__file__).parent.parent.parent / "audit" / "audit.log"
MOUNT_POINT = "secret"


class VaultBackend(SecretsBackend):
    """
    Vault KV v2 secrets backend.

    Authenticates via AppRole using:
      VAULT_ADDR, VAULT_ROLE_ID_ROTATION_AGENT, VAULT_SECRET_ID_ROTATION_AGENT
    """

    def __init__(self) -> None:
        if hvac is None:
            raise ImportError("hvac is required for VaultBackend: pip install hvac")

        self.vault_addr = os.environ.get("VAULT_ADDR", "http://localhost:8200")
        self.role_id = os.environ.get("VAULT_ROLE_ID_ROTATION_AGENT")
        self.secret_id = os.environ.get("VAULT_SECRET_ID_ROTATION_AGENT")
        self._client: hvac.Client | None = None

    def _get_client(self) -> "hvac.Client":
        """Return an authenticated Vault client, re-authenticating if needed."""
        if self._client is None or not self._client.is_authenticated():
            client = hvac.Client(url=self.vault_addr)
            if self.role_id and self.secret_id:
                client.auth.approle.login(
                    role_id=self.role_id,
                    secret_id=self.secret_id,
                )
            else:
                # Fallback for local dev: use VAULT_TOKEN
                token = os.environ.get("VAULT_TOKEN", "root")
                client.token = token
            self._client = client
        return self._client

    def get_secret(self, path: str) -> dict[str, Any]:
        client = self._get_client()
        response = client.secrets.kv.v2.read_secret_version(
            path=path, mount_point=MOUNT_POINT, raise_on_deleted_version=True
        )
        return response["data"]["data"]

    def put_secret(self, path: str, data: dict[str, Any]) -> None:
        client = self._get_client()
        client.secrets.kv.v2.create_or_update_secret(
            path=path, secret=data, mount_point=MOUNT_POINT
        )

    def get_previous_version(self, path: str) -> dict[str, Any] | None:
        """Fetch version N-1 of a secret."""
        client = self._get_client()
        try:
            # Get current metadata to find current version number
            metadata = client.secrets.kv.v2.read_secret_metadata(
                path=path, mount_point=MOUNT_POINT
            )
            current_version = metadata["data"]["current_version"]
            if current_version <= 1:
                return None  # No previous version

            prev_version = current_version - 1
            response = client.secrets.kv.v2.read_secret_version(
                path=path,
                version=prev_version,
                mount_point=MOUNT_POINT,
                raise_on_deleted_version=False,
            )
            if response and response.get("data", {}).get("data"):
                return response["data"]["data"]
            return None
        except Exception as e:
            log.warning(f"Could not fetch previous version for {path}: {e}")
            return None

    def rollback_secret(self, path: str) -> None:
        """Write previous version's data as a new current version."""
        prev_data = self.get_previous_version(path)
        if prev_data is None:
            raise RuntimeError(f"No previous version found for {path} — cannot rollback")
        self.put_secret(path, prev_data)
        log.info(f"Rolled back {path} to previous version")

    def write_audit_event(self, event: dict[str, Any]) -> None:
        """Append a structured JSON audit event to audit/audit.log."""
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "backend" not in event:
            event["backend"] = "vault"

        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")
