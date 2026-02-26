"""
payments-api/app.py — Payments service that fetches BancoSur API keys from Vault/AWS.

Key design patterns:
  - SecretsClient abstraction: switches between Vault and AWS via SECRETS_BACKEND env var
  - CredentialCache: holds current + previous key for zero-downtime rotation
  - /reload-credentials: hot-reloads key without service restart
  - Dual-credential window: in-flight payments using previous key complete normally

Production note: Graceful drain + swap (stop accepting new requests, wait for in-flight to
complete, then swap) is a production improvement not implemented here due to complexity.
"""
import hashlib
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

SECRETS_BACKEND = os.environ.get("SECRETS_BACKEND", "vault")
MOCK_PROVIDER_URL = os.environ.get("MOCK_PROVIDER_URL", "http://mock-provider:5003")
PREVIOUS_KEY_TTL = int(os.environ.get("PREVIOUS_KEY_TTL", "60"))


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit_log(action: str, result: str, metadata: dict | None = None) -> None:
    event = {
        "timestamp": utcnow(),
        "action": action,
        "actor": "payments-api",
        "resource": "pagos/providers/bancosur/api_key",
        "backend": SECRETS_BACKEND,
        "result": result,
        "metadata": metadata or {},
    }
    log.info(json.dumps(event))


# ============================================================
# Secrets Client
# ============================================================

class SecretsClient:
    """Fetches secrets from Vault (local demo) or AWS Secrets Manager (production)."""

    def __init__(self) -> None:
        self._backend = SECRETS_BACKEND

    def get_bancosur_api_key(self) -> str:
        if self._backend == "vault":
            return self._get_from_vault("secret/data/pagos/providers/bancosur/api_key", "api_key")
        elif self._backend == "aws":
            return self._get_from_aws("pagos/providers/bancosur/api_key", "api_key")
        raise ValueError(f"Unknown SECRETS_BACKEND: {self._backend}")

    def _get_from_vault(self, path: str, field: str) -> str:
        import hvac  # type: ignore

        vault_addr = os.environ.get("VAULT_ADDR", "http://vault:8200")
        client = hvac.Client(url=vault_addr)

        # Local demo: use root token directly (dev mode).
        # Production: use AppRole with credentials injected via Kubernetes
        # secrets or ECS task role — set VAULT_ROLE_ID_PAYMENTS_API and
        # VAULT_SECRET_ID_PAYMENTS_API instead of VAULT_TOKEN.
        token = os.environ.get("VAULT_TOKEN")
        role_id = os.environ.get("VAULT_ROLE_ID_PAYMENTS_API")
        if token:
            client.token = token
        elif role_id:
            secret_id = os.environ["VAULT_SECRET_ID_PAYMENTS_API"]
            client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        else:
            raise RuntimeError(
                "No Vault auth configured: set VAULT_TOKEN (demo) or "
                "VAULT_ROLE_ID_PAYMENTS_API + VAULT_SECRET_ID_PAYMENTS_API (production)"
            )

        secret = client.secrets.kv.v2.read_secret_version(
            path="pagos/providers/bancosur/api_key", mount_point="secret"
        )
        return secret["data"]["data"][field]

    def _get_from_aws(self, secret_name: str, field: str) -> str:
        import boto3
        from botocore.exceptions import ClientError

        sm = boto3.client("secretsmanager", region_name=os.environ.get("AWS_REGION", "us-east-1"))
        try:
            resp = sm.get_secret_value(SecretId=secret_name)
            data = json.loads(resp["SecretString"])
            return data[field]
        except ClientError as e:
            raise RuntimeError(f"AWS Secrets Manager error: {e}") from e


# ============================================================
# Credential Cache (dual-key for zero-downtime rotation)
# ============================================================

class CredentialCache:
    """
    Holds current and previous API key.

    During rotation:
      1. rotate(new_key) is called — sets previous = current, current = new_key
      2. In-flight requests using previous key continue for PREVIOUS_KEY_TTL seconds
      3. After TTL, previous is cleared (background thread)

    This mirrors real provider behavior (e.g., Stripe's key rotation).
    """

    def __init__(self) -> None:
        self.current: str = ""
        self.previous: str | None = None
        self._clear_timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def validate_request(self, key: str) -> bool:
        with self._lock:
            if key == self.current:
                return True
            if self.previous and key == self.previous:
                return True
            return False

    def rotate(self, new_key: str) -> None:
        with self._lock:
            if self._clear_timer:
                self._clear_timer.cancel()
            self.previous = self.current if self.current else None
            self.current = new_key
            if self.previous:
                self._clear_timer = threading.Timer(PREVIOUS_KEY_TTL, self._clear_previous)
                self._clear_timer.daemon = True
                self._clear_timer.start()

    def _clear_previous(self) -> None:
        with self._lock:
            self.previous = None
            log.info(json.dumps({
                "timestamp": utcnow(),
                "action": "previous_key_cleared",
                "actor": "payments-api",
                "resource": "pagos/providers/bancosur/api_key",
                "result": "success",
            }))


# ============================================================
# Application initialization
# ============================================================

secrets_client = SecretsClient()
cache = CredentialCache()


def load_initial_credentials() -> None:
    """Called at startup — fetches key from secrets backend."""
    max_retries = 5
    for attempt in range(1, max_retries + 1):
        try:
            key = secrets_client.get_bancosur_api_key()
            cache.rotate(key)
            audit_log("secret_read", "success", {"attempt": attempt, "startup": True})
            log.info(json.dumps({
                "timestamp": utcnow(),
                "action": "startup_credentials_loaded",
                "actor": "payments-api",
                "backend": SECRETS_BACKEND,
                "result": "success",
            }))
            return
        except Exception as e:
            log.warning(f"Attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                time.sleep(2 ** attempt)

    log.error("Failed to load credentials after all retries. Service may be degraded.")


# ============================================================
# Routes
# ============================================================

@app.get("/health")
def health():
    """Health check: validates current API key against mock-provider."""
    if not cache.current:
        return jsonify({"status": "degraded", "reason": "no_credentials_loaded"}), 503

    try:
        resp = requests.post(
            f"{MOCK_PROVIDER_URL}/bancosur/validate",
            json={"api_key": cache.current},
            timeout=5,
        )
        if resp.status_code == 200:
            audit_log("secret_read", "success", {"check": "health"})
            return jsonify({"status": "ok", "service": "payments-api"}), 200
        else:
            return jsonify({"status": "degraded", "reason": "key_invalid"}), 503
    except requests.RequestException as e:
        return jsonify({"status": "degraded", "reason": str(e)}), 503


@app.post("/payment")
def process_payment():
    """Process a payment using the current BancoSur API key."""
    if not cache.current:
        return jsonify({"error": "Service degraded — no credentials loaded"}), 503

    data = request.get_json(force=True, silent=True) or {}
    amount = data.get("amount")
    if not amount:
        return jsonify({"error": "amount required"}), 400

    try:
        resp = requests.post(
            f"{MOCK_PROVIDER_URL}/bancosur/validate",
            json={"api_key": cache.current},
            timeout=5,
        )
        if resp.status_code != 200:
            return jsonify({"error": "Payment provider rejected API key"}), 502

        audit_log("payment_processed", "success", {"amount": amount})
        return jsonify({"status": "processed", "amount": amount}), 200
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502


@app.post("/reload-credentials")
def reload_credentials():
    """
    Hot-reload API key from secrets backend — no service restart required.
    Called by the rotation script after storing the new key.
    """
    try:
        new_key = secrets_client.get_bancosur_api_key()
        cache.rotate(new_key)
        audit_log("secret_read", "success", {"trigger": "reload_credentials"})
        return jsonify({"status": "ok", "message": "Credentials reloaded"}), 200
    except Exception as e:
        audit_log("secret_read", "failure", {"error": str(e)})
        return jsonify({"error": str(e)}), 500


# ============================================================
# Startup
# ============================================================

with app.app_context():
    load_initial_credentials()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    app.run(host="0.0.0.0", port=port, debug=False)
