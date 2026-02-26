"""
webhooks-service/app.py — Webhook receiver that validates WalletPro HMAC signatures.

Fetches the webhook secret from Vault/AWS and validates the X-WalletPro-Signature header.
Supports dual-credential window for zero-downtime rotation.
"""
import hashlib
import hmac
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
        "actor": "webhooks-service",
        "resource": "pagos/providers/walletpro/webhook_secret",
        "backend": SECRETS_BACKEND,
        "result": result,
        "metadata": metadata or {},
    }
    log.info(json.dumps(event))


# ============================================================
# Secrets Client
# ============================================================

class SecretsClient:
    def __init__(self) -> None:
        self._backend = SECRETS_BACKEND

    def get_walletpro_webhook_secret(self) -> str:
        if self._backend == "vault":
            return self._get_from_vault(
                "secret/data/pagos/providers/walletpro/webhook_secret", "webhook_secret"
            )
        elif self._backend == "aws":
            return self._get_from_aws(
                "pagos/providers/walletpro/webhook_secret", "webhook_secret"
            )
        raise ValueError(f"Unknown SECRETS_BACKEND: {self._backend}")

    def _get_from_vault(self, path: str, field: str) -> str:
        import hvac  # type: ignore

        vault_addr = os.environ.get("VAULT_ADDR", "http://vault:8200")
        client = hvac.Client(url=vault_addr)

        # Local demo: use root token directly (dev mode).
        # Production: use AppRole with credentials injected via Kubernetes
        # secrets or ECS task role — set VAULT_ROLE_ID_WEBHOOKS_SERVICE and
        # VAULT_SECRET_ID_WEBHOOKS_SERVICE instead of VAULT_TOKEN.
        token = os.environ.get("VAULT_TOKEN")
        role_id = os.environ.get("VAULT_ROLE_ID_WEBHOOKS_SERVICE")
        if token:
            client.token = token
        elif role_id:
            secret_id = os.environ["VAULT_SECRET_ID_WEBHOOKS_SERVICE"]
            client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        else:
            raise RuntimeError(
                "No Vault auth configured: set VAULT_TOKEN (demo) or "
                "VAULT_ROLE_ID_WEBHOOKS_SERVICE + VAULT_SECRET_ID_WEBHOOKS_SERVICE (production)"
            )

        secret = client.secrets.kv.v2.read_secret_version(
            path="pagos/providers/walletpro/webhook_secret", mount_point="secret"
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

class WebhookSecretCache:
    """Same dual-credential pattern as payments-api, adapted for webhook secrets."""

    def __init__(self) -> None:
        self.current: str = ""
        self.previous: str | None = None
        self._clear_timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def validate_hmac(self, payload: str, signature: str) -> tuple[bool, str]:
        """Returns (is_valid, reason). Tries current secret first, then previous."""
        with self._lock:
            if self._check_hmac(payload, self.current, signature):
                return True, "current"
            if self.previous and self._check_hmac(payload, self.previous, signature):
                return True, "previous_in_window"
        return False, "invalid_signature"

    @staticmethod
    def _check_hmac(payload: str, secret: str, signature: str) -> bool:
        if not secret:
            return False
        expected = hmac.new(
            secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    def rotate(self, new_secret: str) -> None:
        with self._lock:
            if self._clear_timer:
                self._clear_timer.cancel()
            self.previous = self.current if self.current else None
            self.current = new_secret
            if self.previous:
                self._clear_timer = threading.Timer(PREVIOUS_KEY_TTL, self._clear_previous)
                self._clear_timer.daemon = True
                self._clear_timer.start()

    def _clear_previous(self) -> None:
        with self._lock:
            self.previous = None


# ============================================================
# Application initialization
# ============================================================

secrets_client = SecretsClient()
cache = WebhookSecretCache()


def load_initial_credentials() -> None:
    max_retries = 5
    for attempt in range(1, max_retries + 1):
        try:
            secret = secrets_client.get_walletpro_webhook_secret()
            cache.rotate(secret)
            audit_log("secret_read", "success", {"attempt": attempt, "startup": True})
            return
        except Exception as e:
            log.warning(f"Attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                time.sleep(2 ** attempt)

    log.error("Failed to load webhook secret after all retries.")


# ============================================================
# Routes
# ============================================================

@app.get("/health")
def health():
    """Health check: validates current webhook secret against mock-provider."""
    if not cache.current:
        return jsonify({"status": "degraded", "reason": "no_credentials_loaded"}), 503

    test_payload = '{"type":"health_check"}'
    test_sig = hmac.new(
        cache.current.encode(), test_payload.encode(), hashlib.sha256
    ).hexdigest()

    try:
        resp = requests.post(
            f"{MOCK_PROVIDER_URL}/walletpro/validate-hmac",
            json={"payload": test_payload, "signature": test_sig},
            timeout=5,
        )
        if resp.status_code == 200:
            return jsonify({"status": "ok", "service": "webhooks-service"}), 200
        return jsonify({"status": "degraded", "reason": "hmac_validation_failed"}), 503
    except requests.RequestException as e:
        return jsonify({"status": "degraded", "reason": str(e)}), 503


@app.post("/webhook")
def receive_webhook():
    """
    Receive a WalletPro webhook and validate its HMAC-SHA256 signature.
    Expected header: X-WalletPro-Signature: sha256=<hex>
    """
    signature_header = request.headers.get("X-WalletPro-Signature", "")
    if not signature_header.startswith("sha256="):
        return jsonify({"error": "Missing or invalid signature header"}), 400

    signature = signature_header.removeprefix("sha256=")
    payload = request.get_data(as_text=True)

    valid, reason = cache.validate_hmac(payload, signature)

    if not valid:
        audit_log("webhook_validation", "failure", {
            "reason": reason, "client_ip": request.remote_addr
        })
        return jsonify({"error": "Invalid webhook signature"}), 401

    audit_log("webhook_validation", "success", {"reason": reason})

    # Parse and process the webhook event
    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON payload"}), 400

    event_type = event.get("type", "unknown")
    log.info(f"Processed webhook event: {event_type}")

    return jsonify({"status": "accepted", "event_type": event_type}), 200


@app.post("/reload-credentials")
def reload_credentials():
    """Hot-reload webhook secret from secrets backend."""
    try:
        new_secret = secrets_client.get_walletpro_webhook_secret()
        cache.rotate(new_secret)
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
    port = int(os.environ.get("PORT", "5002"))
    app.run(host="0.0.0.0", port=port, debug=False)
