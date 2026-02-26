"""
mock-provider/app.py — Simulates BancoSur and WalletPro payment provider APIs.

Implements:
  - Key generation with dual-credential window (60s overlap during rotation)
  - HMAC validation for webhook secrets
  - Structured JSON logging for anomaly detection demo

This is intentionally simple in-memory state — NOT production code.
"""
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Optional

from flask import Flask, jsonify, request

app = Flask(__name__)

# Structured JSON logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit_log(action: str, provider: str, result: str, metadata: dict | None = None) -> None:
    event = {
        "timestamp": utcnow(),
        "action": action,
        "actor": "mock-provider",
        "resource": f"provider/{provider}",
        "backend": "mock-provider",
        "result": result,
        "metadata": metadata or {},
    }
    log.info(json.dumps(event))


# ============================================================
# In-memory state per provider
# Each provider tracks current key, previous key, and dual-window expiry
# ============================================================

DUAL_WINDOW_SECONDS = int(os.environ.get("DUAL_WINDOW_SECONDS", "60"))

ProviderState = dict  # type alias for clarity

_state: dict[str, ProviderState] = {
    "bancosur": {
        "current_key": f"bsur_{secrets.token_hex(16)}",
        "previous_key": None,
        "dual_window_expires_at": 0.0,
        "webhook_secret": f"bsur_whsec_{secrets.token_hex(16)}",
    },
    "walletpro": {
        "current_key": f"wpro_{secrets.token_hex(16)}",
        "previous_key": None,
        "dual_window_expires_at": 0.0,
        "webhook_secret": f"wpro_whsec_{secrets.token_hex(16)}",
    },
}


def _get_state(provider: str) -> ProviderState:
    if provider not in _state:
        return {}
    return _state[provider]


def _is_in_dual_window(state: ProviderState) -> bool:
    return time.time() < state["dual_window_expires_at"]


def _validate_key(provider: str, key: str) -> tuple[bool, str]:
    """Validate a key against current + optional previous (within dual window)."""
    state = _get_state(provider)
    if not state:
        return False, "unknown_provider"

    if key == state["current_key"]:
        return True, "current"
    if state["previous_key"] and _is_in_dual_window(state) and key == state["previous_key"]:
        return True, "previous_in_window"
    return False, "invalid"


# ============================================================
# Health
# ============================================================

@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "mock-provider"}), 200


# ============================================================
# BancoSur endpoints
# ============================================================

@app.post("/bancosur/rotate-key")
def bancosur_rotate_key():
    state = _state["bancosur"]
    old_key = state["current_key"]
    new_key = f"bsur_{secrets.token_hex(16)}"

    state["previous_key"] = old_key
    state["current_key"] = new_key
    state["dual_window_expires_at"] = time.time() + DUAL_WINDOW_SECONDS

    audit_log("key_rotated", "bancosur", "success", {
        "dual_window_seconds": DUAL_WINDOW_SECONDS,
        "new_key_prefix": new_key[:12] + "...",
    })

    return jsonify({
        "api_key": new_key,
        "dual_window_expires_in_seconds": DUAL_WINDOW_SECONDS,
        "message": f"Previous key valid for {DUAL_WINDOW_SECONDS}s during rotation window",
    }), 200


@app.post("/bancosur/validate")
def bancosur_validate():
    data = request.get_json(force=True, silent=True) or {}
    key = data.get("api_key", "")

    valid, reason = _validate_key("bancosur", key)
    audit_log("key_validated", "bancosur", "success" if valid else "failure", {
        "valid": valid, "reason": reason,
        "key_prefix": key[:8] + "..." if key else "(empty)",
        "client_ip": request.remote_addr,
    })

    if valid:
        return jsonify({"valid": True, "reason": reason}), 200
    return jsonify({"valid": False, "reason": reason}), 401


@app.post("/bancosur/revoke-previous")
def bancosur_revoke_previous():
    state = _state["bancosur"]
    state["previous_key"] = None
    state["dual_window_expires_at"] = 0.0

    audit_log("previous_key_revoked", "bancosur", "success")
    return jsonify({"message": "Previous key revoked"}), 200


# ============================================================
# WalletPro endpoints
# ============================================================

@app.post("/walletpro/rotate-key")
def walletpro_rotate_key():
    state = _state["walletpro"]
    old_key = state["current_key"]
    new_key = f"wpro_{secrets.token_hex(16)}"

    state["previous_key"] = old_key
    state["current_key"] = new_key
    state["dual_window_expires_at"] = time.time() + DUAL_WINDOW_SECONDS

    audit_log("key_rotated", "walletpro", "success", {
        "dual_window_seconds": DUAL_WINDOW_SECONDS,
        "new_key_prefix": new_key[:12] + "...",
    })

    return jsonify({
        "api_key": new_key,
        "dual_window_expires_in_seconds": DUAL_WINDOW_SECONDS,
        "message": f"Previous key valid for {DUAL_WINDOW_SECONDS}s during rotation window",
    }), 200


@app.post("/walletpro/validate")
def walletpro_validate():
    data = request.get_json(force=True, silent=True) or {}
    key = data.get("api_key", "")

    valid, reason = _validate_key("walletpro", key)
    audit_log("key_validated", "walletpro", "success" if valid else "failure", {
        "valid": valid, "reason": reason,
        "key_prefix": key[:8] + "..." if key else "(empty)",
        "client_ip": request.remote_addr,
    })

    if valid:
        return jsonify({"valid": True, "reason": reason}), 200
    return jsonify({"valid": False, "reason": reason}), 401


@app.post("/walletpro/validate-hmac")
def walletpro_validate_hmac():
    """Validate HMAC-SHA256 webhook signature using current or previous secret."""
    data = request.get_json(force=True, silent=True) or {}
    payload = data.get("payload", "")
    signature = data.get("signature", "")

    if isinstance(payload, dict):
        payload = json.dumps(payload, separators=(",", ":"), sort_keys=True)

    state = _state["walletpro"]

    def compute_hmac(secret: str) -> str:
        return hmac.new(
            secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()

    # Check current webhook secret
    if hmac.compare_digest(compute_hmac(state["webhook_secret"]), signature):
        audit_log("hmac_validated", "walletpro", "success", {"reason": "current"})
        return jsonify({"valid": True, "reason": "current"}), 200

    # No previous-webhook-secret dual-window in this demo (webhook secret rotation
    # is not yet implemented in the rotation script).

    audit_log("hmac_validated", "walletpro", "failure", {"reason": "invalid_signature"})
    return jsonify({"valid": False, "reason": "invalid_signature"}), 401


@app.post("/walletpro/revoke-previous")
def walletpro_revoke_previous():
    state = _state["walletpro"]
    state["previous_key"] = None
    state["dual_window_expires_at"] = 0.0

    audit_log("previous_key_revoked", "walletpro", "success")
    return jsonify({"message": "Previous key revoked"}), 200


@app.get("/walletpro/current-key")
def walletpro_current_key():
    """Debug endpoint — returns current key (demo only, not production)."""
    return jsonify({"api_key": _state["walletpro"]["current_key"]}), 200


@app.get("/bancosur/current-key")
def bancosur_current_key():
    """Debug endpoint — returns current key (demo only, not production)."""
    return jsonify({"api_key": _state["bancosur"]["current_key"]}), 200


@app.get("/bancosur/current-webhook-secret")
def bancosur_current_webhook_secret():
    """Debug endpoint — returns current webhook secret (demo only, not production)."""
    return jsonify({"webhook_secret": _state["bancosur"]["webhook_secret"]}), 200


@app.get("/walletpro/current-webhook-secret")
def walletpro_current_webhook_secret():
    """Debug endpoint — returns current webhook secret (demo only, not production)."""
    return jsonify({"webhook_secret": _state["walletpro"]["webhook_secret"]}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5003"))
    app.run(host="0.0.0.0", port=port, debug=False)
