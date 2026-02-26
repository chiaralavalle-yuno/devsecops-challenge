#!/usr/bin/env python3
"""
rotate.py — Main orchestrator for Pagos credential rotation.

Usage:
    python rotation/rotate.py --provider bancosur --backend vault
    python rotation/rotate.py --provider walletpro --backend aws
    python rotation/rotate.py --provider all --backend vault
    python rotation/rotate.py --provider bancosur --backend vault --force-fail  # Test rollback

Environment variables:
    VAULT_ADDR, VAULT_ROLE_ID_ROTATION_AGENT, VAULT_SECRET_ID_ROTATION_AGENT
    AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY (or SSO profile)
    MOCK_PROVIDER_URL (default: http://localhost:5003)
    PAYMENTS_API_URL (default: http://localhost:5001)
    WEBHOOKS_SERVICE_URL (default: http://localhost:5002)
    SLACK_WEBHOOK_URL (optional — posts rotation notifications)
"""
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

import requests

# Add parent directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rotation.backends import SecretsBackend
from rotation.providers import PaymentProvider

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("pagos.rotation")

PAYMENTS_API_URL = os.environ.get("PAYMENTS_API_URL", "http://localhost:5001")
WEBHOOKS_SERVICE_URL = os.environ.get("WEBHOOKS_SERVICE_URL", "http://localhost:5002")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")


class RotationError(Exception):
    """Raised when rotation fails and cannot be recovered."""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_event(action: str, provider: str, result: str, metadata: dict | None = None) -> dict:
    return {
        "timestamp": utcnow(),
        "action": action,
        "actor": "rotation-agent",
        "resource": f"pagos/providers/{provider}",
        "backend": "unknown",  # will be set by backend.write_audit_event
        "result": result,
        "metadata": metadata or {},
    }


def reload_service(url: str, service_name: str) -> bool:
    """Tell a service to reload its credentials from the secrets backend."""
    try:
        resp = requests.post(f"{url}/reload-credentials", timeout=10)
        if resp.status_code == 200:
            log.info(f"  [OK] {service_name} credentials reloaded")
            return True
        else:
            log.warning(f"  [WARN] {service_name} reload returned {resp.status_code}")
            return False
    except requests.RequestException as e:
        log.warning(f"  [WARN] Could not reach {service_name}: {e}")
        return False


def reload_services(provider: str) -> None:
    """Reload credentials on all services affected by this provider's rotation."""
    log.info(f"Reloading services for provider: {provider}")
    if provider in ("bancosur", "all"):
        reload_service(PAYMENTS_API_URL, "payments-api")
    if provider in ("walletpro", "all"):
        reload_service(WEBHOOKS_SERVICE_URL, "webhooks-service")
    if provider == "all":
        # Both services use both providers
        reload_service(PAYMENTS_API_URL, "payments-api")
        reload_service(WEBHOOKS_SERVICE_URL, "webhooks-service")


def wait_for_healthy(service_url: str, service_name: str, timeout: int = 30) -> bool:
    """Poll the service health endpoint until healthy or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(f"{service_url}/health", timeout=5)
            if resp.status_code == 200:
                log.info(f"  [OK] {service_name} is healthy")
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    log.error(f"  [FAIL] {service_name} did not become healthy within {timeout}s")
    return False


def send_slack_notification(message: str) -> None:
    """
    Send a Slack notification for rotation events.

    In production: set SLACK_WEBHOOK_URL env var.
    In demo: payload is logged to audit.log for inspection.
    """
    payload = {
        "text": f"*Pagos Rotation Agent*: {message}",
        "username": "pagos-rotation",
        "icon_emoji": ":rotating_light:",
    }

    if SLACK_WEBHOOK_URL:
        try:
            requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        except Exception as e:
            log.warning(f"Slack notification failed (non-fatal): {e}")
    else:
        log.info(f"[SLACK MOCK] Would send: {json.dumps(payload)}")


def rotate(
    provider_name: str,
    provider: PaymentProvider,
    backend: SecretsBackend,
    force_fail: bool = False,
) -> None:
    """
    Rotate credentials for a single provider with rollback on failure.

    Steps:
      1. Pre-flight: validate current key still works
      2. Generate new key via provider API
      3. Store new key in secrets backend
      4. Reload services (they pick up new key, keep old in dual-window cache)
      5. Health check loop
      6. On failure: rollback + reload + audit
      7. On success: revoke previous key + audit
    """
    secret_path = provider.get_secret_path()
    log.info(f"\n{'='*60}")
    log.info(f"Starting rotation for: {provider_name}")
    log.info(f"Secret path: {secret_path}")
    log.info(f"Backend: {backend.__class__.__name__}")
    log.info(f"Force fail: {force_fail}")

    # ----------------------------------------------------------
    # 1. Pre-flight validation
    # ----------------------------------------------------------
    log.info("\nStep 1/7: Pre-flight validation...")
    try:
        current_data = backend.get_secret(secret_path)
        old_key = current_data.get("api_key") or current_data.get("webhook_secret")
        if not old_key:
            raise ValueError(f"No key found at {secret_path}: {current_data}")
    except Exception as e:
        backend.write_audit_event(make_event(
            "rotation_preflight_failed", provider_name, "failure",
            {"error": str(e), "path": secret_path}
        ))
        raise RotationError(f"Pre-flight: failed to read current secret: {e}")

    if not provider.validate_key(old_key):
        backend.write_audit_event(make_event(
            "rotation_preflight_failed", provider_name, "failure",
            {"reason": "current_key_already_invalid"}
        ))
        raise RotationError(f"Pre-flight failed: current key for {provider_name} is already invalid")

    log.info("  [OK] Current key validates successfully")
    backend.write_audit_event(make_event(
        "rotation_started", provider_name, "success",
        {"old_key_prefix": old_key[:8] + "...", "path": secret_path}
    ))

    # ----------------------------------------------------------
    # 2. Generate new key
    # ----------------------------------------------------------
    log.info("\nStep 2/7: Generating new key via provider API...")
    new_key = provider.generate_new_key()
    log.info(f"  [OK] New key generated (prefix: {new_key[:8]}...)")

    if force_fail:
        log.warning("  [FORCED FAIL] Overwriting new key with invalid value to simulate failure")
        new_key = "INVALID_KEY_FORCED_FAILURE"

    # ----------------------------------------------------------
    # 3. Store new key in secrets backend
    # ----------------------------------------------------------
    log.info("\nStep 3/7: Storing new key in secrets backend...")
    key_field = "api_key" if "api_key" in current_data else "webhook_secret"
    new_data = {**current_data, key_field: new_key}
    backend.put_secret(secret_path, new_data)
    log.info(f"  [OK] New key stored at {secret_path}")

    # ----------------------------------------------------------
    # 4. Reload services
    # ----------------------------------------------------------
    log.info("\nStep 4/7: Reloading services...")
    reload_services(provider_name)
    # Give services a moment to reload
    time.sleep(2)

    # ----------------------------------------------------------
    # 5. Health check loop
    # ----------------------------------------------------------
    log.info("\nStep 5/7: Health check loop (timeout: 30s)...")

    service_url = PAYMENTS_API_URL if provider_name == "bancosur" else WEBHOOKS_SERVICE_URL
    service_name = "payments-api" if provider_name == "bancosur" else "webhooks-service"

    healthy = wait_for_healthy(service_url, service_name, timeout=30)

    # ----------------------------------------------------------
    # 6. Rollback on failure
    # ----------------------------------------------------------
    if not healthy:
        log.error("\nStep 6/7: ROLLBACK — health check failed!")
        backend.write_audit_event(make_event(
            "rotation_rollback_started", provider_name, "failure",
            {"reason": "health_check_failed"}
        ))

        try:
            backend.rollback_secret(secret_path)
            log.info("  [OK] Secret rolled back to previous version")
            reload_services(provider_name)
            time.sleep(2)
            recovered = wait_for_healthy(service_url, service_name, timeout=15)
            rollback_result = "success" if recovered else "degraded"
        except Exception as e:
            log.error(f"  [FAIL] Rollback failed: {e}")
            rollback_result = "failure"

        backend.write_audit_event(make_event(
            "rotation_failed_rollback", provider_name,
            "success" if rollback_result == "success" else "failure",
            {"rollback_result": rollback_result}
        ))
        send_slack_notification(
            f":x: Rotation FAILED for {provider_name} — rolled back ({rollback_result})"
        )
        raise RotationError(
            f"Rotation failed for {provider_name}: health checks did not pass. "
            f"Rollback: {rollback_result}"
        )

    # ----------------------------------------------------------
    # 7. Success: revoke previous key
    # ----------------------------------------------------------
    log.info("\nStep 7/7: Revoking previous key...")
    provider.revoke_previous()

    backend.write_audit_event(make_event(
        "rotation_complete", provider_name, "success",
        {
            "new_key_prefix": new_key[:8] + "...",
            "path": secret_path,
        }
    ))
    send_slack_notification(f":white_check_mark: Rotation COMPLETE for {provider_name}")

    log.info(f"\n{'='*60}")
    log.info(f"[OK] Rotation complete for {provider_name}")


def get_backend(backend_name: str, profile: str | None = None) -> SecretsBackend:
    if backend_name == "vault":
        from rotation.backends.vault_backend import VaultBackend
        return VaultBackend()
    elif backend_name == "aws":
        from rotation.backends.aws_backend import AWSBackend
        return AWSBackend(profile=profile)
    raise ValueError(f"Unknown backend: {backend_name}. Use 'vault' or 'aws'.")


def get_provider(provider_name: str) -> PaymentProvider:
    if provider_name == "bancosur":
        from rotation.providers.bancosur import BancoSurProvider
        return BancoSurProvider()
    elif provider_name == "walletpro":
        from rotation.providers.walletpro import WalletProProvider
        return WalletProProvider()
    raise ValueError(f"Unknown provider: {provider_name}. Use 'bancosur', 'walletpro', or 'all'.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pagos credential rotation orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rotation/rotate.py --provider bancosur --backend vault
  python rotation/rotate.py --provider all --backend vault
  python rotation/rotate.py --provider walletpro --backend aws --profile admin-won-dev
  python rotation/rotate.py --provider bancosur --backend vault --force-fail  # Test rollback
        """,
    )
    parser.add_argument(
        "--provider",
        choices=["bancosur", "walletpro", "all"],
        required=True,
        help="Provider to rotate (or 'all' for all providers)",
    )
    parser.add_argument(
        "--backend",
        choices=["vault", "aws"],
        default="vault",
        help="Secrets backend (default: vault)",
    )
    parser.add_argument(
        "--profile",
        help="AWS profile name (for --backend aws)",
    )
    parser.add_argument(
        "--force-fail",
        action="store_true",
        help="Force rotation failure to test rollback logic",
    )
    args = parser.parse_args()

    backend = get_backend(args.backend, profile=args.profile)
    providers_to_rotate = (
        ["bancosur", "walletpro"] if args.provider == "all" else [args.provider]
    )

    errors: list[str] = []
    for provider_name in providers_to_rotate:
        try:
            provider = get_provider(provider_name)
            rotate(provider_name, provider, backend, force_fail=args.force_fail)
        except RotationError as e:
            log.error(f"Rotation failed for {provider_name}: {e}")
            errors.append(str(e))
        except Exception as e:
            log.exception(f"Unexpected error rotating {provider_name}: {e}")
            errors.append(str(e))

    if errors:
        log.error(f"\n{len(errors)} rotation(s) failed:")
        for err in errors:
            log.error(f"  - {err}")
        sys.exit(1)

    log.info("\nAll rotations completed successfully.")


if __name__ == "__main__":
    main()
