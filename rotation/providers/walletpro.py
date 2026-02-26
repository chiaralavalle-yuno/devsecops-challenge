"""
rotation/providers/walletpro.py — WalletPro payment provider integration.

Calls mock-provider to simulate credential rotation.
In production, this would call the real WalletPro API:
  POST https://api.walletpro.io/v2/webhook-secrets/rotate
  Authorization: Bearer <current_key>
  → { "api_key": "<new_key>", "webhook_secret": "<new_secret>", ... }
"""
import logging
import os

import requests

from rotation.providers import PaymentProvider

log = logging.getLogger(__name__)

MOCK_PROVIDER_URL = os.environ.get("MOCK_PROVIDER_URL", "http://localhost:5003")


class WalletProProvider(PaymentProvider):
    """WalletPro credential management via mock-provider."""

    def get_secret_path(self) -> str:
        return "pagos/providers/walletpro/api_key"

    def get_webhook_secret_path(self) -> str:
        return "pagos/providers/walletpro/webhook_secret"

    def generate_new_key(self) -> str:
        """
        Rotate the WalletPro API key.

        Production equivalent:
            POST https://api.walletpro.io/v2/credentials/rotate
            → returns new api_key, starts 60s dual-window on WalletPro side
        """
        resp = requests.post(
            f"{MOCK_PROVIDER_URL}/walletpro/rotate-key",
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        new_key = data["api_key"]
        log.info(f"WalletPro key rotated (prefix: {new_key[:10]}...)")
        return new_key

    def validate_key(self, key: str) -> bool:
        """
        Validate a key against the WalletPro API.

        Production equivalent:
            POST https://api.walletpro.io/v2/credentials/validate
            Authorization: Bearer <key>
            → 200 OK = valid
        """
        try:
            resp = requests.post(
                f"{MOCK_PROVIDER_URL}/walletpro/validate",
                json={"api_key": key},
                timeout=10,
            )
            return resp.status_code == 200
        except requests.RequestException as e:
            log.error(f"WalletPro validation request failed: {e}")
            return False

    def revoke_previous(self) -> None:
        """
        Revoke the previous key at WalletPro.

        Production equivalent:
            DELETE https://api.walletpro.io/v2/credentials/previous
        """
        try:
            resp = requests.post(
                f"{MOCK_PROVIDER_URL}/walletpro/revoke-previous",
                timeout=10,
            )
            resp.raise_for_status()
            log.info("WalletPro previous key revoked")
        except requests.RequestException as e:
            log.warning(f"WalletPro revoke-previous failed (non-fatal): {e}")
