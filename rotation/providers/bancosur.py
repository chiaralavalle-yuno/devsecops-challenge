"""
rotation/providers/bancosur.py — BancoSur payment provider integration.

Calls mock-provider to simulate credential rotation.
In production, this would call the real BancoSur API:
  POST https://api.bancosur.com/v1/credentials/rotate
  Authorization: Bearer <current_key>
  → { "api_key": "<new_key>", "expires_at": "..." }
"""
import logging
import os

import requests

from rotation.providers import PaymentProvider

log = logging.getLogger(__name__)

MOCK_PROVIDER_URL = os.environ.get("MOCK_PROVIDER_URL", "http://localhost:5003")


class BancoSurProvider(PaymentProvider):
    """BancoSur credential management via mock-provider."""

    def get_secret_path(self) -> str:
        return "pagos/providers/bancosur/api_key"

    def get_webhook_secret_path(self) -> str:
        return "pagos/providers/bancosur/webhook_secret"

    def generate_new_key(self) -> str:
        """
        Rotate the BancoSur API key.

        Production equivalent:
            POST https://api.bancosur.com/v1/credentials/rotate
            → returns new api_key, starts 60s dual-window on BancoSur side
        """
        resp = requests.post(
            f"{MOCK_PROVIDER_URL}/bancosur/rotate-key",
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        new_key = data["api_key"]
        log.info(f"BancoSur key rotated (prefix: {new_key[:10]}...)")
        return new_key

    def validate_key(self, key: str) -> bool:
        """
        Validate a key against the BancoSur API.

        Production equivalent:
            POST https://api.bancosur.com/v1/credentials/validate
            Authorization: Bearer <key>
            → 200 OK = valid
        """
        try:
            resp = requests.post(
                f"{MOCK_PROVIDER_URL}/bancosur/validate",
                json={"api_key": key},
                timeout=10,
            )
            return resp.status_code == 200
        except requests.RequestException as e:
            log.error(f"BancoSur validation request failed: {e}")
            return False

    def revoke_previous(self) -> None:
        """
        Revoke the previous key at BancoSur.

        Production equivalent:
            DELETE https://api.bancosur.com/v1/credentials/previous
            → ends dual-window immediately
        """
        try:
            resp = requests.post(
                f"{MOCK_PROVIDER_URL}/bancosur/revoke-previous",
                timeout=10,
            )
            resp.raise_for_status()
            log.info("BancoSur previous key revoked")
        except requests.RequestException as e:
            # Non-fatal: key will expire naturally at end of dual window
            log.warning(f"BancoSur revoke-previous failed (non-fatal): {e}")
