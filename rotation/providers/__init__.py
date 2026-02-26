"""
rotation/providers/__init__.py — Abstract base class for payment providers.

Each provider knows how to:
  1. Generate a new credential by calling mock-provider
  2. Validate a credential against mock-provider
  3. Revoke the previous credential after successful rotation
"""
from abc import ABC, abstractmethod


class PaymentProvider(ABC):
    """Abstract interface for payment provider credential management."""

    @abstractmethod
    def generate_new_key(self) -> str:
        """
        Call the provider API to generate a new API key.
        Returns the new key value.
        """
        ...

    @abstractmethod
    def validate_key(self, key: str) -> bool:
        """
        Validate that a key is currently accepted by the provider.
        Returns True if valid.
        """
        ...

    @abstractmethod
    def revoke_previous(self) -> None:
        """
        Revoke the previous key after successful rotation.
        Called after health checks pass and dual-window expires.
        """
        ...

    @abstractmethod
    def get_secret_path(self) -> str:
        """Return the secrets backend path for this provider's API key."""
        ...

    @abstractmethod
    def get_webhook_secret_path(self) -> str:
        """Return the secrets backend path for this provider's webhook secret."""
        ...
