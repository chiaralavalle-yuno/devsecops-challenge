"""
rotation/backends/__init__.py — Abstract base class for secrets backends.

Both AWS Secrets Manager and HashiCorp Vault implement this interface,
making the rotation logic backend-agnostic.
"""
from abc import ABC, abstractmethod
from typing import Any


class SecretsBackend(ABC):
    """Abstract interface for secrets storage backends."""

    @abstractmethod
    def get_secret(self, path: str) -> dict[str, Any]:
        """
        Retrieve the current version of a secret.

        Args:
            path: Secret path (e.g., "pagos/providers/bancosur/api_key")

        Returns:
            Dict of key-value pairs stored at this path.
        """
        ...

    @abstractmethod
    def put_secret(self, path: str, data: dict[str, Any]) -> None:
        """
        Store a new version of a secret.

        Args:
            path: Secret path
            data: Dict of key-value pairs to store
        """
        ...

    @abstractmethod
    def get_previous_version(self, path: str) -> dict[str, Any] | None:
        """
        Retrieve the previous version of a secret (for rollback).

        Args:
            path: Secret path

        Returns:
            Dict of key-value pairs from the previous version, or None if no history.
        """
        ...

    @abstractmethod
    def rollback_secret(self, path: str) -> None:
        """
        Roll back a secret to its previous version.

        Used when health checks fail after rotation. Implementations should:
        1. Retrieve the previous version
        2. Write it as the new current version
        3. AWS: promote AWSPREVIOUS stage to AWSCURRENT
        4. Vault: write previous version's data as new KV entry

        Args:
            path: Secret path to roll back
        """
        ...

    @abstractmethod
    def write_audit_event(self, event: dict[str, Any]) -> None:
        """
        Write a structured audit event to the centralized audit log.

        For AWS backend: writes to audit/audit.log + CloudWatch Logs
        For Vault backend: writes to audit/audit.log (Vault's audit device
        captures all API-level events independently)

        Args:
            event: Dict conforming to audit_schema.json
        """
        ...
