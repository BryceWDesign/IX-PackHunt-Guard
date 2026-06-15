"""Privacy-preserving identity helpers.

The detector needs continuity to identify coordinated behavior. It does not need
raw identity values. This module turns account/session keys into stable HMAC
pseudonyms that can be rotated per deployment.
"""

from __future__ import annotations

from dataclasses import dataclass

from ix_packhunt_guard._hashing import hmac_sha256


@dataclass(frozen=True)
class PseudonymousIdentityProvider:
    """Derive non-reversible identifiers for abuse correlation."""

    secret: bytes
    deployment_id: str

    def __post_init__(self) -> None:
        if len(self.secret) < 16:
            raise ValueError("secret must be at least 16 bytes")
        if not self.deployment_id:
            raise ValueError("deployment_id is required")

    def principal(self, raw_principal: str) -> str:
        return self._derive("principal", raw_principal)

    def session(self, raw_session: str) -> str:
        return self._derive("session", raw_session)

    def tenant(self, raw_tenant: str) -> str:
        return self._derive("tenant", raw_tenant)

    def _derive(self, namespace: str, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError(f"{namespace} value is required")
        digest = hmac_sha256(
            self.secret,
            f"{self.deployment_id}:{namespace}:{normalized}",
        )
        return f"ixpg_{namespace}_{digest[:32]}"
