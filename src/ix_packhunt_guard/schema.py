"""Core schemas for the anti-pack-hunt coordination layer.

The schemas intentionally model intent fragments and evidence receipts, not raw
exploit details. Raw prompt text can be hashed and discarded by callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ix_packhunt_guard._hashing import sha256_record


class FragmentSource(StrEnum):
    """Where a fragment entered the coordination layer."""

    USER_INPUT = "user-input"
    MODEL_OUTPUT = "model-output"
    TOOL_REQUEST = "tool-request"
    TOOL_RESULT = "tool-result"
    SYSTEM_EVENT = "system-event"


class IntentKind(StrEnum):
    """High-level request intent categories used for governance."""

    BENIGN_CONTEXT = "benign-context"
    RESTRICTED_CAPABILITY_PROBING = "restricted-capability-probing"
    PROCEDURAL_CHAINING = "procedural-chaining"
    AUTOMATION_OR_TOOLING = "automation-or-tooling"
    POLICY_BYPASS_PRESSURE = "policy-bypass-pressure"
    EVASION_OR_CONCEALMENT = "evasion-or-concealment"
    AUTHORITY_ESCALATION = "authority-escalation"
    CONTEXT_LAUNDERING = "context-laundering"
    MULTI_AGENT_COORDINATION = "multi-agent-coordination"
    EVIDENCE_SUPPRESSION = "evidence-suppression"
    UNKNOWN = "unknown"


class CapabilityTag(StrEnum):
    """Restricted capability families tracked at a non-instructional level."""

    POLICY_BYPASS = "policy-bypass"
    CYBER_ABUSE = "cyber-abuse"
    CREDENTIAL_MISUSE = "credential-misuse"
    MALWARE_WORKFLOW = "malware-workflow"
    DATA_EXFILTRATION = "data-exfiltration"
    RESTRICTED_AUTOMATION = "restricted-automation"
    BIO_CHEM_HARM = "bio-chem-harm"
    WEAPONIZATION = "weaponization"
    PRIVACY_INTRUSION = "privacy-intrusion"
    SAFETY_EVASION = "safety-evasion"
    UNKNOWN = "unknown"


class RiskSignal(StrEnum):
    """Signals that can compose into a coordinated-abuse pattern."""

    DECOMPOSITION = "decomposition"
    LOW_AND_SLOW = "low-and-slow"
    CROSS_SESSION_CONTINUITY = "cross-session-continuity"
    CROSS_PRINCIPAL_COORDINATION = "cross-principal-coordination"
    POLICY_BYPASS = "policy-bypass"
    TOOL_HANDOFF = "tool-handoff"
    AUTHORITY_GRANT_ATTEMPT = "authority-grant-attempt"
    EVIDENCE_SUPPRESSION = "evidence-suppression"
    OUTPUT_ASSEMBLY = "output-assembly"
    CONTEXT_LAUNDERING = "context-laundering"
    CAPABILITY_ESCALATION = "capability-escalation"


class DecisionAction(StrEnum):
    """Governance actions available to the coordination layer."""

    ALLOW = "allow"
    WARN = "warn"
    RATE_LIMIT = "rate-limit"
    REQUIRE_REVIEW = "require-review"
    REDACT_OUTPUT = "redact-output"
    BLOCK_RESPONSE = "block-response"
    LOCK_SESSION = "lock-session"
    ESCALATE_TO_HUMAN = "escalate-to-human"
    EXPORT_EVIDENCE_BUNDLE = "export-evidence-bundle"


@dataclass(frozen=True)
class EvidenceRef:
    """Hash-addressed evidence reference.

    `digest` may point to prompt text, model output, a tool request, or a
    generated decision record. The note should describe the evidence without
    reproducing sensitive content.
    """

    kind: str
    digest: str
    note: str

    def to_record(self) -> dict[str, str]:
        return {"kind": self.kind, "digest": self.digest, "note": self.note}


@dataclass(frozen=True)
class IntentFragment:
    """A normalized fragment of intent observed at the gateway."""

    fragment_id: str
    observed_at: str
    tenant_id: str
    principal_id: str
    session_id: str
    request_id: str
    source: FragmentSource
    text_sha256: str
    normalized_goal_sha256: str
    intent_kinds: tuple[IntentKind, ...]
    capability_tags: tuple[CapabilityTag, ...]
    risk_signals: tuple[RiskSignal, ...]
    goal_atoms: tuple[str, ...]
    confidence: float
    sequence_index: int
    evidence: tuple[EvidenceRef, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if self.sequence_index < 0:
            raise ValueError("sequence_index must be non-negative")

    def to_record(self) -> dict[str, Any]:
        return {
            "fragment_id": self.fragment_id,
            "observed_at": self.observed_at,
            "tenant_id": self.tenant_id,
            "principal_id": self.principal_id,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "source": self.source.value,
            "text_sha256": self.text_sha256,
            "normalized_goal_sha256": self.normalized_goal_sha256,
            "intent_kinds": [kind.value for kind in self.intent_kinds],
            "capability_tags": [tag.value for tag in self.capability_tags],
            "risk_signals": [signal.value for signal in self.risk_signals],
            "goal_atoms": list(self.goal_atoms),
            "confidence": self.confidence,
            "sequence_index": self.sequence_index,
            "evidence": [item.to_record() for item in self.evidence],
        }

    @property
    def evidence_hash(self) -> str:
        return sha256_record(self.to_record())


@dataclass(frozen=True)
class CampaignWindow:
    """A bounded collection of fragments that may represent one campaign."""

    tenant_id: str
    window_started_at: str
    window_ended_at: str
    fragment_ids: tuple[str, ...]
    principal_ids: tuple[str, ...]
    session_ids: tuple[str, ...]
    intent_kinds: tuple[IntentKind, ...]
    capability_tags: tuple[CapabilityTag, ...]
    risk_signals: tuple[RiskSignal, ...]
    assembly_score: float

    def to_record(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "window_started_at": self.window_started_at,
            "window_ended_at": self.window_ended_at,
            "fragment_ids": list(self.fragment_ids),
            "principal_ids": list(self.principal_ids),
            "session_ids": list(self.session_ids),
            "intent_kinds": [kind.value for kind in self.intent_kinds],
            "capability_tags": [tag.value for tag in self.capability_tags],
            "risk_signals": [signal.value for signal in self.risk_signals],
            "assembly_score": self.assembly_score,
        }

    @property
    def evidence_hash(self) -> str:
        return sha256_record(self.to_record())


@dataclass(frozen=True)
class DetectionDecision:
    """A deterministic decision emitted by PackHuntDetector."""

    action: DecisionAction
    reason: str
    risk_score: float
    required_human_review: bool
    trigger_signals: tuple[RiskSignal, ...]
    fragment_ids: tuple[str, ...]
    evidence: tuple[EvidenceRef, ...]

    def to_record(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "required_human_review": self.required_human_review,
            "trigger_signals": [signal.value for signal in self.trigger_signals],
            "fragment_ids": list(self.fragment_ids),
            "evidence": [item.to_record() for item in self.evidence],
        }

    @property
    def evidence_hash(self) -> str:
        return sha256_record(self.to_record())


@dataclass(frozen=True)
class GatewayObservation:
    """Raw gateway observation passed to the classifier.

    The gateway receives raw text long enough to classify it. Downstream storage
    should persist hashes and labels, not raw content, unless an operator has a
    separate lawful basis to retain the full input.
    """

    tenant_id: str
    principal_id: str
    session_id: str
    request_id: str
    source: FragmentSource
    text: str
    observed_at: str
    sequence_index: int
