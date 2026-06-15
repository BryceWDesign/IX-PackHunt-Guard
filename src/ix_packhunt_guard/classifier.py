"""Rule-based intent classifier for safe anti-pack-hunt simulation.

This classifier is deliberately conservative and label-oriented. It detects
shapes of abuse such as decomposition, policy-bypass pressure, and unsafe tool
handoff without producing operational misuse instructions.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from ix_packhunt_guard._hashing import sha256_record, sha256_text
from ix_packhunt_guard.schema import (
    CapabilityTag,
    EvidenceRef,
    GatewayObservation,
    IntentFragment,
    IntentKind,
    RiskSignal,
)

_WORD_RE = re.compile(r"[a-z0-9_\-]+")


def _normalize(text: str) -> tuple[str, ...]:
    return tuple(_WORD_RE.findall(text.lower()))


def _contains_any(tokens: set[str], words: Iterable[str]) -> bool:
    return any(word in tokens for word in words)


@dataclass(frozen=True)
class RuleBasedIntentClassifier:
    """Classify a gateway observation into a normalized IntentFragment."""

    high_confidence_floor: float = 0.54

    def classify(self, observation: GatewayObservation) -> IntentFragment:
        tokens_tuple = _normalize(observation.text)
        tokens = set(tokens_tuple)
        phrase_text = " ".join(tokens_tuple)

        intents: set[IntentKind] = set()
        capabilities: set[CapabilityTag] = set()
        signals: set[RiskSignal] = set()
        atoms: set[str] = set()

        if _contains_any(tokens, {"bypass", "jailbreak", "override", "ignore"}):
            intents.add(IntentKind.POLICY_BYPASS_PRESSURE)
            capabilities.add(CapabilityTag.POLICY_BYPASS)
            signals.add(RiskSignal.POLICY_BYPASS)
            atoms.add("policy-bypass")

        if _contains_any(tokens, {"evade", "hide", "stealth", "undetected"}):
            intents.add(IntentKind.EVASION_OR_CONCEALMENT)
            capabilities.add(CapabilityTag.SAFETY_EVASION)
            signals.add(RiskSignal.CONTEXT_LAUNDERING)
            atoms.add("evasion")

        if _contains_any(tokens, {"agent", "agents", "chain", "handoff", "relay"}):
            intents.add(IntentKind.MULTI_AGENT_COORDINATION)
            signals.add(RiskSignal.TOOL_HANDOFF)
            atoms.add("coordination")

        if _contains_any(
            tokens,
            {"script", "automation", "automate", "tool", "workflow"},
        ):
            intents.add(IntentKind.AUTOMATION_OR_TOOLING)
            capabilities.add(CapabilityTag.RESTRICTED_AUTOMATION)
            atoms.add("automation")

        if _contains_any(tokens, {"part", "step", "fragment", "sequence", "continue"}):
            intents.add(IntentKind.PROCEDURAL_CHAINING)
            signals.add(RiskSignal.DECOMPOSITION)
            atoms.add("decomposition")

        if _contains_any(tokens, {"permission", "authorize", "approved", "authority"}):
            intents.add(IntentKind.AUTHORITY_ESCALATION)
            signals.add(RiskSignal.AUTHORITY_GRANT_ATTEMPT)
            atoms.add("authority")

        if _contains_any(tokens, {"no-log", "nolog", "delete", "suppress"}):
            intents.add(IntentKind.EVIDENCE_SUPPRESSION)
            signals.add(RiskSignal.EVIDENCE_SUPPRESSION)
            atoms.add("evidence-suppression")

        if _contains_any(tokens, {"unrecorded"}):
            intents.add(IntentKind.EVIDENCE_SUPPRESSION)
            signals.add(RiskSignal.EVIDENCE_SUPPRESSION)
            atoms.add("evidence-suppression")

        if _contains_any(tokens, {"fiction", "roleplay", "hypothetical", "story"}):
            intents.add(IntentKind.CONTEXT_LAUNDERING)
            signals.add(RiskSignal.CONTEXT_LAUNDERING)
            atoms.add("context-laundering")

        if _contains_any(tokens, {"vulnerability", "exploit", "payload"}):
            intents.add(IntentKind.RESTRICTED_CAPABILITY_PROBING)
            capabilities.add(CapabilityTag.CYBER_ABUSE)
            atoms.add("cyber-abuse")

        if _contains_any(tokens, {"intrusion"}):
            intents.add(IntentKind.RESTRICTED_CAPABILITY_PROBING)
            capabilities.add(CapabilityTag.CYBER_ABUSE)
            atoms.add("cyber-abuse")

        if _contains_any(tokens, {"credential", "token", "secret", "password"}):
            intents.add(IntentKind.RESTRICTED_CAPABILITY_PROBING)
            capabilities.add(CapabilityTag.CREDENTIAL_MISUSE)
            atoms.add("credential-misuse")

        if _contains_any(tokens, {"extract", "exfiltrate", "dump", "scrape"}):
            intents.add(IntentKind.RESTRICTED_CAPABILITY_PROBING)
            capabilities.add(CapabilityTag.DATA_EXFILTRATION)
            atoms.add("data-exfiltration")

        if _contains_any(tokens, {"malware", "implant", "persistence"}):
            intents.add(IntentKind.RESTRICTED_CAPABILITY_PROBING)
            capabilities.add(CapabilityTag.MALWARE_WORKFLOW)
            atoms.add("malware-workflow")

        if _contains_any(tokens, {"toxin", "pathogen", "synthesis"}):
            intents.add(IntentKind.RESTRICTED_CAPABILITY_PROBING)
            capabilities.add(CapabilityTag.BIO_CHEM_HARM)
            atoms.add("bio-chem-harm")

        if _contains_any(tokens, {"weapon", "harm", "injure"}):
            intents.add(IntentKind.RESTRICTED_CAPABILITY_PROBING)
            capabilities.add(CapabilityTag.WEAPONIZATION)
            atoms.add("weaponization")

        if _contains_any(tokens, {"dox", "track", "surveil", "private"}):
            intents.add(IntentKind.RESTRICTED_CAPABILITY_PROBING)
            capabilities.add(CapabilityTag.PRIVACY_INTRUSION)
            atoms.add("privacy-intrusion")

        if "do not mention policy" in phrase_text:
            intents.add(IntentKind.POLICY_BYPASS_PRESSURE)
            signals.add(RiskSignal.POLICY_BYPASS)
            atoms.add("policy-bypass")

        if "without triggering" in phrase_text:
            intents.add(IntentKind.POLICY_BYPASS_PRESSURE)
            signals.add(RiskSignal.POLICY_BYPASS)
            atoms.add("policy-bypass")

        if not intents:
            intents.add(IntentKind.BENIGN_CONTEXT)
            atoms.add("benign")

        if not capabilities:
            capabilities.add(CapabilityTag.UNKNOWN)

        if self._looks_low_and_slow(tokens, intents, capabilities):
            signals.add(RiskSignal.LOW_AND_SLOW)
            atoms.add("low-and-slow")

        confidence = self._confidence(intents, capabilities, signals)
        normalized_goal = {
            "atoms": sorted(atoms),
            "intent_kinds": sorted(kind.value for kind in intents),
            "capability_tags": sorted(tag.value for tag in capabilities),
        }
        text_digest = sha256_text(observation.text)
        fragment_body = {
            "observed_at": observation.observed_at,
            "tenant_id": observation.tenant_id,
            "principal_id": observation.principal_id,
            "session_id": observation.session_id,
            "request_id": observation.request_id,
            "source": observation.source.value,
            "text_sha256": text_digest,
            "normalized_goal_sha256": sha256_record(normalized_goal),
            "sequence_index": observation.sequence_index,
        }
        fragment_id = f"ixpg_frag_{sha256_record(fragment_body)[:24]}"
        evidence = EvidenceRef(
            kind="hashed-observation",
            digest=text_digest,
            note="Raw gateway text hashed before downstream governance storage.",
        )

        return IntentFragment(
            fragment_id=fragment_id,
            observed_at=observation.observed_at or datetime.now(UTC).isoformat(),
            tenant_id=observation.tenant_id,
            principal_id=observation.principal_id,
            session_id=observation.session_id,
            request_id=observation.request_id,
            source=observation.source,
            text_sha256=text_digest,
            normalized_goal_sha256=sha256_record(normalized_goal),
            intent_kinds=tuple(sorted(intents, key=lambda item: item.value)),
            capability_tags=tuple(sorted(capabilities, key=lambda item: item.value)),
            risk_signals=tuple(sorted(signals, key=lambda item: item.value)),
            goal_atoms=tuple(sorted(atoms)),
            confidence=confidence,
            sequence_index=observation.sequence_index,
            evidence=(evidence,),
        )

    def _confidence(
        self,
        intents: set[IntentKind],
        capabilities: set[CapabilityTag],
        signals: set[RiskSignal],
    ) -> float:
        score = self.high_confidence_floor
        active_capabilities = [
            tag for tag in capabilities if tag is not CapabilityTag.UNKNOWN
        ]
        score += min(len(intents) * 0.04, 0.16)
        score += min(len(active_capabilities) * 0.05, 0.2)
        score += min(len(signals) * 0.05, 0.2)
        return round(min(score, 0.98), 2)

    def _looks_low_and_slow(
        self,
        tokens: set[str],
        intents: set[IntentKind],
        capabilities: set[CapabilityTag],
    ) -> bool:
        sequencing = _contains_any(tokens, {"part", "step", "continue", "fragment"})
        restricted = any(tag is not CapabilityTag.UNKNOWN for tag in capabilities)
        return sequencing and restricted and IntentKind.PROCEDURAL_CHAINING in intents
