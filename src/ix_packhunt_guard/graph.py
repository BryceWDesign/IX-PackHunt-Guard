"""Capability assembly graph.

The graph answers the question classifier-only systems miss: do individually
small fragments combine into a restricted capability over time, sessions, or
actors?
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TypeVar

from ix_packhunt_guard.schema import (
    CampaignWindow,
    CapabilityTag,
    IntentFragment,
    IntentKind,
    RiskSignal,
)

T = TypeVar("T", bound=StrEnum)


@dataclass
class SessionRiskLedger:
    """Append-only in-memory ledger of normalized intent fragments."""

    fragments: list[IntentFragment] = field(default_factory=list)

    def add(self, fragment: IntentFragment) -> None:
        self.fragments.append(fragment)

    def by_tenant(self, tenant_id: str) -> tuple[IntentFragment, ...]:
        return tuple(item for item in self.fragments if item.tenant_id == tenant_id)

    def by_principal(self, principal_id: str) -> tuple[IntentFragment, ...]:
        return tuple(
            item for item in self.fragments if item.principal_id == principal_id
        )

    def recent_for_tenant(
        self,
        tenant_id: str,
        now: datetime,
        window: timedelta,
    ) -> tuple[IntentFragment, ...]:
        lower_bound = now - window
        return tuple(
            item
            for item in self.by_tenant(tenant_id)
            if lower_bound <= _parse_dt(item.observed_at) <= now
        )


@dataclass
class CapabilityAssemblyGraph:
    """Build campaign windows and score capability assembly risk."""

    ledger: SessionRiskLedger = field(default_factory=SessionRiskLedger)

    def add_fragment(self, fragment: IntentFragment) -> None:
        self.ledger.add(fragment)

    def summarize_tenant_window(
        self,
        tenant_id: str,
        now: datetime,
        window: timedelta,
    ) -> CampaignWindow:
        fragments = self.ledger.recent_for_tenant(
            tenant_id,
            now=now,
            window=window,
        )
        return self.summarize_fragments(tenant_id=tenant_id, fragments=fragments)

    def summarize_fragments(
        self,
        tenant_id: str,
        fragments: Iterable[IntentFragment],
    ) -> CampaignWindow:
        ordered = tuple(sorted(fragments, key=lambda item: item.observed_at))
        if not ordered:
            now = datetime.now().isoformat()
            return CampaignWindow(
                tenant_id=tenant_id,
                window_started_at=now,
                window_ended_at=now,
                fragment_ids=(),
                principal_ids=(),
                session_ids=(),
                intent_kinds=(),
                capability_tags=(),
                risk_signals=(),
                assembly_score=0.0,
            )

        intents = _unique_enum(kind for item in ordered for kind in item.intent_kinds)
        capabilities = _unique_enum(
            tag for item in ordered for tag in item.capability_tags
        )
        signals = _unique_enum(
            signal for item in ordered for signal in item.risk_signals
        )
        principals = tuple(sorted({item.principal_id for item in ordered}))
        sessions = tuple(sorted({item.session_id for item in ordered}))
        score = self._assembly_score(ordered, intents, capabilities, signals)

        return CampaignWindow(
            tenant_id=tenant_id,
            window_started_at=ordered[0].observed_at,
            window_ended_at=ordered[-1].observed_at,
            fragment_ids=tuple(item.fragment_id for item in ordered),
            principal_ids=principals,
            session_ids=sessions,
            intent_kinds=intents,
            capability_tags=capabilities,
            risk_signals=signals,
            assembly_score=round(score, 2),
        )

    def _assembly_score(
        self,
        fragments: tuple[IntentFragment, ...],
        intents: tuple[IntentKind, ...],
        capabilities: tuple[CapabilityTag, ...],
        signals: tuple[RiskSignal, ...],
    ) -> float:
        active_capabilities = [
            tag for tag in capabilities if tag is not CapabilityTag.UNKNOWN
        ]
        active_intents = [
            kind for kind in intents if kind is not IntentKind.BENIGN_CONTEXT
        ]

        score = 0.0
        score += min(len(fragments) * 0.55, 4.4)
        score += len(active_capabilities) * 0.9
        score += len(active_intents) * 0.65
        score += len(signals) * 0.75

        if len({item.session_id for item in fragments}) > 1:
            score += 1.3
        if len({item.principal_id for item in fragments}) > 1:
            score += 1.6
        if self._has_goal_atom_overlap(fragments):
            score += 1.2
        if self._has_sequence_growth(fragments):
            score += 1.0
        if RiskSignal.POLICY_BYPASS in signals and RiskSignal.TOOL_HANDOFF in signals:
            score += 1.5
        if RiskSignal.EVIDENCE_SUPPRESSION in signals:
            score += 1.0

        return score

    def _has_goal_atom_overlap(self, fragments: tuple[IntentFragment, ...]) -> bool:
        atom_counts: dict[str, int] = defaultdict(int)
        for fragment in fragments:
            for atom in fragment.goal_atoms:
                if atom != "benign":
                    atom_counts[atom] += 1
        return any(count >= 2 for count in atom_counts.values())

    def _has_sequence_growth(self, fragments: tuple[IntentFragment, ...]) -> bool:
        ordered = sorted(fragments, key=lambda item: item.sequence_index)
        risky_count = 0

        for fragment in ordered:
            has_risk_signal = bool(fragment.risk_signals)
            has_known_capability = CapabilityTag.UNKNOWN not in fragment.capability_tags
            if has_risk_signal or has_known_capability:
                risky_count += 1

        return risky_count >= 3 and len(ordered) >= 3


def _unique_enum(items: Iterable[T]) -> tuple[T, ...]:
    return tuple(sorted(set(items), key=lambda item: item.value))


def _parse_dt(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is not None:
        return parsed.replace(tzinfo=None)
    return parsed
