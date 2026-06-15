"""Pack-hunt detector and gateway orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from itertools import pairwise

from ix_packhunt_guard.classifier import RuleBasedIntentClassifier
from ix_packhunt_guard.graph import CapabilityAssemblyGraph
from ix_packhunt_guard.schema import (
    CampaignWindow,
    CapabilityTag,
    DecisionAction,
    DetectionDecision,
    EvidenceRef,
    GatewayObservation,
    IntentFragment,
    RiskSignal,
)


@dataclass(frozen=True)
class DetectorThresholds:
    """Tunable deterministic thresholds for gateway decisions."""

    warn: float = 3.0
    rate_limit: float = 4.5
    require_review: float = 6.0
    block: float = 8.0
    lock_session: float = 10.5
    window_minutes: int = 60

    def __post_init__(self) -> None:
        ordered = (
            self.warn,
            self.rate_limit,
            self.require_review,
            self.block,
            self.lock_session,
        )
        if any(left > right for left, right in pairwise(ordered)):
            raise ValueError("thresholds must be non-decreasing")
        if self.window_minutes <= 0:
            raise ValueError("window_minutes must be positive")


@dataclass
class PackHuntDetector:
    """Detect prompt-decomposition and coordinated-abuse patterns.

    The detector does not decide whether a person is guilty or malicious. It
    decides whether the current request stream has crossed a governance boundary
    and must be slowed, reviewed, blocked, or exported for audit.
    """

    classifier: RuleBasedIntentClassifier = field(
        default_factory=RuleBasedIntentClassifier
    )
    graph: CapabilityAssemblyGraph = field(default_factory=CapabilityAssemblyGraph)
    thresholds: DetectorThresholds = field(default_factory=DetectorThresholds)

    def observe(
        self,
        observation: GatewayObservation,
    ) -> tuple[IntentFragment, CampaignWindow, DetectionDecision]:
        fragment = self.classifier.classify(observation)
        self.graph.add_fragment(fragment)

        now = _parse_dt(fragment.observed_at)
        window = self.graph.summarize_tenant_window(
            tenant_id=fragment.tenant_id,
            now=now,
            window=timedelta(minutes=self.thresholds.window_minutes),
        )
        decision = self.decide(window=window, latest_fragment=fragment)

        return fragment, window, decision

    def decide(
        self,
        window: CampaignWindow,
        latest_fragment: IntentFragment,
    ) -> DetectionDecision:
        score = window.assembly_score
        trigger_signals = set(window.risk_signals)
        reason = "No coordinated restricted-capability assembly detected."
        action = DecisionAction.ALLOW
        human_review = False

        if self._single_fragment_must_block(latest_fragment):
            action = DecisionAction.BLOCK_RESPONSE
            score = max(score, self.thresholds.block)
            trigger_signals.update(latest_fragment.risk_signals)
            reason = (
                "Latest fragment contains direct policy-bypass or "
                "evidence-suppression pressure tied to restricted capability "
                "labels."
            )
            human_review = True
        elif score >= self.thresholds.lock_session:
            action = DecisionAction.LOCK_SESSION
            reason = "Coordinated assembly risk exceeded lock-session threshold."
            human_review = True
        elif score >= self.thresholds.block:
            action = DecisionAction.BLOCK_RESPONSE
            reason = "Capability assembly graph crossed the block threshold."
            human_review = True
        elif score >= self.thresholds.require_review:
            action = DecisionAction.REQUIRE_REVIEW
            reason = (
                "Capability assembly graph requires human review before "
                "continuing."
            )
            human_review = True
        elif score >= self.thresholds.rate_limit:
            action = DecisionAction.RATE_LIMIT
            reason = (
                "Request stream resembles low-and-slow capability assembly; "
                "rate limit recommended."
            )
        elif score >= self.thresholds.warn:
            action = DecisionAction.WARN
            reason = (
                "Early coordination signals detected; preserve evidence and "
                "continue monitoring."
            )

        evidence_items = [
            EvidenceRef(
                kind="latest-fragment",
                digest=latest_fragment.evidence_hash,
                note="Hash of normalized latest gateway fragment.",
            ),
            EvidenceRef(
                kind="campaign-window",
                digest=window.evidence_hash,
                note="Hash of current capability assembly window.",
            ),
        ]

        if human_review:
            evidence_items.append(
                EvidenceRef(
                    kind="human-authority-required",
                    digest=window.evidence_hash,
                    note=(
                        "Decision requires human review before the gateway "
                        "should continue unrestricted output."
                    ),
                )
            )

        return DetectionDecision(
            action=action,
            reason=reason,
            risk_score=round(score, 2),
            required_human_review=human_review,
            trigger_signals=tuple(sorted(trigger_signals, key=lambda item: item.value)),
            fragment_ids=window.fragment_ids,
            evidence=tuple(evidence_items),
        )

    def _single_fragment_must_block(self, fragment: IntentFragment) -> bool:
        restricted = any(
            tag is not CapabilityTag.UNKNOWN for tag in fragment.capability_tags
        )
        bypass = RiskSignal.POLICY_BYPASS in fragment.risk_signals
        suppression = RiskSignal.EVIDENCE_SUPPRESSION in fragment.risk_signals
        escalation = RiskSignal.AUTHORITY_GRANT_ATTEMPT in fragment.risk_signals

        return restricted and (bypass or suppression or escalation)


def _parse_dt(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is not None:
        return parsed.replace(tzinfo=None)
    return parsed
