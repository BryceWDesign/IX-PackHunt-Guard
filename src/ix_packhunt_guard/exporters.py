"""Export detection outcomes into adjacent IX governance packet shapes.

These exporters intentionally return plain dictionaries. That keeps Wave 1 free
of cross-repo imports while still producing stable handoff records for BlackFox,
CognitionKernel, and Autonomy Assurance adapters.
"""

from __future__ import annotations

from typing import Any

from ix_packhunt_guard.schema import CampaignWindow, DetectionDecision, IntentFragment


def blackfox_review_packet(
    *,
    fragment: IntentFragment,
    window: CampaignWindow,
    decision: DetectionDecision,
) -> dict[str, Any]:
    """Return a BlackFox-style review packet."""

    return {
        "packet_type": "blackfox-review-packet",
        "schema_version": "1.0",
        "claim_boundary": (
            "PackHunt Guard recommends gateway action only. It does not grant "
            "execution authority, safety certification, or model approval."
        ),
        "recommended_action": decision.action.value,
        "requires_human_review": decision.required_human_review,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "tenant_id": fragment.tenant_id,
        "latest_fragment_id": fragment.fragment_id,
        "campaign_fragment_ids": list(window.fragment_ids),
        "trigger_signals": [signal.value for signal in decision.trigger_signals],
        "capability_tags": [tag.value for tag in window.capability_tags],
        "intent_kinds": [kind.value for kind in window.intent_kinds],
        "evidence": [item.to_record() for item in decision.evidence],
        "decision_hash": decision.evidence_hash,
        "window_hash": window.evidence_hash,
        "latest_fragment_hash": fragment.evidence_hash,
        "authority": {
            "model_may_self_approve": False,
            "human_review_required": decision.required_human_review,
            "execution_authority_granted": False,
        },
    }


def cognition_kernel_risk_record(
    *,
    fragment: IntentFragment,
    window: CampaignWindow,
    decision: DetectionDecision,
) -> dict[str, Any]:
    """Return a CognitionKernel-style risk/refusal record."""

    return {
        "record_type": "cognition-kernel-risk-record",
        "schema_version": "1.0",
        "risk_family": "prompt-decomposition-coordinated-abuse",
        "recommended_refusal_or_review": decision.action.value,
        "risk_score": decision.risk_score,
        "reason": decision.reason,
        "latest_fragment": {
            "fragment_id": fragment.fragment_id,
            "intent_kinds": [kind.value for kind in fragment.intent_kinds],
            "capability_tags": [tag.value for tag in fragment.capability_tags],
            "risk_signals": [signal.value for signal in fragment.risk_signals],
            "goal_atoms": list(fragment.goal_atoms),
            "evidence_hash": fragment.evidence_hash,
        },
        "campaign_window": {
            "fragment_ids": list(window.fragment_ids),
            "principal_count": len(window.principal_ids),
            "session_count": len(window.session_ids),
            "intent_kinds": [kind.value for kind in window.intent_kinds],
            "capability_tags": [tag.value for tag in window.capability_tags],
            "risk_signals": [signal.value for signal in window.risk_signals],
            "assembly_score": window.assembly_score,
            "evidence_hash": window.evidence_hash,
        },
        "doctrine": {
            "output_is_not_evidence": True,
            "memory_is_not_truth": True,
            "persuasion_cannot_override_evidence": True,
            "human_authority_preserved": decision.required_human_review,
        },
    }


def autonomy_assurance_bundle(
    *,
    fragment: IntentFragment,
    window: CampaignWindow,
    decision: DetectionDecision,
) -> dict[str, Any]:
    """Return an Autonomy Assurance-style evidence bundle."""

    return {
        "bundle_type": "autonomy-assurance-evidence-bundle",
        "schema_version": "1.0",
        "mission_need": (
            "Prevent individually low-risk AI requests from assembling into "
            "restricted capability output across sessions, principals, agents, "
            "or time."
        ),
        "requirement": (
            "The gateway shall detect coordinated prompt-decomposition and "
            "policy-bypass patterns, preserve evidence, and require human "
            "authority before unrestricted continuation when thresholds are "
            "crossed."
        ),
        "hazard": {
            "name": "coordinated-capability-assembly",
            "description": (
                "Distributed request fragments may compose into restricted "
                "capability guidance while each fragment appears individually "
                "low risk."
            ),
        },
        "control": {
            "name": "packhunt-guard-gateway",
            "decision_action": decision.action.value,
            "human_review_required": decision.required_human_review,
            "model_self_approval_allowed": False,
        },
        "evidence_chain": [
            item.to_record()
            for item in (
                *fragment.evidence,
                *decision.evidence,
            )
        ],
        "trace": {
            "tenant_id": fragment.tenant_id,
            "latest_fragment_id": fragment.fragment_id,
            "campaign_fragment_ids": list(window.fragment_ids),
            "decision_hash": decision.evidence_hash,
            "window_hash": window.evidence_hash,
            "latest_fragment_hash": fragment.evidence_hash,
        },
        "claim_boundary": (
            "This bundle supports review of gateway behavior. It is not a "
            "certification that a model is safe, jailbreak-proof, or approved "
            "for deployment."
        ),
    }
