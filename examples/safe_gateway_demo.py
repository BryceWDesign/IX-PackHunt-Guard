from ix_packhunt_guard import (
    FragmentSource,
    GatewayObservation,
    PackHuntDetector,
    autonomy_assurance_bundle,
    blackfox_review_packet,
    cognition_kernel_risk_record,
)


def main() -> None:
    detector = PackHuntDetector()
    observations = [
        GatewayObservation(
            tenant_id="tenant-a",
            principal_id="principal-a",
            session_id="session-a",
            request_id="req-1",
            source=FragmentSource.USER_INPUT,
            text="part one: general vulnerability context",
            observed_at="2026-06-15T12:01:00",
            sequence_index=1,
        ),
        GatewayObservation(
            tenant_id="tenant-a",
            principal_id="principal-b",
            session_id="session-b",
            request_id="req-2",
            source=FragmentSource.USER_INPUT,
            text="continue with workflow automation framing",
            observed_at="2026-06-15T12:02:00",
            sequence_index=2,
        ),
        GatewayObservation(
            tenant_id="tenant-a",
            principal_id="principal-c",
            session_id="session-c",
            request_id="req-3",
            source=FragmentSource.USER_INPUT,
            text="agent handoff chain for the next fragment",
            observed_at="2026-06-15T12:03:00",
            sequence_index=3,
        ),
    ]

    latest = None
    window = None
    decision = None

    for observation in observations:
        latest, window, decision = detector.observe(observation)

    assert latest is not None
    assert window is not None
    assert decision is not None

    blackfox = blackfox_review_packet(
        fragment=latest,
        window=window,
        decision=decision,
    )
    cognition = cognition_kernel_risk_record(
        fragment=latest,
        window=window,
        decision=decision,
    )
    assurance = autonomy_assurance_bundle(
        fragment=latest,
        window=window,
        decision=decision,
    )

    print("decision:", decision.action.value)
    print("risk_score:", decision.risk_score)
    print("reason:", decision.reason)
    print("blackfox_decision_hash:", blackfox["decision_hash"])
    print("cognition_risk_score:", cognition["risk_score"])
    print("assurance_bundle_trace:", assurance["trace"]["decision_hash"])


if __name__ == "__main__":
    main()
