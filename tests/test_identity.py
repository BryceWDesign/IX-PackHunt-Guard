from ix_packhunt_guard import PseudonymousIdentityProvider


def test_pseudonymous_identity_is_stable_and_non_raw() -> None:
    provider = PseudonymousIdentityProvider(
        secret=b"0123456789abcdef0123456789abcdef",
        deployment_id="test-deploy",
    )

    first = provider.principal("User@example.com")
    second = provider.principal("user@example.com")

    assert first == second
    assert first.startswith("ixpg_principal_")
    assert "user@example.com" not in first


def test_pseudonymous_identity_rejects_short_secret() -> None:
    try:
        PseudonymousIdentityProvider(secret=b"short", deployment_id="test")
    except ValueError as exc:
        assert "secret" in str(exc)
    else:
        raise AssertionError("short secret should fail")
