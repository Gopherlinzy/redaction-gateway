from policy import decide_action


def test_secret_to_ai_model_warns_with_high_risk() -> None:
    decision = decide_action(
        spans=[{"label": "secret", "kind": "bearer"}],
        source="manual_ui",
        target="ai_model",
        mode="warn",
    )

    assert decision["decision"] == "warn"
    assert decision["risk_level"] == "high"
    assert decision["reason"] == "secret detected"


def test_url_to_local_review_warns() -> None:
    decision = decide_action(
        spans=[{"label": "private_url"}],
        source="manual_ui",
        target="local_review",
        mode="warn",
    )

    assert decision["decision"] == "warn"
