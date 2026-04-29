from policy import decide_action


def test_secret_to_ai_model_blocks() -> None:
    decision = decide_action(
        spans=[{"label": "secret"}],
        source="manual_ui",
        target="ai_model",
        mode="warn",
    )

    assert decision["decision"] == "block"
    assert decision["risk_level"] == "high"


def test_url_to_local_review_warns() -> None:
    decision = decide_action(
        spans=[{"label": "private_url"}],
        source="manual_ui",
        target="local_review",
        mode="warn",
    )

    assert decision["decision"] == "warn"
