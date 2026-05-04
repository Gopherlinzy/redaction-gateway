from adapters.symphony import build_decide_payload


def test_builds_prompt_payload_for_symphony() -> None:
    payload = build_decide_payload("token=sk-123456789012", source="symphony_prompt")

    assert payload["target"] == "ai_model"
    assert payload["mode"] == "block"
    assert payload["source"] == "symphony_prompt"
