from adapters.linear import build_redact_payload


def test_builds_linear_comment_payload() -> None:
    payload = build_redact_payload("customer email is a@b.c", source="linear_comment")

    assert payload["target"] == "linear"
    assert payload["mode"] == "redact"
    assert payload["source"] == "linear_comment"
