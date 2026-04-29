from detectors.regex_backstop import detect_regex_secret_spans


def test_detects_openai_key() -> None:
    text = "OPENAI_API_KEY=sk-testsecretvalue1234567890"

    spans = detect_regex_secret_spans(text)

    assert len(spans) == 1
    assert spans[0]["label"] == "secret"
    assert spans[0]["source"] == "regex"


def test_detects_bearer_token() -> None:
    text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"

    spans = detect_regex_secret_spans(text)

    assert len(spans) == 1
    assert spans[0]["label"] == "secret"
