from detectors.regex_backstop import detect_regex_secret_spans


def test_high_recall_catches_weak_verification_code_context() -> None:
    text = "login helper text: code 246810"

    spans = detect_regex_secret_spans(text, "high_recall")

    assert len(spans) == 1
    assert spans[0]["kind"] == "verification_code"


def test_high_precision_skips_weak_verification_code_context() -> None:
    text = "login helper text: code 246810"

    spans = detect_regex_secret_spans(text, "high_precision")

    assert spans == []


def test_strong_jwt_matches_in_high_precision() -> None:
    text = "jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.signaturepart"

    spans = detect_regex_secret_spans(text, "high_precision")

    assert len(spans) == 1
    assert spans[0]["kind"] == "jwt"
