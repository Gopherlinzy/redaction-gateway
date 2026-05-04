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


def test_strict_is_alias_for_high_precision() -> None:
    # weak context "code 246810" passes high_recall but not high_precision/strict
    text = "login helper text: code 246810"
    assert detect_regex_secret_spans(text, "strict") == []
    assert detect_regex_secret_spans(text, "high_precision") == []


def test_permissive_is_alias_for_high_recall() -> None:
    text = "login helper text: code 246810"
    spans_permissive = detect_regex_secret_spans(text, "permissive")
    spans_high_recall = detect_regex_secret_spans(text, "high_recall")
    assert len(spans_permissive) == len(spans_high_recall) == 1
    assert spans_permissive[0]["kind"] == "verification_code"


def test_normalize_mode_unknown_falls_back_to_balanced() -> None:
    from detectors.regex_backstop import normalize_detection_mode
    assert normalize_detection_mode("unknown_mode") == "balanced"
    assert normalize_detection_mode("strict") == "high_precision"
    assert normalize_detection_mode("permissive") == "high_recall"
