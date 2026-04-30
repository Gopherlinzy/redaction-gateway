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


def test_detects_chinese_dynamic_password() -> None:
    text = "访问系统所需的初始动态口令为：882190。"

    spans = detect_regex_secret_spans(text)

    assert len(spans) == 1
    assert spans[0]["label"] == "secret"
    assert spans[0]["text"] == "882190"


def test_detects_verification_code_with_context() -> None:
    text = "Your verification code is 246810."

    spans = detect_regex_secret_spans(text)

    assert len(spans) == 1
    assert spans[0]["label"] == "secret"
    assert spans[0]["kind"] == "verification_code"
    assert spans[0]["source"] == "regex"
    assert spans[0]["score"] == 0.65
    assert spans[0]["reason_codes"] == ["regex_pattern_match", "context_match"]
    assert spans[0]["text"] == "246810"


def test_detects_jwt_token() -> None:
    text = "jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.signaturepart"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["kind"] == "jwt"


def test_detects_cookie_session_material() -> None:
    text = "Set-Cookie: sessionid=abc123def456ghi789; HttpOnly; Secure"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["kind"] == "session"


def test_detects_database_connection_string() -> None:
    text = "DATABASE_URL=postgres://appuser:supersecret@db.internal:5432/app"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["kind"] == "db_connection"


def test_detects_webhook_secret_label() -> None:
    text = "webhook_secret=whsec_testsecretvalue1234567890"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["kind"] == "webhook_secret"


def test_detects_generic_token_label() -> None:
    text = "token = vx_api_token_1234567890abcdef"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["kind"] == "token"
    assert spans[0]["source"] == "regex"
    assert spans[0]["score"] == 0.75
    assert spans[0]["reason_codes"] == ["regex_pattern_match"]


def test_legacy_regex_keeps_generic_token_rule_for_fallback() -> None:
    text = "token = vx_api_token_1234567890abcdef"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["source"] == "regex"
    assert spans[0]["kind"] == "token"
