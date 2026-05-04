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


def test_detects_mongodb_srv_connection_string() -> None:
    text = "mongodb+srv://analytics:AnalyTics!Pass@cluster0.abcde.mongodb.net/prod"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["kind"] == "db_connection"
    assert spans[0]["text"] == "AnalyTics!Pass"


def test_detects_private_key_block_as_single_secret() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQCqGK7UO5jX4Z...\n-----END RSA PRIVATE KEY-----"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["kind"] == "private_key"
    assert spans[0]["start"] == 0
    assert spans[0]["end"] == len(text)
    assert spans[0]["text"] == text


def test_detects_webhook_secret_label() -> None:
    text = "webhook_secret=whsec_testsecretvalue1234567890"

    spans = detect_regex_secret_spans(text, "balanced")

    # whsec_ matches both the named-assignment pattern (webhook_secret)
    # and the prefix api_key pattern — at least one span must be present
    assert len(spans) >= 1
    kinds = {s["kind"] for s in spans}
    assert kinds & {"webhook_secret", "api_key"}


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


def test_detects_hf_token_with_suffix_padding() -> None:
    text = "HF_TOKEN = hf_ThisIsATestTokenWithPad_1234567890ABCDEF"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["kind"] == "api_key"
    assert spans[0]["text"] == "hf_ThisIsATestTokenWithPad_1234567890ABCDEF"


def test_detects_stripe_live_key() -> None:
    text = "STRIPE_SECRET_KEY=sk_live_abc123defghijklmnopqrst"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["kind"] == "api_key"
    assert spans[0]["text"] == "sk_live_abc123defghijklmnopqrst"


def test_detects_stripe_test_key() -> None:
    text = "sk_test_oldvalue123456789012"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["kind"] == "api_key"
    assert spans[0]["text"] == "sk_test_oldvalue123456789012"


def test_token_span_covers_value_only_not_key() -> None:
    text = "github_actions_example = https://github.com/actions/checkout@v4?token=ghp_demo123"

    spans = detect_regex_secret_spans(text, "balanced")

    token_spans = [s for s in spans if s["kind"] == "token"]
    assert len(token_spans) == 1
    assert token_spans[0]["text"] == "ghp_demo123"
    assert "token=" not in token_spans[0]["text"]


def test_webhook_secret_span_covers_value_only() -> None:
    text = "client_secret=mysecretvalue1234"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["kind"] == "webhook_secret"
    assert spans[0]["text"] == "mysecretvalue1234"
    assert "client_secret" not in spans[0]["text"]


def test_session_cookie_span_covers_value_only() -> None:
    text = "Set-Cookie: session=abc123def456ghi789; HttpOnly"

    spans = detect_regex_secret_spans(text, "balanced")

    session_spans = [s for s in spans if s["kind"] == "session"]
    assert len(session_spans) == 1
    assert session_spans[0]["text"] == "abc123def456ghi789"
    assert "Set-Cookie" not in session_spans[0]["text"]
    assert "session=" not in session_spans[0]["text"]


def test_bearer_span_covers_token_only() -> None:
    text = "Authorization: Bearer mytoken1234567890abcdef"

    spans = detect_regex_secret_spans(text, "balanced")

    bearer_spans = [s for s in spans if s["kind"] == "bearer"]
    assert len(bearer_spans) == 1
    assert bearer_spans[0]["text"] == "mytoken1234567890abcdef"
    assert "Bearer" not in bearer_spans[0]["text"]
