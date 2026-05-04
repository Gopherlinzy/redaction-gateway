from detectors.secret_candidates import generate_secret_candidates


def test_assignment_candidate_only_covers_value() -> None:
    text = "access_token = demo_access_token_abcdef1234567890"

    candidates = generate_secret_candidates(text)

    assert candidates == [
        {
            "label": "secret",
            "kind": "token",
            "source": "parser_rule",
            "score": 0.75,
            "reason_codes": ["structure_match", "key_name_match", "value_shape_match"],
            "start": 15,
            "end": len(text),
            "text": "demo_access_token_abcdef1234567890",
        }
    ]


def test_authorization_candidate_only_covers_bearer_value() -> None:
    text = "Authorization: Bearer sk-testsecretvalue1234567890"

    candidates = generate_secret_candidates(text)

    assert candidates == [
        {
            "label": "secret",
            "kind": "api_key",
            "source": "parser_rule",
            "score": 0.9,
            "reason_codes": ["structure_match", "value_shape_match"],
            "start": 22,
            "end": len(text),
            "text": "sk-testsecretvalue1234567890",
        }
    ]


def test_log_sentence_candidate_only_covers_short_code() -> None:
    text = "verification code is 128841"

    candidates = generate_secret_candidates(text)

    assert candidates == [
        {
            "label": "secret",
            "kind": "verification_code",
            "source": "parser_rule",
            "score": 0.65,
            "reason_codes": ["structure_match", "context_match"],
            "start": 21,
            "end": 27,
            "text": "128841",
        }
    ]


def test_cookie_pair_skips_theme_cookie() -> None:
    text = "Cookie: theme=dark"

    candidates = generate_secret_candidates(text)

    assert candidates == []


def test_cookie_pair_detects_session_cookie() -> None:
    text = "Set-Cookie: sessionid=abc123def456ghi789; HttpOnly; Secure"

    candidates = generate_secret_candidates(text)

    assert candidates == [
        {
            "label": "secret",
            "kind": "session",
            "source": "parser_rule",
            "score": 0.8,
            "reason_codes": ["structure_match", "value_shape_match"],
            "start": 22,
            "end": 40,
            "text": "abc123def456ghi789",
        }
    ]


def test_cookie_pair_detects_refresh_token_value_only() -> None:
    text = "Set-Cookie: refresh_token=7a8s9d0f1g2h3j4k5l6; HttpOnly; Secure"

    candidates = generate_secret_candidates(text)

    assert candidates == [
        {
            "label": "secret",
            "kind": "token",
            "source": "parser_rule",
            "score": 0.75,
            "reason_codes": ["structure_match", "key_name_match", "value_shape_match"],
            "start": 26,
            "end": 45,
            "text": "7a8s9d0f1g2h3j4k5l6",
        }
    ]


def test_json_yaml_pair_detects_token_value() -> None:
    text = '"client_secret": "demo_client_secret_abcdef123456"'

    candidates = generate_secret_candidates(text)

    assert candidates == [
        {
            "label": "secret",
            "kind": "token",
            "source": "parser_rule",
            "score": 0.75,
            "reason_codes": ["structure_match", "key_name_match", "value_shape_match"],
            "start": 18,
            "end": len(text) - 1,
            "text": "demo_client_secret_abcdef123456",
        }
    ]


def test_assignment_candidate_detects_mongodb_srv_value_only() -> None:
    text = "DATABASE_URL=mongodb+srv://analytics:AnalyTics!Pass@cluster0.abcde.mongodb.net/prod"

    candidates = generate_secret_candidates(text)

    assert candidates == [
        {
            "label": "secret",
            "kind": "db_connection",
            "source": "parser_rule",
            "score": 0.9,
            "reason_codes": ["structure_match", "value_shape_match"],
            "start": 37,
            "end": 51,
            "text": "AnalyTics!Pass",
        }
    ]


def test_assignment_candidate_detects_hf_token_full_value() -> None:
    text = "HF_TOKEN = hf_ThisIsATestTokenWithPad_1234567890ABCDEF"

    candidates = generate_secret_candidates(text)

    assert candidates == [
        {
            "label": "secret",
            "kind": "api_key",
            "source": "parser_rule",
            "score": 0.9,
            "reason_codes": ["structure_match", "value_shape_match"],
            "start": 11,
            "end": len(text),
            "text": "hf_ThisIsATestTokenWithPad_1234567890ABCDEF",
        }
    ]


def test_assignment_candidate_detects_stripe_live_key() -> None:
    text = "STRIPE_SECRET_KEY=sk_live_abc123defghijklmnopqrst"

    candidates = generate_secret_candidates(text)

    assert len(candidates) == 1
    assert candidates[0]["kind"] == "api_key"
    assert candidates[0]["source"] == "parser_rule"
    assert candidates[0]["text"] == "sk_live_abc123defghijklmnopqrst"


def test_assignment_candidate_detects_stripe_test_key() -> None:
    text = "STRIPE_SECRET_KEY=sk_test_oldvalue123456789012"

    candidates = generate_secret_candidates(text)

    assert len(candidates) == 1
    assert candidates[0]["kind"] == "api_key"
    assert candidates[0]["text"] == "sk_test_oldvalue123456789012"


def test_assignment_candidate_detects_key_in_diff_add_line() -> None:
    text = "+OPENAI_API_KEY=sk-testsecret1234567890"

    candidates = generate_secret_candidates(text)

    assert len(candidates) == 1
    assert candidates[0]["kind"] == "api_key"
    assert candidates[0]["source"] == "parser_rule"
    assert candidates[0]["text"] == "sk-testsecret1234567890"


def test_compressed_json_detects_multiple_token_values() -> None:
    text = '{"access_token":"ya29abc123def456","refresh_token":"1token789xyz012345"}'

    candidates = generate_secret_candidates(text)

    assert len(candidates) == 2
    kinds = {c["kind"] for c in candidates}
    assert kinds == {"token"}
    texts = {c["text"] for c in candidates}
    assert texts == {"ya29abc123def456", "1token789xyz012345"}


def test_http_header_candidate_detects_x_api_key() -> None:
    text = "X-API-Key: sk_live_abc123defghijklmnopqrst"

    candidates = generate_secret_candidates(text)

    assert len(candidates) == 1
    assert candidates[0]["kind"] == "api_key"
    assert candidates[0]["source"] == "parser_rule"
    assert candidates[0]["text"] == "sk_live_abc123defghijklmnopqrst"


def test_http_header_candidate_detects_x_auth_token() -> None:
    text = "X-Auth-Token: sometoken12345678abcdef"

    candidates = generate_secret_candidates(text)

    assert len(candidates) == 1
    assert candidates[0]["kind"] == "bearer"
    assert candidates[0]["source"] == "parser_rule"
    assert candidates[0]["text"] == "sometoken12345678abcdef"


def test_assignment_candidate_detects_private_key_value_only() -> None:
    text = 'signing_key = "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADAN...\\n-----END PRIVATE KEY-----"'

    candidates = generate_secret_candidates(text)

    assert candidates == [
        {
            "label": "secret",
            "kind": "private_key",
            "source": "parser_rule",
            "score": 0.95,
            "reason_codes": ["structure_match", "key_name_match", "pem_block_match"],
            "start": 15,
            "end": len(text) - 1,
            "text": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADAN...\\n-----END PRIVATE KEY-----",
        }
    ]
