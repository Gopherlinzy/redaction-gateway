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
