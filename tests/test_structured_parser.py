from detectors.structured_parser import parse_structured_fragments


def test_parses_env_assignment_value_span() -> None:
    text = "access_token = demo_access_token_abcdef1234567890"

    fragments = parse_structured_fragments(text)

    assert fragments == [
        {
            "structure_kind": "assignment",
            "raw_fragment": text,
            "fragment_span": (0, len(text)),
            "prefix": "",
            "key": "access_token",
            "separator": " = ",
            "value": "demo_access_token_abcdef1234567890",
            "quote_char": "",
            "line_span": (0, len(text)),
            "value_span": (15, len(text)),
        }
    ]


def test_parses_http_bearer_value_span() -> None:
    text = "Authorization: Bearer sk-testsecretvalue1234567890"

    fragments = parse_structured_fragments(text)

    assert fragments == [
        {
            "structure_kind": "http_header",
            "raw_fragment": text,
            "fragment_span": (0, len(text)),
            "header_name": "Authorization",
            "auth_scheme": "Bearer",
            "separator": ": ",
            "value": "sk-testsecretvalue1234567890",
            "value_span": (22, len(text)),
        }
    ]


def test_parses_json_pair_value_span() -> None:
    text = '"client_secret": "demo_client_secret_abcdef123456"'

    fragments = parse_structured_fragments(text)

    assert fragments == [
        {
            "structure_kind": "json_yaml_pair",
            "raw_fragment": text,
            "fragment_span": (0, len(text)),
            "container_kind": "json",
            "key": "client_secret",
            "separator": ": ",
            "value": "demo_client_secret_abcdef123456",
            "quote_char": '"',
            "value_span": (18, len(text) - 1),
        }
    ]


def test_parses_yaml_pair_value_span() -> None:
    text = "client_secret: demo_client_secret_abcdef123456"

    fragments = parse_structured_fragments(text)

    assert fragments == [
        {
            "structure_kind": "json_yaml_pair",
            "raw_fragment": text,
            "fragment_span": (0, len(text)),
            "container_kind": "yaml",
            "key": "client_secret",
            "separator": ": ",
            "value": "demo_client_secret_abcdef123456",
            "quote_char": "",
            "value_span": (15, len(text)),
        }
    ]


def test_parses_cookie_pair_value_span() -> None:
    text = "Cookie: sessionid=abc123def456ghi789; theme=dark"

    fragments = parse_structured_fragments(text)

    assert fragments == [
        {
            "structure_kind": "cookie_pair",
            "raw_fragment": text,
            "fragment_span": (0, len(text)),
            "header_name": "Cookie",
            "cookie_name": "sessionid",
            "separator": "=",
            "value": "abc123def456ghi789",
            "value_span": (18, 36),
        },
        {
            "structure_kind": "cookie_pair",
            "raw_fragment": text,
            "fragment_span": (0, len(text)),
            "header_name": "Cookie",
            "cookie_name": "theme",
            "separator": "=",
            "value": "dark",
            "value_span": (44, 48),
        }
    ]


def test_parses_cookie_header_later_pairs() -> None:
    text = "Cookie: sessionid=abc123def456ghi789; theme=dark"

    fragments = parse_structured_fragments(text)

    assert fragments[1] == {
        "structure_kind": "cookie_pair",
        "raw_fragment": text,
        "fragment_span": (0, len(text)),
        "header_name": "Cookie",
        "cookie_name": "theme",
        "separator": "=",
        "value": "dark",
        "value_span": (44, 48),
    }


def test_parses_quoted_yaml_scalar_value_span() -> None:
    text = 'client_secret: "abc123"'

    fragments = parse_structured_fragments(text)

    assert fragments == [
        {
            "structure_kind": "json_yaml_pair",
            "raw_fragment": text,
            "fragment_span": (0, len(text)),
            "container_kind": "yaml",
            "key": "client_secret",
            "separator": ": ",
            "value": "abc123",
            "quote_char": '"',
            "value_span": (16, 22),
        }
    ]


def test_parses_hyphenated_json_pair_value_span() -> None:
    text = '"client-secret": "demo-client-secret-abcdef"'

    fragments = parse_structured_fragments(text)

    assert fragments == [
        {
            "structure_kind": "json_yaml_pair",
            "raw_fragment": text,
            "fragment_span": (0, len(text)),
            "container_kind": "json",
            "key": "client-secret",
            "separator": ": ",
            "value": "demo-client-secret-abcdef",
            "quote_char": '"',
            "value_span": (18, len(text) - 1),
        }
    ]


def test_parses_hyphenated_yaml_pair_value_span() -> None:
    text = "api-key: demo-api-key-abcdef"

    fragments = parse_structured_fragments(text)

    assert fragments == [
        {
            "structure_kind": "json_yaml_pair",
            "raw_fragment": text,
            "fragment_span": (0, len(text)),
            "container_kind": "yaml",
            "key": "api-key",
            "separator": ": ",
            "value": "demo-api-key-abcdef",
            "quote_char": "",
            "value_span": (9, len(text)),
        }
    ]


def test_parses_non_zero_offset_line_spans() -> None:
    prefix = "previous line"
    text = f"{prefix}\nclient_secret: demo_client_secret_abcdef123456"

    fragments = parse_structured_fragments(text)

    assert fragments == [
        {
            "structure_kind": "json_yaml_pair",
            "raw_fragment": "client_secret: demo_client_secret_abcdef123456",
            "fragment_span": (len(prefix) + 1, len(text)),
            "container_kind": "yaml",
            "key": "client_secret",
            "separator": ": ",
            "value": "demo_client_secret_abcdef123456",
            "quote_char": "",
            "value_span": (len(prefix) + 1 + 15, len(text)),
        }
    ]


def test_parses_otp_as_log_sentence() -> None:
    text = "OTP: 123456"

    fragments = parse_structured_fragments(text)

    assert fragments == [
        {
            "structure_kind": "log_sentence",
            "raw_fragment": text,
            "fragment_span": (0, len(text)),
            "context_phrase": "OTP:",
            "candidate_value": "123456",
            "candidate_span": (5, 11),
            "context_span": (0, 4),
        }
    ]


def test_parses_log_sentence_candidate_span() -> None:
    text = "verification code is 128841"

    fragments = parse_structured_fragments(text)

    assert fragments == [
        {
            "structure_kind": "log_sentence",
            "raw_fragment": text,
            "fragment_span": (0, len(text)),
            "context_phrase": "verification code is",
            "candidate_value": "128841",
            "candidate_span": (21, 27),
            "context_span": (0, 20),
        }
    ]


def test_parses_diff_add_line_as_assignment() -> None:
    text = "+OPENAI_API_KEY=sk-testsecret1234567890"

    fragments = parse_structured_fragments(text)

    assert len(fragments) == 1
    assert fragments[0]["structure_kind"] == "assignment"
    assert fragments[0]["key"] == "OPENAI_API_KEY"
    assert fragments[0]["value"] == "sk-testsecret1234567890"


def test_parses_diff_remove_line_as_assignment() -> None:
    text = "-OLD_KEY=sk-oldsecretvalue123456789"

    fragments = parse_structured_fragments(text)

    assert len(fragments) == 1
    assert fragments[0]["structure_kind"] == "assignment"
    assert fragments[0]["key"] == "OLD_KEY"
    assert fragments[0]["value"] == "sk-oldsecretvalue123456789"


def test_parses_diff_context_line_as_assignment() -> None:
    text = " API_KEY=sk-contextsecret12345678"

    fragments = parse_structured_fragments(text)

    assert len(fragments) == 1
    assert fragments[0]["structure_kind"] == "assignment"
    assert fragments[0]["key"] == "API_KEY"
    assert fragments[0]["value"] == "sk-contextsecret12345678"


def test_parses_compressed_json_extracts_all_pairs() -> None:
    text = '{"access_token":"ya29abc123def456","refresh_token":"1token789xyz012345"}'

    fragments = parse_structured_fragments(text)

    assert len(fragments) == 2
    keys = {f["key"] for f in fragments}
    assert keys == {"access_token", "refresh_token"}
    for f in fragments:
        assert f["structure_kind"] == "json_yaml_pair"
        assert f["container_kind"] == "json"


def test_parses_x_api_key_header() -> None:
    text = "X-API-Key: sk_live_abc123defghijklmnopqrst"

    fragments = parse_structured_fragments(text)

    assert len(fragments) == 1
    assert fragments[0]["structure_kind"] == "http_header"
    assert fragments[0]["header_name"] == "X-API-Key"
    assert fragments[0]["value"] == "sk_live_abc123defghijklmnopqrst"


def test_parses_x_auth_token_header() -> None:
    text = "X-Auth-Token: sometoken12345678abcdef"

    fragments = parse_structured_fragments(text)

    assert len(fragments) == 1
    assert fragments[0]["structure_kind"] == "http_header"
    assert fragments[0]["header_name"] == "X-Auth-Token"
    assert fragments[0]["value"] == "sometoken12345678abcdef"
