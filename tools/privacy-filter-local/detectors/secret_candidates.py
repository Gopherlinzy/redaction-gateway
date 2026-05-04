import re

from detectors.structured_parser import parse_structured_fragments


API_KEY_PATTERN = re.compile(
    r"^(?:sk[-_][A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{20,}|hf_[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16})$"
)
JWT_PATTERN = re.compile(r"^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
DB_CONNECTION_PATTERN = re.compile(
    r"^(?P<prefix>(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^:\s]+:)"
    r"(?P<password>[^@\s]+)"
    r"(?P<suffix>@[^\/\s]+\/[^\s]+)$",
    re.IGNORECASE,
)
PEM_VALUE_PATTERN = re.compile(
    r"^-----BEGIN [A-Z ]*PRIVATE KEY-----(?:(?:\\n)|\n)[\s\S]+?(?:(?:\\n)|\n)-----END [A-Z ]*PRIVATE KEY-----$"
)
TOKEN_KEY_NAMES = {
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "client_secret",
    "app_secret",
    "webhook_secret",
    "signing_secret",
    "database_url",
}
SESSION_COOKIE_NAMES = {
    "sessionid",
    "session",
    "connect.sid",
    "sid",
}
SECRET_VALUE_SHAPE_PATTERN = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9._-]{12,}$")


def generate_secret_candidates(text: str) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []

    for fragment in parse_structured_fragments(text):
        structure_kind = fragment.get("structure_kind")
        if structure_kind == "assignment":
            fragment_candidates = _candidate_for_assignment(text, fragment)
        elif structure_kind == "http_header":
            fragment_candidates = _candidate_for_http_header(text, fragment)
        elif structure_kind == "cookie_pair":
            fragment_candidates = _candidate_for_cookie_pair(text, fragment)
        elif structure_kind == "json_yaml_pair":
            fragment_candidates = _candidate_for_json_yaml(text, fragment)
        elif structure_kind == "log_sentence":
            fragment_candidates = _candidate_for_log_sentence(text, fragment)
        else:
            fragment_candidates = []

        candidates.extend(fragment_candidates)

    return candidates


def _candidate_for_assignment(text: str, fragment: dict[str, object]) -> list[dict[str, object]]:
    value, span = _value_from_fragment(text, fragment, "value_span")
    if value is None or span is None:
        return []

    if API_KEY_PATTERN.match(value):
        return [_build_candidate(span, text, "api_key", 0.9, ["structure_match", "value_shape_match"])]

    db_password_span = _db_password_span(span, value)
    if db_password_span is not None:
        return [_build_candidate(db_password_span, text, "db_connection", 0.9, ["structure_match", "value_shape_match"])]

    if _looks_like_private_key_value(value):
        return [
            _build_candidate(
                span,
                text,
                "private_key",
                0.95,
                ["structure_match", "key_name_match", "pem_block_match"],
            )
        ]

    if _is_token_key(fragment) and _looks_like_token_value(value):
        return [
            _build_candidate(
                span,
                text,
                "token",
                0.75,
                ["structure_match", "key_name_match", "value_shape_match"],
            )
        ]

    if JWT_PATTERN.match(value):
        return [_build_candidate(span, text, "jwt", 0.9, ["structure_match", "value_shape_match"])]

    return []


def _candidate_for_http_header(text: str, fragment: dict[str, object]) -> list[dict[str, object]]:
    value, span = _value_from_fragment(text, fragment, "value_span")
    if value is None or span is None:
        return []

    if API_KEY_PATTERN.match(value):
        return [_build_candidate(span, text, "api_key", 0.9, ["structure_match", "value_shape_match"])]

    if JWT_PATTERN.match(value):
        return [_build_candidate(span, text, "jwt", 0.9, ["structure_match", "value_shape_match"])]

    return [_build_candidate(span, text, "bearer", 0.8, ["structure_match", "value_shape_match"])]


def _candidate_for_cookie_pair(text: str, fragment: dict[str, object]) -> list[dict[str, object]]:
    value, span = _value_from_fragment(text, fragment, "value_span")
    if value is None or span is None:
        return []

    cookie_name = fragment.get("cookie_name")
    if not isinstance(cookie_name, str):
        return []

    if cookie_name.lower() not in SESSION_COOKIE_NAMES:
        if cookie_name.lower() not in TOKEN_KEY_NAMES:
            return []
        if not _looks_like_token_value(value):
            return []
        return [
            _build_candidate(
                span,
                text,
                "token",
                0.75,
                ["structure_match", "key_name_match", "value_shape_match"],
            )
        ]

    if not _looks_like_session_cookie_value(value):
        return []

    return [_build_candidate(span, text, "session", 0.8, ["structure_match", "value_shape_match"])]


def _candidate_for_json_yaml(text: str, fragment: dict[str, object]) -> list[dict[str, object]]:
    value, span = _value_from_fragment(text, fragment, "value_span")
    if value is None or span is None:
        return []

    if API_KEY_PATTERN.match(value):
        return [_build_candidate(span, text, "api_key", 0.9, ["structure_match", "value_shape_match"])]

    db_password_span = _db_password_span(span, value)
    if db_password_span is not None:
        return [_build_candidate(db_password_span, text, "db_connection", 0.9, ["structure_match", "value_shape_match"])]

    if _looks_like_private_key_value(value):
        return [
            _build_candidate(
                span,
                text,
                "private_key",
                0.95,
                ["structure_match", "key_name_match", "pem_block_match"],
            )
        ]

    if _is_token_key(fragment) and _looks_like_token_value(value):
        return [
            _build_candidate(
                span,
                text,
                "token",
                0.75,
                ["structure_match", "key_name_match", "value_shape_match"],
            )
        ]

    return []


def _candidate_for_log_sentence(text: str, fragment: dict[str, object]) -> list[dict[str, object]]:
    span = fragment.get("candidate_span")
    candidate_value = fragment.get("candidate_value")
    if not isinstance(span, tuple) or not isinstance(candidate_value, str):
        return []

    return [_build_candidate(span, text, "verification_code", 0.65, ["structure_match", "context_match"])]


def _build_candidate(
    span: tuple[int, int],
    text: str,
    kind: str,
    score: float,
    reason_codes: list[str],
) -> dict[str, object]:
    start, end = span
    return {
        "label": "secret",
        "kind": kind,
        "source": "parser_rule",
        "score": score,
        "reason_codes": reason_codes,
        "start": start,
        "end": end,
        "text": text[start:end],
    }


def _value_from_fragment(
    text: str,
    fragment: dict[str, object],
    span_key: str,
) -> tuple[str | None, tuple[int, int] | None]:
    span = fragment.get(span_key)
    if not isinstance(span, tuple) or len(span) != 2:
        return None, None

    start, end = span
    return text[start:end], (start, end)


def _is_token_key(fragment: dict[str, object]) -> bool:
    key = fragment.get("key")
    if not isinstance(key, str):
        return False

    return key.lower() in TOKEN_KEY_NAMES


def _looks_like_token_value(value: str) -> bool:
    return bool(SECRET_VALUE_SHAPE_PATTERN.fullmatch(value))


def _looks_like_session_cookie_value(value: str) -> bool:
    return len(value) >= 8 and bool(re.fullmatch(r"[A-Za-z0-9._-]+", value))


def _db_password_span(value_span: tuple[int, int], value: str) -> tuple[int, int] | None:
    match = DB_CONNECTION_PATTERN.match(value)
    if not match:
        return None

    start, _ = value_span
    return (start + match.start("password"), start + match.end("password"))


def _looks_like_private_key_value(value: str) -> bool:
    return bool(PEM_VALUE_PATTERN.match(value))
