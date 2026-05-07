import re

KEY_PATTERN = r"[A-Za-z_][A-Za-z0-9_-]*"

ASSIGNMENT_PATTERN = re.compile(
    r"^[+ -]?(?P<prefix>export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<separator>\s*=\s*)"
    r"(?P<quote_char>['\"]?)(?P<value>.*?)(?P=quote_char)$"
)
AUTHORIZATION_PATTERN = re.compile(
    r"^(?P<header_name>Authorization)(?P<separator>:\s+)"
    r"(?P<auth_scheme>Bearer)\s+(?P<value>.+)$",
    re.IGNORECASE,
)
GENERIC_API_HEADER_PATTERN = re.compile(
    r"^(?P<header_name>X-API-Key|X-Auth-Token|X-Access-Token|X-Secret-Key|X-Client-Secret)"
    r"(?P<separator>:\s+)"
    r"(?P<value>.+)$",
    re.IGNORECASE,
)
COOKIE_HEADER_PATTERN = re.compile(r"^(?P<header_name>Cookie|Set-Cookie):\s+", re.IGNORECASE)
COOKIE_PAIR_PATTERN = re.compile(
    rf"(?P<cookie_name>{KEY_PATTERN})(?P<separator>=)(?P<value>[^;\s]+)"
)
JSON_PAIR_PATTERN = re.compile(
    rf'(?P<key_quote>")(?P<key>{KEY_PATTERN})'
    r'(?P=key_quote)(?P<separator>:\s*)'
    r'(?P<raw_value>"[^"]*"|[^\s,\}]+)'
)
YAML_PAIR_PATTERN = re.compile(
    rf"^(?P<key>{KEY_PATTERN})"
    r"(?P<separator>:\s+)"
    r"(?P<raw_value>.+)$"
)
LOG_SENTENCE_PATTERN = re.compile(
    r"^(?P<context_phrase>verification code is|OTP:|动态口令为：)\s*"
    r"(?P<candidate_value>[A-Za-z0-9-]+)$",
    re.IGNORECASE,
)


def _iter_lines(text: str):
    offset = 0
    for raw_line in text.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        line_end = offset + len(line)
        yield line, offset, line_end
        offset += len(raw_line)


def parse_structured_fragments(text: str) -> list[dict[str, object]]:
    fragments: list[dict[str, object]] = []

    for line, line_start, line_end in _iter_lines(text):
        parsed_fragments = _parse_line(line, line_start, line_end)
        fragments.extend(parsed_fragments)

    return fragments


def _parse_line(line: str, line_start: int, line_end: int) -> list[dict[str, object]]:
    for parser in (
        _parse_assignment,
        _parse_http_header,
        _parse_log_sentence,
        _parse_cookie_pair,
        _parse_json_pair,
        _parse_yaml_pair,
    ):
        fragment = parser(line, line_start, line_end)
        if fragment:
            return fragment if isinstance(fragment, list) else [fragment]

    return []


def _base_fragment(line: str, line_start: int, line_end: int, structure_kind: str) -> dict[str, object]:
    return {
        "structure_kind": structure_kind,
        "raw_fragment": line,
        "fragment_span": (line_start, line_end),
    }


def _parse_assignment(line: str, line_start: int, line_end: int) -> dict[str, object] | None:
    match = ASSIGNMENT_PATTERN.match(line)
    if not match:
        return None

    value_start = line_start + match.start("value")
    value_end = line_start + match.end("value")
    result = _base_fragment(line, line_start, line_end, "assignment")
    result.update(
        {
            "prefix": match.group("prefix") or "",
            "key": match.group("key"),
            "separator": match.group("separator"),
            "value": match.group("value"),
            "quote_char": match.group("quote_char") or "",
            "line_span": (line_start, line_end),
            "value_span": (value_start, value_end),
        }
    )
    return result


def _parse_http_header(line: str, line_start: int, line_end: int) -> dict[str, object] | None:
    match = AUTHORIZATION_PATTERN.match(line)
    if match:
        result = _base_fragment(line, line_start, line_end, "http_header")
        result.update(
            {
                "header_name": match.group("header_name"),
                "auth_scheme": match.group("auth_scheme"),
                "separator": match.group("separator"),
                "value": match.group("value"),
                "value_span": (line_start + match.start("value"), line_start + match.end("value")),
            }
        )
        return result

    match = GENERIC_API_HEADER_PATTERN.match(line)
    if not match:
        return None

    result = _base_fragment(line, line_start, line_end, "http_header")
    result.update(
        {
            "header_name": match.group("header_name"),
            "auth_scheme": "",
            "separator": match.group("separator"),
            "value": match.group("value"),
            "value_span": (line_start + match.start("value"), line_start + match.end("value")),
        }
    )
    return result


def _parse_cookie_pair(line: str, line_start: int, line_end: int) -> list[dict[str, object]] | None:
    header_match = COOKIE_HEADER_PATTERN.match(line)
    if not header_match:
        return None

    fragments: list[dict[str, object]] = []
    value_start = header_match.end()
    for match in COOKIE_PAIR_PATTERN.finditer(line, value_start):
        fragments.append(
            {
                **_base_fragment(line, line_start, line_end, "cookie_pair"),
                "header_name": header_match.group("header_name"),
                "cookie_name": match.group("cookie_name"),
                "separator": match.group("separator"),
                "value": match.group("value"),
                "value_span": (line_start + match.start("value"), line_start + match.end("value")),
            }
        )

    return fragments


def _parse_json_pair(line: str, line_start: int, line_end: int) -> list[dict[str, object]] | None:
    fragments: list[dict[str, object]] = []
    for match in JSON_PAIR_PATTERN.finditer(line):
        quote_char, value = _parse_scalar_value(match.group("raw_value"))
        result = _base_fragment(line, line_start, line_end, "json_yaml_pair")
        result.update(
            {
                "container_kind": "json",
                "key": match.group("key"),
                "separator": match.group("separator"),
                "value": value,
                "quote_char": quote_char,
                "value_span": _value_span(line_start, match.start("raw_value"), match.group("raw_value"), quote_char),
            }
        )
        fragments.append(result)
    return fragments or None


def _parse_yaml_pair(line: str, line_start: int, line_end: int) -> dict[str, object] | None:
    match = YAML_PAIR_PATTERN.match(line)
    if not match:
        return None

    quote_char, value = _parse_scalar_value(match.group("raw_value"))

    result = _base_fragment(line, line_start, line_end, "json_yaml_pair")
    result.update(
        {
            "container_kind": "yaml",
            "key": match.group("key"),
            "separator": match.group("separator"),
            "value": value,
            "quote_char": quote_char,
            "value_span": _value_span(line_start, match.start("raw_value"), match.group("raw_value"), quote_char),
        }
    )
    return result


def _parse_log_sentence(line: str, line_start: int, line_end: int) -> dict[str, object] | None:
    match = LOG_SENTENCE_PATTERN.match(line)
    if not match:
        return None

    context_end = line_start + match.end("context_phrase")
    result = _base_fragment(line, line_start, line_end, "log_sentence")
    result.update(
        {
            "context_phrase": match.group("context_phrase"),
            "candidate_value": match.group("candidate_value"),
            "candidate_span": (line_start + match.start("candidate_value"), line_start + match.end("candidate_value")),
            "context_span": (line_start, context_end),
        }
    )
    return result


def _parse_scalar_value(raw_value: str) -> tuple[str, str]:
    if len(raw_value) >= 2 and raw_value[0] == raw_value[-1] and raw_value[0] in {"'", '"'}:
        return raw_value[0], raw_value[1:-1]

    return "", raw_value


def _value_span(line_start: int, raw_value_start: int, raw_value: str, quote_char: str) -> tuple[int, int]:
    if quote_char:
        return (
            line_start + raw_value_start + 1,
            line_start + raw_value_start + len(raw_value) - 1,
        )

    return (line_start + raw_value_start, line_start + raw_value_start + len(raw_value))
