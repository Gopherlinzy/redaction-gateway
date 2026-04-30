# Structured Secret Detector V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把现有 `privacy-filter-local` 的 secret 检测从“全文 regex 主导”升级为“结构化解析 + 规则候选 + 可解释打分 + 模型中度辅助 + legacy 双轨兜底”的混合检测器，并确保输出强保真，只替换 value，不吞掉 key 或整句结构。

**Architecture:** 在保留现有 FastAPI、UI 和 OPF/legacy regex 的前提下，引入一个新的 parser-first secret pipeline。它先把文本解析成结构化片段，再对 value 生成 secret 候选并打分，最后与 legacy regex/OPF 双轨 merge。第一阶段模型辅助只占接口位，不直接主导结果；真实行为先由结构解析、规则和 score 驱动。

**Tech Stack:** Python 3.14, FastAPI, pytest, Pydantic, vanilla HTML/CSS/JavaScript, OPF runtime

---

## File Map

**Worktree root:** `/Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1`

- Create: `tools/privacy-filter-local/detectors/structured_parser.py`
- Create: `tools/privacy-filter-local/detectors/secret_candidates.py`
- Create: `tools/privacy-filter-local/detectors/secret_scores.py`
- Modify: `tools/privacy-filter-local/detectors/regex_backstop.py`
- Modify: `tools/privacy-filter-local/app.py`
- Modify: `tools/privacy-filter-local/ui/index.html`
- Modify: `tools/privacy-filter-local/tests/test_gateway.py`
- Modify: `tools/privacy-filter-local/tests/test_regex_backstop.py`
- Create: `tools/privacy-filter-local/tests/test_structured_parser.py`
- Create: `tools/privacy-filter-local/tests/test_secret_candidates.py`
- Create: `tools/privacy-filter-local/tests/test_secret_scores.py`

## Shared Contracts

Use these exact structure kinds:

- `assignment`
- `http_header`
- `cookie_pair`
- `json_yaml_pair`
- `log_sentence`

Use these exact candidate fields:

- `label`
- `kind`
- `source`
- `score`
- `reason_codes`
- `start`
- `end`
- `text`

Use these exact reason codes in first-stage scoring:

- `structure_match`
- `key_name_match`
- `value_shape_match`
- `context_match`
- `model_confirmed`

Use these exact candidate sources:

- `parser_rule`
- `legacy_regex`
- `opf`

First-stage model-assist constraint:

- do not create a live model-calling module in this plan
- do reserve the `model_confirmed` reason code and the score pipeline shape
- treat model assistance as an interface boundary only in V2 baseline

## Task 1: Introduce parser tests and the structured fragment contract

**Files:**
- Create: `tools/privacy-filter-local/tests/test_structured_parser.py`
- Create: `tools/privacy-filter-local/detectors/structured_parser.py`
- Test: `tools/privacy-filter-local/tests/test_structured_parser.py`

- [ ] **Step 1: Write the failing parser tests**

Create `tools/privacy-filter-local/tests/test_structured_parser.py` with these tests:

```python
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
```

- [ ] **Step 2: Run the parser tests to verify they fail**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_structured_parser.py -v`

Expected: FAIL because `structured_parser.py` and `parse_structured_fragments()` do not exist yet.

- [ ] **Step 3: Create the minimal parser implementation**

Create `tools/privacy-filter-local/detectors/structured_parser.py` with:

```python
import re


ASSIGNMENT_PATTERN = re.compile(
    r"^(?P<prefix>export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<separator>\s*=\s*)"
    r"(?P<quote>['\"]?)(?P<value>.*?)(?P=quote)$"
)

AUTHORIZATION_PATTERN = re.compile(
    r"^(?P<header_name>Authorization)(?P<separator>:\s+)(?P<auth_scheme>Bearer)\s+(?P<value>.+)$",
    re.IGNORECASE,
)

COOKIE_PATTERN = re.compile(
    r"^(?P<header_name>Cookie|Set-Cookie):\s+(?P<cookie_name>[A-Za-z_][A-Za-z0-9._-]*)(?P<separator>=)(?P<value>[^;\s]+)",
    re.IGNORECASE,
)

JSON_PAIR_PATTERN = re.compile(
    r'^(?:"(?P<json_key>[A-Za-z_][A-Za-z0-9_]*)")(?P<json_separator>:\s+)"(?P<json_value>.+)"$'
)

YAML_PAIR_PATTERN = re.compile(
    r"^(?P<yaml_key>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<yaml_separator>:\s+)"
    r"(?P<yaml_value>.+)$"
)

LOG_SENTENCE_PATTERN = re.compile(
    r"^(?P<context_phrase>verification code is|OTP:\s*|动态口令为：)(?P<candidate_value>[A-Za-z0-9-]+)$",
    re.IGNORECASE,
)


def parse_structured_fragments(text: str) -> list[dict[str, object]]:
    fragments: list[dict[str, object]] = []

    for offset, line in _iter_lines(text):
        if match := ASSIGNMENT_PATTERN.match(line):
            value = match.group("value")
            value_start = offset + match.start("value")
            value_end = offset + match.end("value")
            fragments.append(
                {
                    "structure_kind": "assignment",
                    "raw_fragment": line,
                    "fragment_span": (offset, offset + len(line)),
                    "prefix": match.group("prefix") or "",
                    "key": match.group("key"),
                    "separator": match.group("separator"),
                    "value": value,
                    "quote_char": match.group("quote"),
                    "line_span": (offset, offset + len(line)),
                    "value_span": (value_start, value_end),
                }
            )
            continue

        if match := AUTHORIZATION_PATTERN.match(line):
            fragments.append(
                {
                    "structure_kind": "http_header",
                    "raw_fragment": line,
                    "fragment_span": (offset, offset + len(line)),
                    "header_name": match.group("header_name"),
                    "auth_scheme": match.group("auth_scheme"),
                    "separator": match.group("separator"),
                    "value": match.group("value"),
                    "value_span": (offset + match.start("value"), offset + match.end("value")),
                }
            )
            continue

        if match := COOKIE_PATTERN.match(line):
            fragments.append(
                {
                    "structure_kind": "cookie_pair",
                    "raw_fragment": line,
                    "fragment_span": (offset, offset + len(line)),
                    "header_name": match.group("header_name"),
                    "cookie_name": match.group("cookie_name"),
                    "separator": match.group("separator"),
                    "value": match.group("value"),
                    "value_span": (offset + match.start("value"), offset + match.end("value")),
                }
            )
            continue

        if match := JSON_PAIR_PATTERN.match(line):
            fragments.append(
                {
                    "structure_kind": "json_yaml_pair",
                    "raw_fragment": line,
                    "fragment_span": (offset, offset + len(line)),
                    "container_kind": "json",
                    "key": match.group("json_key"),
                    "separator": match.group("json_separator"),
                    "value": match.group("json_value"),
                    "quote_char": '"',
                    "value_span": (offset + match.start("json_value"), offset + match.end("json_value")),
                }
            )
            continue

        if match := YAML_PAIR_PATTERN.match(line):
            fragments.append(
                {
                    "structure_kind": "json_yaml_pair",
                    "raw_fragment": line,
                    "fragment_span": (offset, offset + len(line)),
                    "container_kind": "yaml",
                    "key": match.group("yaml_key"),
                    "separator": match.group("yaml_separator"),
                    "value": match.group("yaml_value"),
                    "quote_char": "",
                    "value_span": (offset + match.start("yaml_value"), offset + match.end("yaml_value")),
                }
            )
            continue

        if match := LOG_SENTENCE_PATTERN.match(line):
            fragments.append(
                {
                    "structure_kind": "log_sentence",
                    "raw_fragment": line,
                    "fragment_span": (offset, offset + len(line)),
                    "context_phrase": match.group("context_phrase").strip(),
                    "candidate_value": match.group("candidate_value"),
                    "candidate_span": (
                        offset + match.start("candidate_value"),
                        offset + match.end("candidate_value"),
                    ),
                    "context_span": (
                        offset + match.start("context_phrase"),
                        offset + match.end("context_phrase"),
                    ),
                }
            )

    return fragments


def _iter_lines(text: str):
    start = 0
    for line in text.splitlines():
        yield start, line
        start += len(line) + 1
```

- [ ] **Step 4: Re-run the parser tests to verify they pass**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_structured_parser.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/detectors/structured_parser.py \
  tools/privacy-filter-local/tests/test_structured_parser.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: add structured secret fragment parser"
```

## Task 2: Generate parser-based secret candidates with precise value spans

**Files:**
- Create: `tools/privacy-filter-local/detectors/secret_candidates.py`
- Create: `tools/privacy-filter-local/tests/test_secret_candidates.py`
- Test: `tools/privacy-filter-local/tests/test_secret_candidates.py`

- [ ] **Step 1: Write the failing candidate-generation tests**

Create `tools/privacy-filter-local/tests/test_secret_candidates.py`:

```python
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
```

- [ ] **Step 2: Run the candidate tests to verify they fail**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_secret_candidates.py -v`

Expected: FAIL because `secret_candidates.py` and `generate_secret_candidates()` do not exist yet.

- [ ] **Step 3: Create the minimal candidate generator**

Create `tools/privacy-filter-local/detectors/secret_candidates.py` with:

```python
import re

from detectors.structured_parser import parse_structured_fragments


API_KEY_PATTERN = re.compile(r"^(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{20,}|hf_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})$")
JWT_PATTERN = re.compile(r"^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
DB_PATTERN = re.compile(r"^(?:postgres|postgresql|mysql|mongodb):\/\/[^:\s]+:[^@\s]+@[^\/\s]+\/[^\s]+$", re.IGNORECASE)
TOKEN_KEY_NAMES = {"token", "access_token", "refresh_token", "api_key", "client_secret", "app_secret", "webhook_secret", "signing_secret", "database_url"}


def generate_secret_candidates(text: str) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for fragment in parse_structured_fragments(text):
        candidates.extend(_candidates_for_fragment(fragment))
    return candidates


def _candidates_for_fragment(fragment: dict[str, object]) -> list[dict[str, object]]:
    if fragment["structure_kind"] == "assignment":
        return _candidate_for_assignment(fragment)
    if fragment["structure_kind"] == "http_header":
        return _candidate_for_http_header(fragment)
    if fragment["structure_kind"] == "cookie_pair":
        return _candidate_for_cookie_pair(fragment)
    if fragment["structure_kind"] == "json_yaml_pair":
        return _candidate_for_json_yaml(fragment)
    if fragment["structure_kind"] == "log_sentence":
        return _candidate_for_log_sentence(fragment)
    return []


def _candidate_for_assignment(fragment: dict[str, object]) -> list[dict[str, object]]:
    key = str(fragment["key"]).lower()
    value = str(fragment["value"])
    if API_KEY_PATTERN.match(value):
        return [_build_candidate(fragment["value_span"], value, "api_key", 0.9, ["structure_match", "value_shape_match"])]
    if DB_PATTERN.match(value):
        return [_build_candidate(fragment["value_span"], value, "db_connection", 0.9, ["structure_match", "value_shape_match"])]
    if key in TOKEN_KEY_NAMES:
        return [_build_candidate(fragment["value_span"], value, "token", 0.75, ["structure_match", "key_name_match", "value_shape_match"])]
    if JWT_PATTERN.match(value):
        return [_build_candidate(fragment["value_span"], value, "jwt", 0.9, ["structure_match", "value_shape_match"])]
    return []


def _candidate_for_http_header(fragment: dict[str, object]) -> list[dict[str, object]]:
    value = str(fragment["value"])
    if API_KEY_PATTERN.match(value):
        return [_build_candidate(fragment["value_span"], value, "api_key", 0.9, ["structure_match", "value_shape_match"])]
    if JWT_PATTERN.match(value):
        return [_build_candidate(fragment["value_span"], value, "jwt", 0.9, ["structure_match", "value_shape_match"])]
    return [_build_candidate(fragment["value_span"], value, "bearer", 0.8, ["structure_match", "value_shape_match"])]


def _candidate_for_cookie_pair(fragment: dict[str, object]) -> list[dict[str, object]]:
    value = str(fragment["value"])
    return [_build_candidate(fragment["value_span"], value, "session", 0.8, ["structure_match", "value_shape_match"])]


def _candidate_for_json_yaml(fragment: dict[str, object]) -> list[dict[str, object]]:
    key = str(fragment["key"]).lower()
    value = str(fragment["value"])
    if API_KEY_PATTERN.match(value):
        return [_build_candidate(fragment["value_span"], value, "api_key", 0.9, ["structure_match", "value_shape_match"])]
    if key in TOKEN_KEY_NAMES:
        return [_build_candidate(fragment["value_span"], value, "token", 0.75, ["structure_match", "key_name_match", "value_shape_match"])]
    return []


def _candidate_for_log_sentence(fragment: dict[str, object]) -> list[dict[str, object]]:
    value = str(fragment["candidate_value"])
    return [_build_candidate(fragment["candidate_span"], value, "verification_code", 0.65, ["structure_match", "context_match"])]


def _build_candidate(span: tuple[int, int], text: str, kind: str, score: float, reason_codes: list[str]) -> dict[str, object]:
    return {
        "label": "secret",
        "kind": kind,
        "source": "parser_rule",
        "score": score,
        "reason_codes": reason_codes,
        "start": span[0],
        "end": span[1],
        "text": text,
    }
```

- [ ] **Step 4: Re-run the candidate tests to verify they pass**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_secret_candidates.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/detectors/secret_candidates.py \
  tools/privacy-filter-local/tests/test_secret_candidates.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: add parser-based secret candidates"
```

## Task 3: Add score normalization and mode thresholds

**Files:**
- Create: `tools/privacy-filter-local/detectors/secret_scores.py`
- Create: `tools/privacy-filter-local/tests/test_secret_scores.py`
- Modify: `tools/privacy-filter-local/detectors/secret_candidates.py`
- Test: `tools/privacy-filter-local/tests/test_secret_scores.py`

- [ ] **Step 1: Write the failing score tests**

Create `tools/privacy-filter-local/tests/test_secret_scores.py`:

```python
from detectors.secret_scores import filter_candidates_for_mode


def test_high_recall_accepts_context_only_short_code() -> None:
    candidate = {
        "label": "secret",
        "kind": "verification_code",
        "source": "parser_rule",
        "score": 0.65,
        "reason_codes": ["structure_match", "context_match"],
        "start": 21,
        "end": 27,
        "text": "128841",
    }

    accepted = filter_candidates_for_mode([candidate], "high_recall")

    assert accepted == [candidate]


def test_high_precision_rejects_context_only_short_code() -> None:
    candidate = {
        "label": "secret",
        "kind": "verification_code",
        "source": "parser_rule",
        "score": 0.65,
        "reason_codes": ["structure_match", "context_match"],
        "start": 21,
        "end": 27,
        "text": "128841",
    }

    accepted = filter_candidates_for_mode([candidate], "high_precision")

    assert accepted == []


def test_balanced_accepts_strong_assignment_secret() -> None:
    candidate = {
        "label": "secret",
        "kind": "token",
        "source": "parser_rule",
        "score": 0.75,
        "reason_codes": ["structure_match", "key_name_match", "value_shape_match"],
        "start": 15,
        "end": 49,
        "text": "demo_access_token_abcdef1234567890",
    }

    accepted = filter_candidates_for_mode([candidate], "balanced")

    assert accepted == [candidate]
```

- [ ] **Step 2: Run the score tests to verify they fail**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_secret_scores.py -v`

Expected: FAIL because `secret_scores.py` does not exist yet.

- [ ] **Step 3: Create the threshold module**

Create `tools/privacy-filter-local/detectors/secret_scores.py`:

```python
MODE_THRESHOLDS = {
    "high_recall": 0.6,
    "balanced": 0.7,
    "high_precision": 0.8,
}


def normalize_detection_mode(detection_mode: str) -> str:
    return detection_mode if detection_mode in MODE_THRESHOLDS else "balanced"


def filter_candidates_for_mode(candidates: list[dict[str, object]], detection_mode: str) -> list[dict[str, object]]:
    mode = normalize_detection_mode(detection_mode)
    threshold = MODE_THRESHOLDS[mode]
    return [candidate for candidate in candidates if float(candidate["score"]) >= threshold]
```

- [ ] **Step 4: Re-run the score tests to verify they pass**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_secret_scores.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/detectors/secret_scores.py \
  tools/privacy-filter-local/tests/test_secret_scores.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: add score-driven secret thresholds"
```

## Task 4: Run the new parser-first pipeline ahead of legacy regex

**Files:**
- Modify: `tools/privacy-filter-local/app.py`
- Modify: `tools/privacy-filter-local/tests/test_gateway.py`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Add a failing gateway regression for value-only redaction**

Append this test to `tools/privacy-filter-local/tests/test_gateway.py`:

```python
def test_collect_spans_prefers_parser_value_span_for_token_assignment() -> None:
    text = "token = vx_api_token_1234567890abcdef"

    spans = collect_spans(text, "balanced")

    assert spans == [
        {
            "label": "secret",
            "kind": "token",
            "source": "parser_rule",
            "score": 0.75,
            "reason_codes": ["structure_match", "key_name_match", "value_shape_match"],
            "start": 8,
            "end": len(text),
            "text": "vx_api_token_1234567890abcdef",
        }
    ]
```

- [ ] **Step 2: Run the regression to verify it fails**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_collect_spans_prefers_parser_value_span_for_token_assignment -v`

Expected: FAIL because `collect_spans()` still relies on legacy regex and returns a whole-line token span.

- [ ] **Step 3: Update `app.py` to combine parser candidates and legacy regex**

Modify `tools/privacy-filter-local/app.py` to import and use the new modules:

```python
from detectors.secret_candidates import generate_secret_candidates
from detectors.secret_scores import filter_candidates_for_mode
```

Replace the collection body with:

```python
def collect_spans(text: str, detection_mode: str = DETECTION_MODE_DEFAULT) -> list[dict[str, object]]:
    runtime_spans: list[dict[str, object]]
    try:
        runtime_spans = detect_with_runtime(text)
    except Exception as exc:
        logger.warning("OPF runtime unavailable, falling back to regex-only detection: %s", exc)
        runtime_spans = []

    parser_candidates = filter_candidates_for_mode(
        generate_secret_candidates(text),
        detection_mode,
    )
    legacy_regex_spans = detect_regex_secret_spans(text, detection_mode)
    spans = runtime_spans + legacy_regex_spans + parser_candidates
    return merge_spans(spans)
```

Also update `span_priority()` so parser candidates outrank legacy regex:

```python
def span_priority(span: dict[str, object]) -> tuple[int, int]:
    label = str(span["label"])
    source = str(span.get("source", ""))
    width = int(span["end"]) - int(span["start"])
    if label == "secret" and source == "parser_rule":
        return (3, -width)
    if label == "secret" and source == "regex":
        return (2, -width)
    if label == "secret":
        return (1, -width)
    return (0, width)
```

- [ ] **Step 4: Re-run the regression to verify it passes**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_collect_spans_prefers_parser_value_span_for_token_assignment -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/app.py \
  tools/privacy-filter-local/tests/test_gateway.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: run parser-first secret pipeline"
```

## Task 5: Teach legacy regex to stay as fallback, not primary assignment parser

**Files:**
- Modify: `tools/privacy-filter-local/detectors/regex_backstop.py`
- Modify: `tools/privacy-filter-local/tests/test_regex_backstop.py`
- Test: `tools/privacy-filter-local/tests/test_regex_backstop.py`

- [ ] **Step 1: Add a failing fallback regression**

Append this test to `tools/privacy-filter-local/tests/test_regex_backstop.py`:

```python
def test_legacy_regex_keeps_generic_token_rule_for_fallback() -> None:
    text = "token = vx_api_token_1234567890abcdef"

    spans = detect_regex_secret_spans(text, "balanced")

    assert len(spans) == 1
    assert spans[0]["source"] == "regex"
    assert spans[0]["kind"] == "token"
```

- [ ] **Step 2: Run the fallback regression to verify it passes before refactor**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_regex_backstop.py::test_legacy_regex_keeps_generic_token_rule_for_fallback -v`

Expected: PASS

- [ ] **Step 3: Add explicit fallback comments and preserve behavior**

At the top of `tools/privacy-filter-local/detectors/regex_backstop.py`, add this comment:

```python
# Legacy fallback detector:
# - still scans whole text
# - still over-matches some assignment structures
# - remains in place as a safety net while the parser-first detector takes over primary secret handling
```

Do not remove existing generic token regex in this task. This task is only to freeze its role as fallback.

- [ ] **Step 4: Re-run the full regex suite to verify no regressions**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_regex_backstop.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/detectors/regex_backstop.py \
  tools/privacy-filter-local/tests/test_regex_backstop.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "chore: freeze legacy regex as fallback detector"
```

## Task 6: Expose parser-rule metadata in UI for manual verification

**Files:**
- Modify: `tools/privacy-filter-local/ui/index.html`
- Modify: `tools/privacy-filter-local/tests/test_gateway.py`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Add failing UI-contract tests for debug metadata**

Append this test to `tools/privacy-filter-local/tests/test_gateway.py`:

```python
def test_root_ui_includes_score_and_reason_debug_fields() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert "score" in response.text
    assert "reason_codes" in response.text
    assert "source" in response.text
```

- [ ] **Step 2: Run the UI metadata test to verify it fails**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_root_ui_includes_score_and_reason_debug_fields -v`

Expected: FAIL because the current UI does not explicitly display `score` or `reason_codes`.

- [ ] **Step 3: Update the detections rendering in `ui/index.html`**

Add a helper that formats detection rows with metadata:

```javascript
function formatDetection(span) {
  const details = {
    label: span.label,
    kind: span.kind || null,
    source: span.source || null,
    score: span.score ?? null,
    reason_codes: span.reason_codes || [],
    text: span.text
  };
  return JSON.stringify(details, null, 2);
}
```

Then replace the existing detection rendering:

```javascript
detectionList.textContent = data.spans.map(formatDetection).join("\n\n");
```

- [ ] **Step 4: Re-run the UI metadata test to verify it passes**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_root_ui_includes_score_and_reason_debug_fields -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/ui/index.html \
  tools/privacy-filter-local/tests/test_gateway.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: surface structured secret metadata in ui"
```

## Task 7: Run golden regressions and a realistic mixed-text smoke test

**Files:**
- Modify: `tools/privacy-filter-local/tests/test_gateway.py`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`
- Test: `tools/privacy-filter-local/tests/test_structured_parser.py`
- Test: `tools/privacy-filter-local/tests/test_secret_candidates.py`
- Test: `tools/privacy-filter-local/tests/test_secret_scores.py`
- Test: `tools/privacy-filter-local/tests/test_regex_backstop.py`

- [ ] **Step 1: Add a golden-output regression for value-only preservation**

Append this test to `tools/privacy-filter-local/tests/test_gateway.py`:

```python
def test_redact_preserves_assignment_keys_and_only_replaces_values() -> None:
    client = TestClient(app)

    response = client.post(
        "/redact",
        json={
            "text": "\n".join(
                [
                    "OPENAI_API_KEY=sk-testsecretvalue1234567890",
                    "token = vx_api_token_1234567890abcdef",
                    "access_token = demo_access_token_abcdef1234567890",
                    "refresh_token=refresh_demo_token_abcdef1234567890",
                ]
            ),
            "source": "manual_ui",
            "target": "ai_model",
            "mode": "warn",
            "detection_mode": "balanced",
        },
    )

    assert response.status_code == 200
    assert response.json()["redacted_text"] == "\n".join(
        [
            "OPENAI_API_KEY=<SECRET>",
            "token = <SECRET>",
            "access_token = <SECRET>",
            "refresh_token=<SECRET>",
        ]
    )
```

- [ ] **Step 2: Run the golden regression to verify it fails first**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_redact_preserves_assignment_keys_and_only_replaces_values -v`

Expected: FAIL until the parser-first path and merge priority are working end-to-end.

- [ ] **Step 3: Run the full automated suite**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest -v`

Expected: PASS with parser tests, candidate tests, score tests, gateway regressions, legacy regex tests, and existing OPF tests all green.

- [ ] **Step 4: Run a realistic mixed-text smoke request**

Run:

```bash
cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local
./.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 7861
```

Then issue:

```bash
curl -X POST http://127.0.0.1:7861/redact \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "OPENAI_API_KEY=sk-testsecretvalue1234567890\nAuthorization: Bearer sk-Xp3cR09bttiaAxxx0TdB7w\nDATABASE_URL=postgres://appuser:supersecret@db.internal:5432/app\nverification code is 128841\n\"client_secret\": \"demo_client_secret_abcdef123456\"\nemail=user@example.com",
    "source": "manual_ui",
    "target": "ai_model",
    "mode": "warn",
    "detection_mode": "balanced"
  }'
```

Expected response characteristics:

- `decision` is `warn`
- `risk_level` is `high`
- secret spans carry `kind`, `source`, `score`, and `reason_codes`
- `redacted_text` preserves structure:
  - `OPENAI_API_KEY=<SECRET>`
  - `Authorization: Bearer <SECRET>`
  - `DATABASE_URL=<SECRET>`
  - `verification code is <SECRET>`
  - `"client_secret": "<SECRET>"`
  - `email=user@example.com` remains unchanged unless OPF still tags it as PII

- [ ] **Step 5: Commit the verified V2 baseline**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/detectors/structured_parser.py \
  tools/privacy-filter-local/detectors/secret_candidates.py \
  tools/privacy-filter-local/detectors/secret_scores.py \
  tools/privacy-filter-local/detectors/regex_backstop.py \
  tools/privacy-filter-local/app.py \
  tools/privacy-filter-local/ui/index.html \
  tools/privacy-filter-local/tests/test_gateway.py \
  tools/privacy-filter-local/tests/test_regex_backstop.py \
  tools/privacy-filter-local/tests/test_structured_parser.py \
  tools/privacy-filter-local/tests/test_secret_candidates.py \
  tools/privacy-filter-local/tests/test_secret_scores.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: add structured secret detector v2 baseline"
```
