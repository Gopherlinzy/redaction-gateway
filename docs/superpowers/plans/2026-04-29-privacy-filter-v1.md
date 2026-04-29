# Privacy Filter V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a localhost-only privacy gateway plus manual review UI that detects and redacts secrets / PII before text is sent to AI models or persisted into Linear.

**Architecture:** FastAPI serves a single localhost gateway. Detection combines an OpenAI Privacy Filter runtime wrapper with a regex backstop, then a pure policy engine decides whether to allow, warn, redact, or block. Manual UI is the first caller; Symphony and Linear adapters reuse the same API client surface later.

**Tech Stack:** Python 3.11+, FastAPI, pytest, OpenAI Privacy Filter (`openai/privacy-filter`), standard-library regex, vanilla HTML/JS

---

## File Map

- Create: `tools/privacy-filter-local/requirements.txt`
- Create: `tools/privacy-filter-local/README.md`
- Create: `tools/privacy-filter-local/app.py`
- Create: `tools/privacy-filter-local/policy.py`
- Create: `tools/privacy-filter-local/detectors/opf_runtime.py`
- Create: `tools/privacy-filter-local/detectors/regex_backstop.py`
- Create: `tools/privacy-filter-local/adapters/symphony.py`
- Create: `tools/privacy-filter-local/adapters/linear.py`
- Create: `tools/privacy-filter-local/ui/index.html`
- Create: `tools/privacy-filter-local/tests/test_regex_backstop.py`
- Create: `tools/privacy-filter-local/tests/test_policy.py`
- Create: `tools/privacy-filter-local/tests/test_gateway.py`
- Create: `tools/privacy-filter-local/tests/test_symphony_adapter.py`
- Create: `tools/privacy-filter-local/tests/test_linear_adapter.py`

### Task 1: Scaffold the package and health endpoint

**Files:**
- Create: `tools/privacy-filter-local/requirements.txt`
- Create: `tools/privacy-filter-local/README.md`
- Create: `tools/privacy-filter-local/app.py`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Write the failing health-route test**

```python
from fastapi.testclient import TestClient

from app import app


def test_health_endpoint_returns_ok():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_gateway.py::test_health_endpoint_returns_ok -v`
Expected: FAIL with `ModuleNotFoundError` or missing `/health` route.

- [ ] **Step 3: Write minimal implementation**

```python
from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
```

```text
fastapi>=0.115,<1
uvicorn[standard]>=0.30,<1
pytest>=8,<9
httpx>=0.27,<1
git+https://github.com/openai/privacy-filter.git
```

```markdown
# Privacy Filter Local

Local-only privacy gateway scaffold. Later tasks add detectors, UI, and adapters.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_gateway.py::test_health_endpoint_returns_ok -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/admin/wiki/tools/privacy-filter-local/requirements.txt /Users/admin/wiki/tools/privacy-filter-local/README.md /Users/admin/wiki/tools/privacy-filter-local/app.py /Users/admin/wiki/tools/privacy-filter-local/tests/test_gateway.py
git commit -m "feat: scaffold privacy filter service"
```

### Task 2: Implement regex secret backstop

**Files:**
- Create: `tools/privacy-filter-local/detectors/regex_backstop.py`
- Test: `tools/privacy-filter-local/tests/test_regex_backstop.py`

- [ ] **Step 1: Write the failing regex detector tests**

```python
from detectors.regex_backstop import detect_regex_secret_spans


def test_detects_openai_key():
    text = "OPENAI_API_KEY=sk-testsecretvalue1234567890"

    spans = detect_regex_secret_spans(text)

    assert len(spans) == 1
    assert spans[0]["label"] == "secret"
    assert spans[0]["source"] == "regex"


def test_detects_bearer_token():
    text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"

    spans = detect_regex_secret_spans(text)

    assert len(spans) == 1
    assert spans[0]["label"] == "secret"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_regex_backstop.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'detectors.regex_backstop'`.

- [ ] **Step 3: Write minimal implementation**

```python
import re

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{12,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"hf_[A-Za-z0-9]{16,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._=-]{12,}", re.IGNORECASE),
]


def detect_regex_secret_spans(text: str) -> list[dict[str, object]]:
    spans: list[dict[str, object]] = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            spans.append(
                {
                    "start": match.start(),
                    "end": match.end(),
                    "label": "secret",
                    "source": "regex",
                    "text": match.group(0),
                }
            )
    return spans
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_regex_backstop.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/admin/wiki/tools/privacy-filter-local/detectors/regex_backstop.py /Users/admin/wiki/tools/privacy-filter-local/tests/test_regex_backstop.py
git commit -m "feat: add regex secret backstop"
```

### Task 3: Implement pure policy engine

**Files:**
- Create: `tools/privacy-filter-local/policy.py`
- Test: `tools/privacy-filter-local/tests/test_policy.py`

- [ ] **Step 1: Write the failing policy tests**

```python
from policy import decide_action


def test_secret_to_ai_model_blocks():
    decision = decide_action(
        spans=[{"label": "secret"}],
        source="manual_ui",
        target="ai_model",
        mode="warn",
    )

    assert decision["decision"] == "block"
    assert decision["risk_level"] == "high"


def test_url_to_local_review_warns():
    decision = decide_action(
        spans=[{"label": "private_url"}],
        source="manual_ui",
        target="local_review",
        mode="warn",
    )

    assert decision["decision"] == "warn"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_policy.py -v`
Expected: FAIL because `policy.py` does not exist.

- [ ] **Step 3: Write minimal implementation**

```python
SECRET_LABELS = {"secret"}
REDACT_LABELS = {"private_email", "private_phone", "account_number"}
SOFT_LABELS = {"private_url", "private_address", "private_person", "private_date"}


def decide_action(spans, source: str, target: str, mode: str) -> dict[str, str]:
    labels = {span["label"] for span in spans}
    if SECRET_LABELS & labels and target in {"ai_model", "linear"}:
        return {"decision": "block", "risk_level": "high", "reason": "secret detected"}
    if REDACT_LABELS & labels:
        return {"decision": "redact", "risk_level": "medium", "reason": "sensitive pii"}
    if SOFT_LABELS & labels and target == "local_review":
        return {"decision": "warn", "risk_level": "low", "reason": "review before sharing"}
    if SOFT_LABELS & labels:
        return {"decision": "redact", "risk_level": "medium", "reason": "external target"}
    return {"decision": mode if mode in {"warn", "redact"} else "allow", "risk_level": "low", "reason": "no match"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_policy.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/admin/wiki/tools/privacy-filter-local/policy.py /Users/admin/wiki/tools/privacy-filter-local/tests/test_policy.py
git commit -m "feat: add privacy policy engine"
```

### Task 4: Add OpenAI Privacy Filter runtime wrapper

**Files:**
- Create: `tools/privacy-filter-local/detectors/opf_runtime.py`
- Modify: `tools/privacy-filter-local/app.py`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Write the failing runtime-integration test**

```python
from fastapi.testclient import TestClient
from unittest.mock import patch

from app import app


def test_scan_uses_runtime_and_returns_spans():
    client = TestClient(app)

    with patch("app.detect_with_runtime", return_value=[{"start": 0, "end": 5, "label": "private_email", "source": "opf", "text": "a@b.c"}]):
        response = client.post(
            "/scan",
            json={"text": "a@b.c", "source": "manual_ui", "target": "ai_model", "mode": "warn"},
        )

    assert response.status_code == 200
    assert response.json()["spans"][0]["label"] == "private_email"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_gateway.py::test_scan_uses_runtime_and_returns_spans -v`
Expected: FAIL because `/scan` and `detect_with_runtime` are missing.

- [ ] **Step 3: Write minimal implementation**

```python
from functools import lru_cache
import os

from opf import OPF


@lru_cache(maxsize=1)
def get_redactor():
    device = os.getenv("PRIVACY_FILTER_DEVICE", "cpu")
    return OPF(device=device, output_mode="typed", output_text_only=False)


def detect_with_runtime(text: str) -> list[dict[str, object]]:
    result = get_redactor().redact(text)
    return result.get("detected_spans", [])
```

```python
from pydantic import BaseModel


class ScanRequest(BaseModel):
    text: str
    source: str
    target: str
    mode: str


@app.post("/scan")
def scan(request: ScanRequest) -> dict[str, object]:
    spans = detect_with_runtime(request.text)
    return {"spans": spans, "risk_level": "low", "summary": {"span_count": len(spans)}, "recommended_action": request.mode}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_gateway.py::test_scan_uses_runtime_and_returns_spans -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/admin/wiki/tools/privacy-filter-local/detectors/opf_runtime.py /Users/admin/wiki/tools/privacy-filter-local/app.py /Users/admin/wiki/tools/privacy-filter-local/tests/test_gateway.py
git commit -m "feat: wrap openai privacy filter runtime"
```

### Task 5: Merge detectors and implement redact / decide endpoints

**Files:**
- Modify: `tools/privacy-filter-local/app.py`
- Modify: `tools/privacy-filter-local/policy.py`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Write the failing gateway behavior tests**

```python
from fastapi.testclient import TestClient
from unittest.mock import patch

from app import app


def test_redact_endpoint_blocks_secret_for_ai_model():
    client = TestClient(app)
    spans = [{"start": 15, "end": 29, "label": "secret", "source": "regex", "text": "sk-testsecret"}]

    with patch("app.collect_spans", return_value=spans):
        response = client.post(
            "/decide",
            json={"text": "token is sk-testsecret", "source": "manual_ui", "target": "ai_model", "mode": "warn"},
        )

    assert response.status_code == 200
    assert response.json()["decision"] == "block"


def test_redact_endpoint_replaces_sensitive_text():
    client = TestClient(app)
    spans = [{"start": 8, "end": 13, "label": "private_email", "source": "opf", "text": "a@b.c"}]

    with patch("app.collect_spans", return_value=spans):
        response = client.post(
            "/redact",
            json={"text": "email: a@b.c", "source": "manual_ui", "target": "ai_model", "mode": "warn"},
        )

    assert response.status_code == 200
    assert "<PRIVATE_EMAIL>" in response.json()["redacted_text"]


def test_collect_spans_prefers_secret_on_overlap():
    client = TestClient(app)
    spans = [
        {"start": 0, "end": 20, "label": "private_url", "source": "opf", "text": "https://internal"},
        {"start": 8, "end": 20, "label": "secret", "source": "regex", "text": "internal"},
    ]

    with patch("app.detect_with_runtime", return_value=[spans[0]]), patch("app.detect_regex_secret_spans", return_value=[spans[1]]):
        response = client.post(
            "/redact",
            json={"text": "see https://internal", "source": "manual_ui", "target": "ai_model", "mode": "warn"},
        )

    assert response.status_code == 200
    assert response.json()["spans"][0]["label"] == "secret"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_gateway.py -v`
Expected: FAIL because `/decide`, `/redact`, and `collect_spans` are incomplete.

- [ ] **Step 3: Write minimal implementation**

```python
PLACEHOLDERS = {
    "secret": "<SECRET>",
    "private_email": "<PRIVATE_EMAIL>",
    "private_phone": "<PRIVATE_PHONE>",
    "account_number": "<ACCOUNT_NUMBER>",
    "private_url": "<PRIVATE_URL>",
    "private_address": "<PRIVATE_ADDRESS>",
    "private_person": "<PRIVATE_PERSON>",
    "private_date": "<PRIVATE_DATE>",
}


def merge_spans(spans: list[dict[str, object]]) -> list[dict[str, object]]:
    ordered = sorted(spans, key=lambda item: (item["start"], item["end"]))
    merged: list[dict[str, object]] = []
    for span in ordered:
        if not merged:
            merged.append(span)
            continue
        previous = merged[-1]
        if int(span["start"]) < int(previous["end"]):
            if span["label"] == "secret" and previous["label"] != "secret":
                merged[-1] = span
            continue
        merged.append(span)
    return merged


def collect_spans(text: str) -> list[dict[str, object]]:
    spans = detect_with_runtime(text) + detect_regex_secret_spans(text)
    return merge_spans(spans)


def apply_redaction(text: str, spans: list[dict[str, object]]) -> str:
    pieces = []
    cursor = 0
    for span in spans:
        start = int(span["start"])
        end = int(span["end"])
        if start < cursor:
            continue
        pieces.append(text[cursor:start])
        pieces.append(PLACEHOLDERS.get(span["label"], "<REDACTED>"))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


@app.post("/decide")
def decide(request: ScanRequest) -> dict[str, object]:
    spans = collect_spans(request.text)
    return decide_action(spans, request.source, request.target, request.mode)


@app.post("/redact")
def redact(request: ScanRequest) -> dict[str, object]:
    spans = collect_spans(request.text)
    decision = decide_action(spans, request.source, request.target, request.mode)
    return {
        "decision": decision["decision"],
        "risk_level": decision["risk_level"],
        "spans": spans,
        "redacted_text": apply_redaction(request.text, spans),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_gateway.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/admin/wiki/tools/privacy-filter-local/app.py /Users/admin/wiki/tools/privacy-filter-local/policy.py /Users/admin/wiki/tools/privacy-filter-local/tests/test_gateway.py
git commit -m "feat: add gateway decision and redaction endpoints"
```

### Task 6: Serve the manual review UI

**Files:**
- Create: `tools/privacy-filter-local/ui/index.html`
- Modify: `tools/privacy-filter-local/app.py`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Write the failing UI route test**

```python
from fastapi.testclient import TestClient

from app import app


def test_root_serves_manual_ui():
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert "Privacy Filter Local" in response.text
    assert "textarea" in response.text
    assert "Copy Redacted Text" in response.text
    assert "Detections" in response.text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_gateway.py::test_root_serves_manual_ui -v`
Expected: FAIL because `/` is not defined.

- [ ] **Step 3: Write minimal implementation**

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Privacy Filter Local</title>
  </head>
  <body>
    <h1>Privacy Filter Local</h1>
    <textarea id="sourceText"></textarea>
    <button id="redactButton">Redact</button>
    <button id="copyButton">Copy Redacted Text</button>
    <section>
      <h2>Summary</h2>
      <div id="riskLevel">risk: unknown</div>
      <div id="spanCount">spans: 0</div>
    </section>
    <section>
      <h2>Detections</h2>
      <pre id="detectionList">[]</pre>
    </section>
    <pre id="redactedText"></pre>
    <script>
      document.getElementById("redactButton").addEventListener("click", async () => {
        const text = document.getElementById("sourceText").value;
        const response = await fetch("/redact", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text, source: "manual_ui", target: "ai_model", mode: "warn" }),
        });
        const data = await response.json();
        document.getElementById("riskLevel").textContent = `risk: ${data.risk_level}`;
        document.getElementById("spanCount").textContent = `spans: ${data.spans.length}`;
        document.getElementById("detectionList").textContent = JSON.stringify(data.spans, null, 2);
        document.getElementById("redactedText").textContent = data.redacted_text;
      });
      document.getElementById("copyButton").addEventListener("click", async () => {
        await navigator.clipboard.writeText(document.getElementById("redactedText").textContent);
      });
    </script>
  </body>
</html>
```

```python
from fastapi.responses import HTMLResponse
from pathlib import Path


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (Path(__file__).parent / "ui" / "index.html").read_text(encoding="utf-8")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_gateway.py::test_root_serves_manual_ui -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/admin/wiki/tools/privacy-filter-local/ui/index.html /Users/admin/wiki/tools/privacy-filter-local/app.py /Users/admin/wiki/tools/privacy-filter-local/tests/test_gateway.py
git commit -m "feat: add manual redaction ui"
```

### Task 7: Add Symphony adapter client

**Files:**
- Create: `tools/privacy-filter-local/adapters/symphony.py`
- Test: `tools/privacy-filter-local/tests/test_symphony_adapter.py`

- [ ] **Step 1: Write the failing Symphony adapter tests**

```python
from adapters.symphony import build_decide_payload


def test_builds_prompt_payload_for_symphony():
    payload = build_decide_payload("token=sk-123456789012", source="symphony_prompt")

    assert payload["target"] == "ai_model"
    assert payload["mode"] == "block"
    assert payload["source"] == "symphony_prompt"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_symphony_adapter.py -v`
Expected: FAIL because `adapters/symphony.py` does not exist.

- [ ] **Step 3: Write minimal implementation**

```python
def build_decide_payload(text: str, source: str = "symphony_prompt") -> dict[str, str]:
    return {
        "text": text,
        "source": source,
        "target": "ai_model",
        "mode": "block",
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_symphony_adapter.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/admin/wiki/tools/privacy-filter-local/adapters/symphony.py /Users/admin/wiki/tools/privacy-filter-local/tests/test_symphony_adapter.py
git commit -m "feat: add symphony privacy adapter"
```

### Task 8: Add Linear adapter client

**Files:**
- Create: `tools/privacy-filter-local/adapters/linear.py`
- Test: `tools/privacy-filter-local/tests/test_linear_adapter.py`

- [ ] **Step 1: Write the failing Linear adapter tests**

```python
from adapters.linear import build_redact_payload


def test_builds_linear_comment_payload():
    payload = build_redact_payload("customer email is a@b.c", source="linear_comment")

    assert payload["target"] == "linear"
    assert payload["mode"] == "redact"
    assert payload["source"] == "linear_comment"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_linear_adapter.py -v`
Expected: FAIL because `adapters/linear.py` does not exist.

- [ ] **Step 3: Write minimal implementation**

```python
def build_redact_payload(text: str, source: str = "linear_comment") -> dict[str, str]:
    return {
        "text": text,
        "source": source,
        "target": "linear",
        "mode": "redact",
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_linear_adapter.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/admin/wiki/tools/privacy-filter-local/adapters/linear.py /Users/admin/wiki/tools/privacy-filter-local/tests/test_linear_adapter.py
git commit -m "feat: add linear privacy adapter"
```

### Task 9: Tighten README and local run instructions

**Files:**
- Modify: `tools/privacy-filter-local/README.md`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Write the failing smoke test expectation**

```python
from fastapi.testclient import TestClient
from unittest.mock import patch

from app import app


def test_redact_response_contains_decision_metadata():
    client = TestClient(app)

    with patch("app.collect_spans", return_value=[]):
        response = client.post(
            "/redact",
            json={"text": "hello", "source": "manual_ui", "target": "local_review", "mode": "warn"},
        )

    assert response.status_code == 200
    assert "decision" in response.json()
    assert "risk_level" in response.json()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_gateway.py::test_redact_response_contains_decision_metadata -v`
Expected: FAIL if metadata is missing.

- [ ] **Step 3: Write minimal implementation and docs**

```markdown
# Privacy Filter Local

Local-only text redaction gateway for AI prompts and Linear writes.

## Setup

~~~bash
cd /Users/admin/wiki/tools/privacy-filter-local
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 7861
~~~

## Notes

- First real OPF request may download a model into `~/.opf/privacy_filter`
- Set `PRIVACY_FILTER_DEVICE=cpu` or `cuda`
- Original text is not persisted by design
```

```python
return {
    "decision": decision["decision"],
    "risk_level": decision["risk_level"],
    "reason": decision["reason"],
    "spans": spans,
    "redacted_text": apply_redaction(request.text, spans),
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/admin/wiki/tools/privacy-filter-local && pytest tests/test_gateway.py::test_redact_response_contains_decision_metadata -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add /Users/admin/wiki/tools/privacy-filter-local/README.md /Users/admin/wiki/tools/privacy-filter-local/app.py /Users/admin/wiki/tools/privacy-filter-local/tests/test_gateway.py
git commit -m "docs: add local privacy filter runbook"
```

## Self-Review

- Spec coverage check:
  - localhost gateway: Tasks 1, 4, 5, 6
  - regex backstop: Task 2
  - policy engine: Task 3
  - manual UI: Task 6
  - Symphony adapter: Task 7
  - Linear adapter: Task 8
  - local run / no-persistence guidance: Task 9
- Placeholder scan:
  - removed generic "handle later" language; each task names exact files, commands, and code.
- Type consistency:
  - request payload uses `text/source/target/mode` consistently
  - policy decision uses `decision/risk_level/reason` consistently
  - detector merge prefers `secret` spans when model and regex overlap
