# Developer Secret Filter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `privacy-filter-local` 收敛成一个 `secret-first` 的本地开发安全过滤器，优先识别和脱敏 API key、token、JWT、Bearer、cookie/session、验证码、数据库连接串、webhook secret，同时保留 PII 但降级为次要提示。

**Architecture:** 保留现有 FastAPI + 静态 HTML 结构，不引入前端框架。后端继续使用 `OPF + regex backstop` 混合检测，但将 regex 层升级为带 `detection_mode` 的开发域 secret 检测器；策略层把 `secret` 的默认结果改为 `warn/high risk`；前端新增 `Detection Mode` 下拉，并把 `Primary Risk` 与 `Secondary Signals` 分开展示。

**Tech Stack:** Python 3.14, FastAPI, Pydantic, pytest, vanilla HTML/CSS/JavaScript, OPF runtime

---

## File Map

**Worktree root:** `/Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1`

- Modify: `tools/privacy-filter-local/app.py`
- Modify: `tools/privacy-filter-local/policy.py`
- Modify: `tools/privacy-filter-local/detectors/regex_backstop.py`
- Modify: `tools/privacy-filter-local/ui/index.html`
- Modify: `tools/privacy-filter-local/tests/test_gateway.py`
- Modify: `tools/privacy-filter-local/tests/test_policy.py`
- Modify: `tools/privacy-filter-local/tests/test_regex_backstop.py`
- Create: `tools/privacy-filter-local/tests/test_secret_modes.py`

## Canonical Values

Use these exact `detection_mode` values end-to-end:

- `high_recall`
- `balanced`
- `high_precision`

Use these exact UI labels:

- `High Recall`
- `Balanced`
- `High Precision`

The request payload keeps the existing `mode` field for action posture and adds a separate `detection_mode` field for detection sensitivity.

### Task 1: Thread `detection_mode` through the request and detection pipeline

**Files:**
- Modify: `tools/privacy-filter-local/app.py`
- Modify: `tools/privacy-filter-local/tests/test_gateway.py`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Write the failing gateway test for `detection_mode` propagation**

Add this test to `tools/privacy-filter-local/tests/test_gateway.py`:

```python
def test_redact_endpoint_forwards_detection_mode_to_secret_backstop() -> None:
    client = TestClient(app)

    with patch("app.detect_with_runtime", return_value=[]), patch(
        "app.detect_regex_secret_spans",
        return_value=[],
    ) as regex_detector:
        response = client.post(
            "/redact",
            json={
                "text": "token=demo",
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
                "detection_mode": "high_recall",
            },
        )

    assert response.status_code == 200
    regex_detector.assert_called_once_with("token=demo", "high_recall")
```

- [ ] **Step 2: Run the new test to verify it fails**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_redact_endpoint_forwards_detection_mode_to_secret_backstop -v`

Expected: FAIL because `ScanRequest` does not define `detection_mode`, `collect_spans()` only accepts `text`, and `detect_regex_secret_spans()` is currently called with one argument.

- [ ] **Step 3: Update `app.py` to carry `detection_mode` end-to-end**

Change `tools/privacy-filter-local/app.py` to this shape:

```python
DETECTION_MODE_DEFAULT = "balanced"


class ScanRequest(BaseModel):
    text: str
    source: str
    target: str
    mode: str
    detection_mode: str = DETECTION_MODE_DEFAULT


def collect_spans(text: str, detection_mode: str = DETECTION_MODE_DEFAULT) -> list[dict[str, object]]:
    runtime_spans: list[dict[str, object]]
    try:
        runtime_spans = detect_with_runtime(text)
    except Exception as exc:
        logger.warning("OPF runtime unavailable, falling back to regex-only detection: %s", exc)
        runtime_spans = []
    spans = runtime_spans + detect_regex_secret_spans(text, detection_mode)
    return merge_spans(spans)


@app.post("/scan")
def scan(request: ScanRequest) -> dict[str, object]:
    spans = collect_spans(request.text, request.detection_mode)
    decision = decide_action(spans, request.source, request.target, request.mode)
    return {
        "spans": spans,
        "risk_level": decision["risk_level"],
        "summary": build_summary(spans),
        "recommended_action": decision["decision"],
    }


@app.post("/decide")
def decide(request: ScanRequest) -> dict[str, str]:
    spans = collect_spans(request.text, request.detection_mode)
    return decide_action(spans, request.source, request.target, request.mode)


@app.post("/redact")
def redact(request: ScanRequest) -> dict[str, object]:
    spans = collect_spans(request.text, request.detection_mode)
    decision = decide_action(spans, request.source, request.target, request.mode)
    return {
        "decision": decision["decision"],
        "risk_level": decision["risk_level"],
        "reason": decision["reason"],
        "spans": spans,
        "redacted_text": apply_redaction(request.text, spans),
    }
```

- [ ] **Step 4: Re-run the propagation test to verify it passes**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_redact_endpoint_forwards_detection_mode_to_secret_backstop -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/app.py \
  tools/privacy-filter-local/tests/test_gateway.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: thread detection mode through gateway"
```

### Task 2: Expand the regex backstop into a developer-secret detector

**Files:**
- Modify: `tools/privacy-filter-local/detectors/regex_backstop.py`
- Modify: `tools/privacy-filter-local/tests/test_regex_backstop.py`
- Test: `tools/privacy-filter-local/tests/test_regex_backstop.py`

- [ ] **Step 1: Add failing tests for developer-secret coverage**

Append these tests to `tools/privacy-filter-local/tests/test_regex_backstop.py`:

```python
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
```

- [ ] **Step 2: Run the developer-secret tests to verify they fail**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_regex_backstop.py -v`

Expected: FAIL because `detect_regex_secret_spans()` does not yet accept a mode argument and does not emit `kind` metadata for JWT, session, DB connection strings, webhook secrets, or generic token labels.

- [ ] **Step 3: Replace the simple pattern list with mode-ready secret specs**

Refactor `tools/privacy-filter-local/detectors/regex_backstop.py` around explicit specs:

```python
import re

SECRET_PATTERN_SPECS = [
    {"kind": "api_key", "pattern": re.compile(r"sk-[A-Za-z0-9_-]{12,}")},
    {"kind": "api_key", "pattern": re.compile(r"github_pat_[A-Za-z0-9_]{20,}")},
    {"kind": "api_key", "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9]{12,}")},
    {"kind": "api_key", "pattern": re.compile(r"AKIA[0-9A-Z]{16}")},
    {"kind": "api_key", "pattern": re.compile(r"hf_[A-Za-z0-9]{16,}")},
    {"kind": "bearer", "pattern": re.compile(r"Bearer\s+[A-Za-z0-9._=-]{12,}", re.IGNORECASE)},
    {
        "kind": "jwt",
        "pattern": re.compile(
            r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
    },
    {
        "kind": "session",
        "pattern": re.compile(
            r"(?:Set-Cookie:\s*)?(?:sessionid|session|connect\.sid|sid)=[^;\s]{8,}",
            re.IGNORECASE,
        ),
    },
    {
        "kind": "db_connection",
        "pattern": re.compile(
            r"\b(?:postgres|postgresql|mysql|mongodb):\/\/[^:\s]+:[^@\s]+@[^\/\s]+\/[^\s]+",
            re.IGNORECASE,
        ),
    },
    {
        "kind": "webhook_secret",
        "pattern": re.compile(
            r"\b(?:webhook_secret|signing_secret|client_secret|app_secret)\s*[:=]\s*[A-Za-z0-9._-]{8,}",
            re.IGNORECASE,
        ),
    },
    {
        "kind": "token",
        "pattern": re.compile(
            r"\b(?:token|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*[A-Za-z0-9._-]{10,}",
            re.IGNORECASE,
        ),
    },
]


def build_secret_span(match: re.Match[str], kind: str, group: int = 0) -> dict[str, object]:
    return {
        "start": match.start(group),
        "end": match.end(group),
        "label": "secret",
        "kind": kind,
        "source": "regex",
        "text": match.group(group),
    }
```

Then update the detector loop:

```python
def detect_regex_secret_spans(text: str, detection_mode: str = "balanced") -> list[dict[str, object]]:
    spans: list[dict[str, object]] = []
    for spec in SECRET_PATTERN_SPECS:
        for match in spec["pattern"].finditer(text):
            spans.append(build_secret_span(match, spec["kind"]))
    return spans
```

- [ ] **Step 4: Re-run the regex coverage tests to verify they pass**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_regex_backstop.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/detectors/regex_backstop.py \
  tools/privacy-filter-local/tests/test_regex_backstop.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: add developer secret backstop coverage"
```

### Task 3: Make secret detection mode-aware

**Files:**
- Modify: `tools/privacy-filter-local/detectors/regex_backstop.py`
- Create: `tools/privacy-filter-local/tests/test_secret_modes.py`
- Test: `tools/privacy-filter-local/tests/test_secret_modes.py`

- [ ] **Step 1: Write failing mode-behavior tests**

Create `tools/privacy-filter-local/tests/test_secret_modes.py`:

```python
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
```

- [ ] **Step 2: Run the mode tests to verify they fail**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_secret_modes.py -v`

Expected: FAIL because the detector currently ignores `detection_mode` and has no weak-signal gating.

- [ ] **Step 3: Add per-mode config and contextual secret patterns**

Extend `tools/privacy-filter-local/detectors/regex_backstop.py` with exact mode config:

```python
MODE_CONFIG = {
    "high_recall": {"include_weak_context": True, "include_generic_labels": True},
    "balanced": {"include_weak_context": False, "include_generic_labels": True},
    "high_precision": {"include_weak_context": False, "include_generic_labels": False},
}

CONTEXTUAL_SECRET_SPECS = {
    "high_recall": [
        (
            "verification_code",
            re.compile(
                r"(?:动态口令|初始动态口令|一次性口令|一次性密码|验证码|校验码|短信码|OTP|MFA code|verification code|passcode|code)"
                r"\s*(?:is|are|for|为|是|=)?\s*(?::|：)?\s*([A-Za-z0-9-]{4,10})",
                re.IGNORECASE,
            ),
            1,
        ),
    ],
    "balanced": [
        (
            "verification_code",
            re.compile(
                r"(?:动态口令|初始动态口令|一次性口令|一次性密码|验证码|校验码|短信码|OTP|MFA code|verification code|passcode)"
                r"\s*(?:is|are|for|为|是|=)?\s*(?::|：)?\s*([A-Za-z0-9-]{4,10})",
                re.IGNORECASE,
            ),
            1,
        ),
    ],
    "high_precision": [],
}


def normalize_detection_mode(detection_mode: str) -> str:
    return detection_mode if detection_mode in MODE_CONFIG else "balanced"
```

Update the detector body to honor the mode:

```python
def detect_regex_secret_spans(text: str, detection_mode: str = "balanced") -> list[dict[str, object]]:
    mode = normalize_detection_mode(detection_mode)
    spans: list[dict[str, object]] = []

    for spec in SECRET_PATTERN_SPECS:
        if spec["kind"] == "token" and not MODE_CONFIG[mode]["include_generic_labels"]:
            continue
        for match in spec["pattern"].finditer(text):
            spans.append(build_secret_span(match, spec["kind"]))

    for kind, pattern, group in CONTEXTUAL_SECRET_SPECS[mode]:
        for match in pattern.finditer(text):
            spans.append(build_secret_span(match, kind, group))

    return spans
```

- [ ] **Step 4: Re-run the mode tests to verify they pass**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_secret_modes.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/detectors/regex_backstop.py \
  tools/privacy-filter-local/tests/test_secret_modes.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: add detection modes for secret scanning"
```

### Task 4: Change policy from `block` to `warn` for secret-first manual review

**Files:**
- Modify: `tools/privacy-filter-local/policy.py`
- Modify: `tools/privacy-filter-local/tests/test_policy.py`
- Modify: `tools/privacy-filter-local/tests/test_gateway.py`
- Test: `tools/privacy-filter-local/tests/test_policy.py`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Rewrite the failing policy test to match the new contract**

Replace the old secret policy test in `tools/privacy-filter-local/tests/test_policy.py` with:

```python
def test_secret_to_ai_model_warns_with_high_risk() -> None:
    decision = decide_action(
        spans=[{"label": "secret", "kind": "bearer"}],
        source="manual_ui",
        target="ai_model",
        mode="warn",
    )

    assert decision["decision"] == "warn"
    assert decision["risk_level"] == "high"
    assert decision["reason"] == "secret detected"
```

Update the gateway expectation in `tools/privacy-filter-local/tests/test_gateway.py`:

```python
def test_decide_endpoint_warns_secret_for_ai_model() -> None:
    client = TestClient(app)
    spans = [
        {
            "start": 9,
            "end": 22,
            "label": "secret",
            "kind": "api_key",
            "source": "regex",
            "text": "sk-testsecret",
        }
    ]

    with patch("app.collect_spans", return_value=spans):
        response = client.post(
            "/decide",
            json={
                "text": "token is sk-testsecret",
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
                "detection_mode": "balanced",
            },
        )

    assert response.status_code == 200
    assert response.json()["decision"] == "warn"
    assert response.json()["risk_level"] == "high"
```

- [ ] **Step 2: Run the policy and gateway tests to verify they fail**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_policy.py tests/test_gateway.py::test_decide_endpoint_warns_secret_for_ai_model -v`

Expected: FAIL because `policy.py` still returns `block` for `secret` to `ai_model`.

- [ ] **Step 3: Update the secret branch in `policy.py`**

Change the secret policy branch to:

```python
def decide_action(
    spans: list[dict[str, object]],
    source: str,
    target: str,
    mode: str,
) -> dict[str, str]:
    del source

    labels = {str(span["label"]) for span in spans}
    if SECRET_LABELS & labels:
        return {"decision": "warn", "risk_level": "high", "reason": "secret detected"}
    if REDACT_LABELS & labels:
        return {"decision": "redact", "risk_level": "medium", "reason": "sensitive pii"}
    if SOFT_LABELS & labels:
        if target == "local_review":
            return {
                "decision": "warn",
                "risk_level": "low",
                "reason": "review before sharing",
            }
        return {"decision": "redact", "risk_level": "medium", "reason": "external target"}
    return {
        "decision": mode if mode in VALID_FALLBACK_MODES else "allow",
        "risk_level": "low",
        "reason": "no match",
    }
```

- [ ] **Step 4: Re-run the policy and gateway tests to verify they pass**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_policy.py tests/test_gateway.py::test_decide_endpoint_warns_secret_for_ai_model -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/policy.py \
  tools/privacy-filter-local/tests/test_policy.py \
  tools/privacy-filter-local/tests/test_gateway.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: switch secret policy to warn-first review"
```

### Task 5: Add `Detection Mode` UI and secret-first result rendering

**Files:**
- Modify: `tools/privacy-filter-local/ui/index.html`
- Modify: `tools/privacy-filter-local/tests/test_gateway.py`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Add failing UI-contract tests for the new control and messaging**

Append these tests to `tools/privacy-filter-local/tests/test_gateway.py`:

```python
def test_root_ui_includes_detection_mode_selector() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'id="detectionMode"' in response.text
    assert "High Recall" in response.text
    assert "Balanced" in response.text
    assert "High Precision" in response.text
    assert 'id="modeDescription"' in response.text


def test_root_ui_posts_detection_mode_and_renders_secret_first_sections() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'detection_mode: detectionMode.value' in response.text
    assert 'id="primaryRiskList"' in response.text
    assert 'id="secondarySignalsList"' in response.text
    assert "Detected bearer credential. Replace it before sending externally." in response.text
    assert "Secondary Signals" in response.text
```

- [ ] **Step 2: Run the UI tests to verify they fail**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_root_ui_includes_detection_mode_selector tests/test_gateway.py::test_root_ui_posts_detection_mode_and_renders_secret_first_sections -v`

Expected: FAIL because the current HTML has no dropdown, no `modeDescription`, no `primaryRiskList`, no `secondarySignalsList`, and the fetch body does not send `detection_mode`.

- [ ] **Step 3: Update `ui/index.html` to add the selector and split rendering**

Add this control block below the textarea:

```html
<div class="mode-panel">
  <label class="mapping-label" for="detectionMode">Detection Mode</label>
  <select id="detectionMode">
    <option value="high_recall">High Recall</option>
    <option value="balanced" selected>Balanced</option>
    <option value="high_precision">High Precision</option>
  </select>
  <p id="modeDescription" class="hero-copy"></p>
</div>
```

Replace the single recommendation area with primary and secondary sections:

```html
<section id="nextStepPanel" class="panel">
  <div class="section-label">Primary Risk</div>
  <div id="primaryRiskList" class="recommendation-list">
    <p class="recommendation-item">Run a redaction check to inspect secrets before outbound use.</p>
  </div>
  <div class="section-label">Secondary Signals</div>
  <div id="secondarySignalsList" class="recommendation-list">
    <p class="recommendation-item">PII findings will appear here after a scan.</p>
  </div>
</section>
```

Add the new front-end constants and helpers:

```javascript
const MODE_COPY = {
  high_recall: "Try hard not to miss suspicious secrets. This mode may produce more false positives.",
  balanced: "Blend common secret coverage with tolerable noise for everyday developer use.",
  high_precision: "Prefer strong indicators only. This mode reduces noise but may miss edge-case secrets."
};

const SECRET_KIND_COPY = {
  api_key: "Detected API key material. Replace it before sending externally.",
  bearer: "Detected bearer credential. Replace it before sending externally.",
  jwt: "Detected JWT credential material. Use the redacted version for outbound text.",
  session: "Detected session material. Use the redacted version for outbound text.",
  verification_code: "Detected verification code in a secret context. Review before sharing.",
  db_connection: "Detected database connection string with embedded credentials. Replace it before sharing.",
  webhook_secret: "Detected webhook or client secret. Replace it before sending externally.",
  token: "Detected token-like secret material. Review before sharing."
};

function getPrimarySecretSpans(spans) {
  return spans.filter((span) => span.label === "secret");
}

function getSecondaryPiiSpans(spans) {
  return spans.filter((span) => span.label !== "secret");
}
```

Update the fetch payload and rendering path:

```javascript
const detectionMode = document.getElementById("detectionMode");
const modeDescription = document.getElementById("modeDescription");
const primaryRiskList = document.getElementById("primaryRiskList");
const secondarySignalsList = document.getElementById("secondarySignalsList");

function renderModeDescription() {
  modeDescription.textContent = MODE_COPY[detectionMode.value];
}

function renderPrimaryRisk(spans, reason) {
  const secretSpans = getPrimarySecretSpans(spans);
  primaryRiskList.innerHTML = "";

  if (!secretSpans.length) {
    primaryRiskList.innerHTML = '<p class="recommendation-item">No developer secrets detected. Review the secondary signals before sharing.</p>';
    return;
  }

  for (const span of secretSpans) {
    const item = document.createElement("p");
    item.className = "recommendation-item";
    item.textContent = SECRET_KIND_COPY[span.kind] || "Detected secret. Review before sharing.";
    primaryRiskList.appendChild(item);
  }
}

function renderSecondarySignals(spans) {
  const piiSpans = getSecondaryPiiSpans(spans);
  secondarySignalsList.innerHTML = "";

  if (!piiSpans.length) {
    secondarySignalsList.innerHTML = '<p class="recommendation-item">No secondary PII signals detected.</p>';
    return;
  }

  for (const span of piiSpans) {
    const item = document.createElement("p");
    item.className = "recommendation-item";
    item.textContent = EXPLANATION_COPY[span.label] || EXPLANATION_COPY.default;
    secondarySignalsList.appendChild(item);
  }
}

detectionMode.addEventListener("change", renderModeDescription);
renderModeDescription();
```

Update the request payload:

```javascript
body: JSON.stringify({
  text,
  source: "manual_ui",
  target: "ai_model",
  mode: "warn",
  detection_mode: detectionMode.value
})
```

Update the success path:

```javascript
renderPrimaryRisk(data.spans, data.reason);
renderSecondarySignals(data.spans);
renderReplacementMapping(data.spans);
```

Also replace the old panel reset and bootstrap calls:

```javascript
function resetResultPanels() {
  primaryRiskList.innerHTML = "";
  secondarySignalsList.innerHTML = "";
  sourceMappingList.innerHTML = "";
  outputMappingList.innerHTML = "";
}

renderPrimaryRisk([], "");
renderSecondarySignals([]);
renderReplacementMapping([]);
```

- [ ] **Step 4: Re-run the UI tests to verify they pass**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_root_ui_includes_detection_mode_selector tests/test_gateway.py::test_root_ui_posts_detection_mode_and_renders_secret_first_sections -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/ui/index.html \
  tools/privacy-filter-local/tests/test_gateway.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: add secret-first detection mode ui"
```

### Task 6: Final regression and manual smoke verification

**Files:**
- Modify: `tools/privacy-filter-local/tests/test_gateway.py`
- Modify: `tools/privacy-filter-local/tests/test_regex_backstop.py`
- Modify: `tools/privacy-filter-local/tests/test_secret_modes.py`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`
- Test: `tools/privacy-filter-local/tests/test_policy.py`
- Test: `tools/privacy-filter-local/tests/test_regex_backstop.py`
- Test: `tools/privacy-filter-local/tests/test_secret_modes.py`

- [ ] **Step 1: Add a gateway regression that mixes secret and PII**

Append this test to `tools/privacy-filter-local/tests/test_gateway.py`:

```python
def test_redact_endpoint_returns_secret_first_output_with_secondary_pii() -> None:
    client = TestClient(app)
    spans = [
        {
            "start": 0,
            "end": 29,
            "label": "secret",
            "kind": "verification_code",
            "source": "regex",
            "text": "verification code is 246810",
        },
        {
            "start": 37,
            "end": 57,
            "label": "private_email",
            "source": "opf",
            "text": "user@example.com",
        },
    ]

    with patch("app.collect_spans", return_value=spans):
        response = client.post(
            "/redact",
            json={
                "text": "verification code is 246810 email user@example.com",
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
                "detection_mode": "balanced",
            },
        )

    assert response.status_code == 200
    assert response.json()["decision"] == "warn"
    assert response.json()["risk_level"] == "high"
    assert response.json()["spans"][0]["label"] == "secret"
    assert "<SECRET>" in response.json()["redacted_text"]
    assert "<PRIVATE_EMAIL>" in response.json()["redacted_text"]
```

- [ ] **Step 2: Run the targeted regression to verify it passes**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_redact_endpoint_returns_secret_first_output_with_secondary_pii -v`

Expected: PASS

- [ ] **Step 3: Run the full automated suite**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest -v`

Expected: PASS with all gateway, policy, regex, mode, and runtime tests green.

- [ ] **Step 4: Run a manual smoke request for a realistic developer sample**

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
    "text": "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.signaturepart\nDATABASE_URL=postgres://appuser:supersecret@db.internal:5432/app\nverification code is 246810\nemail=user@example.com",
    "source": "manual_ui",
    "target": "ai_model",
    "mode": "warn",
    "detection_mode": "balanced"
  }'
```

Expected response characteristics:

- `decision` is `warn`
- `risk_level` is `high`
- returned `spans` include `kind` values for `bearer`, `db_connection`, and `verification_code`
- `redacted_text` contains `<SECRET>` and `<PRIVATE_EMAIL>`

- [ ] **Step 5: Commit the final verified state**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/app.py \
  tools/privacy-filter-local/policy.py \
  tools/privacy-filter-local/detectors/regex_backstop.py \
  tools/privacy-filter-local/ui/index.html \
  tools/privacy-filter-local/tests/test_gateway.py \
  tools/privacy-filter-local/tests/test_policy.py \
  tools/privacy-filter-local/tests/test_regex_backstop.py \
  tools/privacy-filter-local/tests/test_secret_modes.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: ship developer secret filter modes"
```
