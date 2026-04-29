# Privacy Filter Local Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the manual `privacy-filter-local` page into the approved industrial-console design, with explanation-first risk guidance and red/green replacement mapping, without changing the existing API.

**Architecture:** Keep the FastAPI service and `/redact` payload unchanged. Implement the redesign entirely inside the existing static `ui/index.html`, using CSS for the console visual system and client-side helpers that derive explanation copy and replacement mapping rows from the existing `spans`, `reason`, `risk_level`, and `redacted_text` fields. All code work happens in the dedicated development worktree at `/Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1`.

**Tech Stack:** Python 3.14, FastAPI, pytest, vanilla HTML/CSS/JavaScript, localhost browser verification

---

## File Map

**Worktree root:** `/Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1`

- Modify: `tools/privacy-filter-local/ui/index.html`
- Modify: `tools/privacy-filter-local/tests/test_gateway.py`

### Task 1: Lock the redesigned UI contract in gateway tests

**Files:**
- Modify: `tools/privacy-filter-local/tests/test_gateway.py`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Write the failing layout-contract test**

```python
def test_root_ui_includes_industrial_console_sections() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'class="app-shell"' in response.text
    assert 'id="inputPanel"' in response.text
    assert 'id="riskPanel"' in response.text
    assert 'id="nextStepPanel"' in response.text
    assert 'id="replacementMapping"' in response.text
    assert "Input Buffer" in response.text
    assert "Recommended Next Step" in response.text
    assert "Replacement Mapping" in response.text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_root_ui_includes_industrial_console_sections -v`
Expected: FAIL because the current HTML does not contain the new console shell classes, ids, or section labels.

- [ ] **Step 3: Add the helper-contract test for explanation copy and mapping helpers**

```python
def test_root_ui_includes_explanation_first_helpers() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert "function buildRecommendationMessage" in response.text
    assert "function renderReplacementMapping" in response.text
    assert "Detected secret. Replace it before sending externally." in response.text
    assert "Detected private email. Redact it if the text will leave local review." in response.text
    assert "红线 = 原文里将被替换掉的敏感内容" in response.text
    assert "绿线 = 脱敏后保留下来的安全占位符" in response.text
```

- [ ] **Step 4: Run both UI contract tests to verify they fail**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_root_ui_includes_industrial_console_sections tests/test_gateway.py::test_root_ui_includes_explanation_first_helpers -v`
Expected: FAIL because the current page does not expose the redesigned sections or helper strings.

- [ ] **Step 5: Commit the failing-test checkpoint after implementation is complete**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/tests/test_gateway.py \
  tools/privacy-filter-local/ui/index.html
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: redesign privacy filter manual ui"
```

### Task 2: Replace the minimal page shell with the industrial-console layout

**Files:**
- Modify: `tools/privacy-filter-local/ui/index.html`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Replace the plain body structure with the new console hierarchy**

Use this structure inside `<body>`:

```html
<body>
  <main class="app-shell">
    <header class="topline">
      <span>Privacy Filter Local</span>
      <span>127.0.0.1 / local-only / review required</span>
    </header>

    <section class="hero-grid">
      <section id="inputPanel" class="panel panel-primary">
        <div class="section-label">Input Buffer</div>
        <h1 class="hero-title">Inspect before the text leaves the machine.</h1>
        <p class="hero-copy">
          Review sensitive text locally, redact it, then copy the safe output.
        </p>
        <textarea id="sourceText" rows="12"></textarea>
        <div class="control-row">
          <button id="redactButton" type="button">Redact</button>
          <button id="copyButton" type="button" class="secondary-action">Copy Redacted</button>
        </div>
      </section>

      <aside id="riskPanel" class="panel panel-risk">
        <div class="section-label">Risk</div>
        <div class="risk-summary">
          <span id="riskLevel">risk: unknown</span>
          <span id="spanCount">spans: 0</span>
        </div>
        <p id="riskReason">No sensitive content detected yet.</p>
      </aside>
    </section>

    <section id="nextStepPanel" class="panel">
      <div class="section-label">Recommended Next Step</div>
      <div id="recommendationList" class="recommendation-list">
        <p class="recommendation-item">Run a redaction check to see what needs replacement before outbound use.</p>
      </div>
    </section>

    <section id="replacementMapping" class="panel">
      <div class="section-label">Replacement Mapping</div>
      <div id="mappingLegend" class="mapping-legend">
        <span class="legend-hot">红线 = 原文里将被替换掉的敏感内容</span>
        <span class="legend-safe">绿线 = 脱敏后保留下来的安全占位符</span>
      </div>
      <div class="mapping-grid">
        <div>
          <div class="mapping-label">Source</div>
          <div id="sourceMappingList" class="mapping-list"></div>
        </div>
        <div>
          <div class="mapping-label">Output</div>
          <div id="outputMappingList" class="mapping-list"></div>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="section-label">Detections</div>
      <pre id="detectionList">[]</pre>
    </section>

    <section class="panel">
      <div class="section-label">Redacted Output</div>
      <pre id="redactedText"></pre>
      <div id="statusMessage" role="status" aria-live="polite"></div>
    </section>
  </main>
```

- [ ] **Step 2: Replace the default page styling with the console visual system**

Add a `<style>` block that defines:

```css
:root {
  --bg: #090a0c;
  --panel: rgba(255, 255, 255, 0.035);
  --panel-border: rgba(255, 183, 111, 0.22);
  --text: #efe8dc;
  --muted: rgba(239, 232, 220, 0.72);
  --accent: #ff7c22;
  --accent-soft: #ffb76f;
  --danger: #ff5f57;
  --safe: #65d46e;
}

body {
  margin: 0;
  min-height: 100vh;
  background:
    linear-gradient(135deg, rgba(255, 124, 34, 0.12), transparent 34%),
    linear-gradient(180deg, rgba(255, 255, 255, 0.03), transparent 24%),
    var(--bg);
  color: var(--text);
  font-family: "SF Mono", Menlo, Monaco, monospace;
}

.app-shell {
  max-width: 1160px;
  margin: 0 auto;
  padding: 24px;
  display: grid;
  gap: 16px;
}

.hero-grid,
.mapping-grid {
  display: grid;
  grid-template-columns: 1.35fr 0.95fr;
  gap: 16px;
}

.panel {
  border: 1px solid var(--panel-border);
  background: var(--panel);
  padding: 16px;
}

.panel-risk {
  border-left: 4px solid var(--accent);
  background: linear-gradient(90deg, rgba(255, 124, 34, 0.18), rgba(255, 255, 255, 0.03));
}

.section-label,
.topline {
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--accent-soft);
  font-size: 11px;
}

.legend-hot { color: var(--danger); }
.legend-safe { color: var(--safe); }

@media (max-width: 900px) {
  .hero-grid,
  .mapping-grid {
    grid-template-columns: 1fr;
  }
}
```

- [ ] **Step 3: Run the layout-contract tests to verify they pass**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_root_ui_includes_industrial_console_sections -v`
Expected: PASS

- [ ] **Step 4: Reload the local page and inspect static hierarchy**

Run:

```bash
cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local
./.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 7861
```

Expected: the page still loads on `http://127.0.0.1:7861/`, but now shows the console shell, split hero, and empty replacement-mapping region.

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add tools/privacy-filter-local/ui/index.html
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: add industrial console layout"
```

### Task 3: Render explanation-first risk guidance and red/green replacement mapping

**Files:**
- Modify: `tools/privacy-filter-local/ui/index.html`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Add the explanation-copy and mapping helper constants**

Insert these constants near the top of the script:

```javascript
const PLACEHOLDER_COPY = {
  secret: "<SECRET>",
  private_email: "<PRIVATE_EMAIL>",
  private_phone: "<PRIVATE_PHONE>",
  account_number: "<ACCOUNT_NUMBER>",
  private_url: "<PRIVATE_URL>",
  private_address: "<PRIVATE_ADDRESS>",
  private_person: "<PRIVATE_PERSON>",
  private_date: "<PRIVATE_DATE>"
};

const EXPLANATION_COPY = {
  secret: "Detected secret. Replace it before sending externally.",
  private_email: "Detected private email. Redact it if the text will leave local review.",
  private_phone: "Detected private phone. Redact it before external sharing.",
  account_number: "Detected account number. Replace it before the text leaves this machine.",
  default: "Detected sensitive content. Keep only placeholders in outbound text."
};
```

- [ ] **Step 2: Add the rendering helpers**

Add these functions below `getErrorMessage`:

```javascript
function buildRecommendationMessage(spans) {
  if (!spans.length) {
    return ["No sensitive content detected. Local review can continue."];
  }

  const labels = [...new Set(spans.map((span) => span.label))];
  return labels.map((label) => EXPLANATION_COPY[label] || EXPLANATION_COPY.default);
}

function renderRecommendationList(spans) {
  const messages = buildRecommendationMessage(spans);
  recommendationList.innerHTML = "";

  for (const message of messages) {
    const item = document.createElement("p");
    item.className = "recommendation-item";
    item.textContent = message;
    recommendationList.appendChild(item);
  }
}

function renderReplacementMapping(spans) {
  sourceMappingList.innerHTML = "";
  outputMappingList.innerHTML = "";

  for (const span of spans) {
    const sourceRow = document.createElement("div");
    sourceRow.className = "mapping-row mapping-row-source";
    sourceRow.innerHTML = `<span class="mark mark-hot">${span.text}</span>`;
    sourceMappingList.appendChild(sourceRow);

    const outputRow = document.createElement("div");
    outputRow.className = "mapping-row mapping-row-output";
    outputRow.innerHTML = `<span class="mark mark-safe">${PLACEHOLDER_COPY[span.label] || "<REDACTED>"}</span>`;
    outputMappingList.appendChild(outputRow);
  }
}
```

- [ ] **Step 3: Update the redact flow to populate the new panels**

In the `redactButton` handler, after `const data = await response.json();`, update the rendering section to:

```javascript
riskLevel.textContent = `risk: ${data.risk_level}`;
spanCount.textContent = `spans: ${data.spans.length}`;
riskReason.textContent = data.reason;
detectionList.textContent = JSON.stringify(data.spans, null, 2);
redactedText.textContent = data.redacted_text;
renderRecommendationList(data.spans);
renderReplacementMapping(data.spans);
setStatus("Redaction complete.");
```

Also add empty-state handling before the `try` block:

```javascript
recommendationList.innerHTML = "";
sourceMappingList.innerHTML = "";
outputMappingList.innerHTML = "";
```

- [ ] **Step 4: Run the helper-contract tests to verify they pass**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest tests/test_gateway.py::test_root_ui_includes_explanation_first_helpers -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/ui/index.html \
  tools/privacy-filter-local/tests/test_gateway.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "feat: add risk guidance and replacement mapping"
```

### Task 4: Run full verification against the worktree service

**Files:**
- Modify: `tools/privacy-filter-local/ui/index.html`
- Test: `tools/privacy-filter-local/tests/test_gateway.py`

- [ ] **Step 1: Run the full test suite**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m pytest -v`
Expected: all tests PASS.

- [ ] **Step 2: Start the worktree service**

Run: `cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local && ./.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 7861`
Expected: service listens on `http://127.0.0.1:7861/`.

- [ ] **Step 3: Verify the redesigned page manually**

Run:

```bash
curl -s http://127.0.0.1:7861/health
curl -s -X POST http://127.0.0.1:7861/redact \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "email: a@b.c token=sk-testsecretvalue1234567890",
    "source": "manual_ui",
    "target": "ai_model",
    "mode": "warn"
  }'
```

Expected:

- `/health` returns `{"status":"ok"}`
- `/redact` returns `risk_level`, `reason`, `spans`, and `redacted_text`
- browser UI shows explanation-first recommendation text
- browser UI shows red-underlined source rows and green-underlined replacement rows

- [ ] **Step 4: Verify clipboard fallback still communicates clearly**

Manual check in browser:

- click `Copy Redacted`
- if clipboard permission is denied, confirm the status message reads `Clipboard access is unavailable here. Redacted text is selected; press Cmd+C to copy.`
- confirm the redacted output is selected for manual copy

- [ ] **Step 5: Final commit if any verification-driven tweaks were needed**

```bash
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 add \
  tools/privacy-filter-local/ui/index.html \
  tools/privacy-filter-local/tests/test_gateway.py
git -C /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1 commit -m "test: verify redesigned privacy filter ui"
```
