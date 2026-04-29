# Privacy Filter V1 Design

## Goal

Build a localhost-first privacy gateway that detects and redacts secrets / PII before text is sent to AI models or persisted into Linear. V1 must serve manual pre-chat review first, while preserving a clean adapter surface for later Symphony and Linear integration.

## Problem

The immediate failure mode is not "general privacy management." It is accidental disclosure during normal AI work:

- pasting `.env` snippets, logs, stack traces, curl commands, or config into chats
- letting an agent include keys, bearer tokens, or internal URLs in a prompt
- letting an agent persist sensitive text into Linear comments, issue descriptions, or handoff summaries

The system therefore needs a local safety boundary that sits in front of outbound text flows.

## Non-Goals

V1 explicitly does not include:

- image OCR redaction
- PDF parsing / document highlighting
- public share links or reveal tokens
- multi-user auth
- background clipboard interception
- compliance guarantees or legal anonymization claims

## Product Shape

V1 has one primary user-facing mode and two planned integration modes:

1. `manual-ui`
   - browser page on `127.0.0.1`
   - paste text, inspect detections, copy redacted output
2. `symphony-adapter`
   - future caller before prompt submission / handoff persistence
3. `linear-adapter`
   - future caller before comment / issue / status write

The adapters must call the same localhost gateway API. Detection and policy must not be reimplemented inside Symphony or Linear glue code.

## Architecture

```text
manual-ui / symphony-adapter / linear-adapter
                    ↓
             privacy-gateway
                    ↓
        policy-engine + risk-classifier
                    ↓
     privacy-filter-runtime + regex-backstop
```

### privacy-gateway

FastAPI service listening only on `127.0.0.1`. It owns the public API contract:

- `POST /scan`
- `POST /redact`
- `POST /decide`
- `GET /health`
- `GET /` for the manual UI

The gateway orchestrates detectors, merges spans, computes risk, and applies the selected policy.

### privacy-filter-runtime

Wrapper around OpenAI Privacy Filter (`openai/privacy-filter`). It provides structured detections for official categories such as `secret`, `private_email`, `private_phone`, `private_url`, and related PII. The runtime must be isolated behind a small adapter so tests can inject fake results without downloading the real model.

### regex-backstop

Rule-based fallback for high-confidence secrets where shape matching is reliable:

- `sk-...`
- `ghp_...`, `github_pat_...`
- `AKIA...`
- `hf_...`
- `Bearer ...`
- JWT-like tokens

This layer exists because shape-based secret matching is often stricter and more predictable than model inference for common key families.

### policy-engine

Pure decision layer. It does not run detection. It receives:

- detected spans
- source context
- target context
- requested mode

It returns:

- `allow`
- `warn`
- `redact`
- `block`

Default policy:

- `secret` to `ai_model` or `linear`: `block`
- `private_email`, `private_phone`, `account_number`: `redact`
- `private_url`, `private_address`, `private_person`, `private_date`: `warn` or `redact` depending on target

### manual-ui

Minimal static UI served by FastAPI:

- input textarea
- redacted output area
- detection table
- copy button
- summary tiles

The UI must not persist original text. It is a review surface, not a storage surface.

## API Contract

### `POST /scan`

Request:

```json
{
  "text": "curl -H 'Authorization: Bearer ...'",
  "source": "manual_ui",
  "target": "ai_model",
  "mode": "warn"
}
```

Response:

```json
{
  "risk_level": "high",
  "summary": {
    "span_count": 2,
    "secret_count": 1,
    "pii_count": 1
  },
  "spans": [
    {
      "start": 24,
      "end": 54,
      "label": "secret",
      "source": "regex",
      "text": "Bearer ..."
    }
  ],
  "recommended_action": "block"
}
```

### `POST /redact`

Returns the same metadata plus `redacted_text` and replacement details.

### `POST /decide`

Returns only the decision payload needed by adapters:

```json
{
  "decision": "block",
  "reason": "secret detected for ai_model target",
  "risk_level": "high"
}
```

## Context Values

### `source`

- `manual_ui`
- `symphony_prompt`
- `symphony_handoff`
- `linear_comment`

### `target`

- `ai_model`
- `linear`
- `local_review`

### `mode`

- `warn`
- `redact`
- `block`

`mode` is a caller preference, not absolute authority. The policy engine may escalate a weak caller mode when a `secret` is detected.

## File Structure

```text
tools/privacy-filter-local/
├── app.py
├── policy.py
├── detectors/
│   ├── opf_runtime.py
│   └── regex_backstop.py
├── adapters/
│   ├── symphony.py
│   └── linear.py
├── ui/
│   └── index.html
├── tests/
│   ├── test_policy.py
│   ├── test_regex_backstop.py
│   ├── test_gateway.py
│   ├── test_symphony_adapter.py
│   └── test_linear_adapter.py
└── README.md
```

## Symphony Fit

This architecture fits a local Symphony deployment well because Symphony is orchestration, not a privacy engine. The right integration points are:

1. before model submit
2. before handoff persist
3. before external comment / ticket write

Symphony should call `/decide` or `/redact` and record only:

- decision
- risk level
- redacted payload or block reason

It should not keep raw sensitive text as a side-effect of the privacy check.

## Linear Fit

Linear is a persistence boundary, so the safest V1 integration is text-only:

- issue descriptions
- comments
- status updates
- handoff summaries

Attachments, screenshots, and raw logs stay out of scope for V1.

## Security Constraints

- bind to `127.0.0.1` only
- do not log request bodies by default
- do not persist original text
- allow model cache under `~/.opf/privacy_filter`
- expose simple health metadata only

## Tradeoff

This deliberately copies Hugging Face's separation of concerns, but not the full product surface. The engineering lesson to copy is boundary separation, not the queue/share/public-link features that increase attack surface for a single-user localhost tool.

## Success Criteria

V1 is successful when:

1. a pasted API key or bearer token is blocked or redacted before copy-out
2. ordinary technical text is not excessively mangled
3. Symphony can reuse the same gateway before prompt submission
4. Linear can reuse the same gateway before comment persistence
5. the tool remains entirely local in its serving path
