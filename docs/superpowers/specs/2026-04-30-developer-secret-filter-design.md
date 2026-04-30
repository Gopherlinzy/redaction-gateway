# Developer Secret Filter Design

## Goal

Refocus `privacy-filter-local` into a developer-first secret inspection tool.

The primary job of the tool is to detect and redact outbound developer secrets before text is pasted into external systems. General PII detection remains available, but it becomes secondary in both UI prominence and decision logic.

This design specifically prioritizes:

1. API keys
2. tokens
3. JWTs
4. Bearer credentials
5. cookies and session identifiers
6. verification codes and one-time passwords
7. database connection strings
8. webhook and client secrets

## Problem Being Solved

The current local tool started from a general privacy-filtering posture. That creates two problems for the intended developer workflow:

- secret detection is not the obvious center of the product
- short but dangerous developer secrets can be missed when they depend on context, such as verification codes or one-time passwords

For a developer safety tool, missing a credential-like value is more important than perfectly classifying broad document PII. The system must therefore become `secret-first`, not `PII-first`.

## Product Decision

The tool will remain a local FastAPI app with a static manual UI, but its behavior will change in three ways:

1. secret detection becomes the primary detection surface
2. PII remains enabled, but is treated as secondary signal
3. users can choose between three detection-strength modes from the UI

The default operational posture is `warn`, not `block`.

That means:

- the tool should clearly explain risk when secrets are found
- the tool should always provide a redacted version for safe reference and copying
- the tool should not force hard blocking in the main manual workflow

## User Workflow

The intended flow is:

1. user pastes technical text into the local tool
2. user chooses a detection mode
3. user runs redact or scan
4. tool highlights primary secret risk first
5. tool shows a safe redacted version
6. user copies the redacted text if needed

The workflow is optimized for developer review before content leaves the local machine.

## Non-Goals

This design does not include:

- account systems
- persistent audit history
- remote policy management
- automatic integration with external paste targets
- image or file scanning
- a full expert-rules editor in the UI

It also does not attempt to remove PII support from the underlying stack. The goal is reprioritization, not deletion.

## Detection Model

### Hybrid Approach

The chosen approach is `model + rules`.

The system keeps the OPF runtime for broad contextual detection and general PII support, then layers developer-secret backstop rules on top.

This is necessary because:

- OPF improves coverage for contextual content and non-secret PII
- developer secrets often have strong syntactic patterns that rules detect more reliably
- short secrets such as OTPs often require context words plus lightweight matching rather than generic semantic classification

### Detection Sources

There are two effective sources of spans:

1. `OPF runtime`
   - contextual PII
   - some secret-like entities
   - broad text understanding

2. `developer secret backstop`
   - regex and contextual patterns tuned for software-development text
   - coverage for short codes, credential prefixes, connection strings, and credential labels

Span merging remains necessary, with secrets taking precedence over lower-priority overlaps.

## Secret Taxonomy

The developer-secret layer should explicitly target these groups.

### 1. API Keys and Tokens

Examples:

- `sk-...`
- `ghp_...`
- `github_pat_...`
- `hf_...`
- provider-specific key prefixes
- generic `api_key=...`
- `token=...`

### 2. JWT and Bearer Material

Examples:

- three-part JWTs
- `Authorization: Bearer ...`
- `Bearer ...`

### 3. Cookie and Session Material

Examples:

- `session=...`
- `sessionid=...`
- `connect.sid=...`
- `Set-Cookie: ...`
- common auth cookie names

### 4. Verification Codes

Examples:

- `verification code`
- `OTP`
- `dynamic password`
- `验证码`
- `动态口令`
- `MFA code`
- `passcode`

These values are often short, so detection depends on nearby context terms rather than pure token shape.

### 5. Database Connection Strings

Examples:

- `postgres://user:pass@host/db`
- `mysql://...`
- `mongodb://...`
- DSNs with embedded credentials

### 6. Webhook and Client Secrets

Examples:

- `webhook_secret`
- `signing_secret`
- `client_secret`
- `app_secret`

## Detection Modes

The UI exposes a single `Detection Mode` dropdown. This is the only user-facing control for sensitivity tuning.

### High Recall

Description:

- tries hard not to miss suspicious secrets
- allows more weak-signal and context-based matches

Use case:

- pre-share review
- checking pasted config blocks
- reviewing logs or support transcripts that may contain leaked secrets

Trade-off:

- higher false-positive rate

### Balanced

Description:

- default mode
- blends common secret coverage with tolerable noise

Use case:

- normal day-to-day developer use

Trade-off:

- middle ground between miss rate and noise

### High Precision

Description:

- prefers strong indicators only
- suppresses weaker contextual matches

Use case:

- longer documents
- lower-noise review passes

Trade-off:

- more likely to miss edge-case secrets

## Mode Behavior

Each mode controls two things:

1. which developer-secret rule groups are active
2. how permissive weak contextual patterns are

The first implementation should keep this configuration in backend constants, not in a dynamic admin system.

Examples:

- `High Recall` can enable broader context windows and weaker generic secret labels
- `Balanced` can enable the standard set only
- `High Precision` can restrict matching to stronger signatures and tighter context rules

## API and Data Contract Changes

The backend request models need an explicit `detection_mode` field.

This field is separate from the existing policy-oriented `mode` field.

- `mode` continues to describe the fallback action posture such as `warn`
- `detection_mode` controls detection sensitivity and rule behavior

This field should be accepted by:

- `/scan`
- `/redact`
- `/decide`

The goal is to ensure the selected UI mode actually affects backend behavior and is not merely decorative.

The output contract should remain structurally close to current behavior:

- risk level
- decision
- spans
- summary
- redacted text where applicable

This keeps the manual tool simple while enabling the new mode semantics.

## Decision Logic

### Primary Principle

`secret-first` decision logic must dominate the result.

If a secret is found:

- the primary risk panel should reflect that first
- the recommendation copy should explain the secret category when possible
- PII should not overshadow the secret outcome

### Default Behavior

The default manual-tool behavior is `warn`.

When secrets are detected:

- do not block the user from viewing results
- do not block copying of redacted text
- do show strong warning language and a high-risk signal

When only PII is detected:

- keep the current lower-priority guidance model
- preserve redaction output
- allow the overall result to mention PII risk, but without using the secret-first framing or secret-specific recommendation copy

## UI Design Changes

The existing industrial-console redesign remains the visual base, but the content hierarchy changes.

### Primary Risk

The top risk area must summarize secret findings first.

Example style:

- `Detected verification code in a secret context. Review before sharing.`
- `Detected bearer credential. Replace it before sending externally.`
- `Detected session material. Use the redacted version for outbound text.`

### Secondary Signals

PII detections move into a secondary block.

They remain visible for trust and completeness, but they do not drive the primary message when secrets are present.

### Detection Mode UI

The UI needs:

- a dropdown labeled `Detection Mode`
- inline description text for the currently selected mode
- a sensible default of `Balanced`

The dropdown should be placed near the main input actions, not hidden in a secondary settings region.

### Redaction Output

`Copy Redacted Text` remains a core action.

This matters because the user wants a safe reference version even when the tool only warns. The redacted output is therefore not a secondary convenience. It is part of the core workflow.

## Error Handling

The system must not silently collapse from model-backed detection into a misleadingly weak mode without a clear internal path.

The OPF adapter bug already demonstrated this risk. The implementation should preserve:

- explicit normalization between OPF result objects and internal span dictionaries
- graceful fallback when OPF is unavailable
- tests that prove fallback is intentional rather than accidental

The user-facing UI does not need to expose raw exception details, but the backend must keep the code path understandable and testable.

If OPF is unavailable:

- developer-secret backstop rules must still run
- secret-focused coverage remains the minimum safe baseline
- reduced PII coverage is acceptable, but silent loss of secret coverage is not

## Testing Strategy

Testing should focus on real behavior, not only on static regex snapshots.

### Unit Tests

Add focused tests for each secret category:

- API key
- token label with secret-like value
- JWT
- Bearer credential
- cookie or session material
- verification code with context
- database connection string with embedded credentials
- webhook or client secret

### Mode Tests

Each mode needs behavior tests showing that the same input can produce different matches depending on detection mode.

At minimum:

- a weak-signal sample that matches in `High Recall`
- the same sample either does not match or is downgraded in `High Precision`
- a strong-signal sample that matches in all three modes

### Runtime Tests

Keep explicit tests for:

- OPF result-object normalization
- merge behavior between OPF and regex spans
- secret precedence on overlap

### Gateway Tests

The request-level tests should cover:

- propagation of `detection_mode`
- primary risk based on secrets
- PII remaining visible but secondary
- redacted output remaining copyable and structurally stable

## Implementation Boundaries

The first implementation should stay small and local:

- backend constants for mode configuration
- static UI updates in the existing HTML file
- limited request-model updates
- no separate rules DSL

This is intentionally narrow. The tool is being tuned for a clear developer use case, not generalized into a configurable platform.

## Success Criteria

This design is successful if:

1. the UI clearly reads as a developer secret review tool
2. secret findings dominate the risk narrative
3. PII remains available but secondary
4. users can choose between three detection-strength modes and those modes materially affect backend behavior
5. short secret-like values such as verification codes are covered when context indicates secret risk
6. users can always copy a redacted reference result in the manual workflow

## Open Design Choice Resolved

The approved defaults are:

- `Hybrid model + rules`
- `Detection Mode` dropdown with `High Recall`, `Balanced`, and `High Precision`
- default `Balanced`
- default manual action posture `warn`
- PII retained, but demoted beneath secret-first logic

No additional design decisions are required before implementation planning.
