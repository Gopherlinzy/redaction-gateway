# Privacy Filter Local Redesign Design

## Goal

Redesign the manual UI for `privacy-filter-local` so it feels like a purposeful local security console instead of a bare utility page. The new UI must make three things immediately legible:

1. what sensitive content was found
2. what will be replaced
3. what the user should do next

The redesign is for the existing localhost manual tool only. It does not change the API contract or introduce new backend flows.

## Chosen Direction

The approved direction is `industrial-console`.

This direction treats the UI as a local inspection terminal:

- dark, hard-edged, high-contrast surface
- strong amber / warning accent rather than generic blue or purple SaaS styling
- terminal-adjacent typography and panel framing
- visible sense of "review before outbound transmission"

The page should feel like a local control surface guarding an exit boundary, not a generic form.

## Problem Being Solved

The current UI works functionally but hides the most important decisions inside plain text and JSON:

- risk is shown as a flat label without actionable advice
- detections are visible but not visually connected to the redacted output
- copy and redact actions look mechanically available rather than safety-gated
- the page has no visual hierarchy that reinforces "inspect first, send later"

The redesign must shift the page from "textarea plus response dump" to "inspection workflow."

## Non-Goals

This redesign explicitly does not include:

- changing `/scan`, `/redact`, `/decide`, or `/health` payloads
- adding persistence, history, accounts, or saved sessions
- adding charts, analytics, or multi-step onboarding
- supporting image / attachment review
- redesigning Symphony or Linear integrations
- introducing a frontend framework

Implementation stays in the existing static `ui/index.html` served by FastAPI.

## Experience Principles

### 1. Outbound Boundary First

The page must communicate that text is paused at a boundary before leaving the machine. The UI should not feel like a freeform editor. It should feel like a checkpoint.

### 2. Actionable Risk, Not Passive Status

Risk is not only a severity label. The page must translate severity into a recommendation the user can act on immediately.

### 3. Visual Mapping Between Source and Safe Output

The user should not have to parse raw detection JSON to understand what changed. The source-side sensitive segments and output-side placeholder replacements need an obvious visual relationship.

### 4. Local Tool Aesthetic

The page should clearly read as a localhost tool:

- precise
- compact
- slightly severe
- intentionally non-corporate

## Information Architecture

The page is a single screen with four main regions, in this order:

1. `topline`
   - product name
   - local-only / host marker
   - review-state context

2. `hero split`
   - left: input buffer and primary actions
   - right: risk panel and recommended next steps

3. `replacement mapping`
   - side-by-side source and output mapping
   - visible red and green underline legend

4. `detections detail`
   - lower-priority structured detail block
   - still available for confidence and debugging

The critical insight is that the old detections block remains, but it is demoted below the recommendation and mapping layers.

## Visual System

### Palette

Primary palette:

- background: near-black charcoal
- panel surfaces: translucent dark graphite
- accent: amber / burnt orange
- critical highlight: red
- safe replacement highlight: green
- body text: warm off-white

Rules:

- no purple gradients
- no soft rounded SaaS card language
- use red only for detected raw sensitive content
- use green only for safe replacement placeholders
- use amber for framing, section labels, and primary call-to-action emphasis

### Typography

Use a mono-forward system:

- headings and operational UI can use a monospaced or terminal-adjacent family
- body copy can remain readable but should still feel technical and local-first

The typography should feel instrument-like, not editorial or marketing-driven.

### Shape Language

- corners should be restrained and mostly squared
- borders should do more work than shadows
- panels should feel framed, not floating
- repeated equal-radius pills/cards should be avoided

### Background Treatment

Use subtle console texture:

- faint grid or scanline structure
- restrained layered gradients
- enough atmosphere to avoid a flat dark slab

The background should support the terminal feel without becoming decorative noise.

## Core Components

### Input Buffer Panel

Contains:

- section label such as `Input Buffer`
- short headline that frames the tool as an inspection point
- short helper copy
- textarea / input region
- primary `Redact` action
- secondary `Copy Redacted` action

Behavior:

- the input region remains the main source of truth
- during in-flight redact operations, the primary action should visibly enter a working state
- the area should visually suggest staging rather than composition

### Risk Panel

The risk panel becomes a decision surface, not a single line of metadata.

Required contents:

- severity label
- severity value
- count of detected spans
- short explanation of why the current content is risky

The risk panel should be visually hotter than the rest of the page through stronger accent use and a left-edge warning bar or equivalent structural emphasis.

### Recommended Next Step Panel

This panel is required.

It translates detection results into plain recommendations. The approved tone is directive-first, because the user explicitly approved the version that told them what to do next.

Recommendation copy style:

- short imperative sentence first
- optional reason implied by surrounding risk context
- written for fast action, not policy prose

Example structure:

- `Redact before sending.`
- `Review internal credentials locally.`
- `Keep only placeholders in outbound text.`

### Replacement Mapping Panel

This is the signature interaction of the redesign.

The panel must show a side-by-side or row-paired comparison between:

- source-side sensitive spans
- output-side safe placeholders

Required visual conventions:

- red underline for source text that will be replaced
- green underline for safe output placeholders
- visible legend that explains both underline colors

The mapping should make replacement comprehensible without reading raw JSON.

### Detections Detail Panel

This panel stays, but with lower visual priority.

Purpose:

- preserve transparent inspection data
- support debugging and trust
- avoid forcing the user to rely on it for the main workflow

It can remain terminal-like and structured, but should not compete with the risk and mapping panels for attention.

## Interaction Design

### Redact

When clicked:

- button enters a clear busy state
- status messaging should confirm active work
- result regions update in-place on success
- risk panel and next-step panel update based on returned data

### Copy Redacted

When clipboard access succeeds:

- confirm success briefly

When clipboard access is unavailable:

- preserve the current fallback behavior
- clearly explain that clipboard access is unavailable
- select the redacted text and instruct the user to press `Cmd+C`

This fallback must remain part of the redesign, not treated as an afterthought.

### Status Messaging

Status text should stay concise and operational:

- `Redacting...`
- `Redaction complete.`
- `Clipboard access is unavailable here. Redacted text is selected; press Cmd+C to copy.`

Avoid verbose banners or modal interruptions.

## Responsive Behavior

Desktop:

- two-column hero split
- two-column replacement mapping

Mobile / narrow widths:

- stack hero panels vertically
- stack source/output mapping vertically
- keep action buttons easy to tap
- preserve hierarchy so risk and next steps remain above raw detections

The layout should compress cleanly without becoming a long series of identical cards.

## Accessibility and Clarity

- color cannot be the only signal for replacement mapping; labels / legend must explain semantics
- risk content must remain readable at a glance
- actions must have clear labels
- status region should be announced politely
- contrast must remain strong across dark surfaces

## Technical Constraints

- implementation stays in `tools/privacy-filter-local/ui/index.html`
- no framework migration
- keep current API endpoints unchanged
- preserve existing fallback logic for runtime failure and clipboard denial
- do not add persistence

## Testing Expectations

The redesign implementation should be validated by:

1. HTML response tests that confirm the new structural markers exist
2. browser verification that the localhost page reflects the new layout
3. manual flow check for:
   - redact success
   - risk suggestion visibility
   - replacement mapping visibility
   - clipboard fallback messaging

## Success Criteria

The redesign is successful when:

1. a first-time user can identify the risky source fragment without reading JSON
2. a first-time user can identify the safe replacement output without guessing
3. the page tells the user what to do next after detection
4. the UI feels intentional and local-tool specific rather than template-generated
5. existing manual redaction and copy fallback behavior still works
