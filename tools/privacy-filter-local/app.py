from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from detectors.opf_runtime import detect_with_runtime
from detectors.regex_backstop import detect_regex_secret_spans
from policy import decide_action

app = FastAPI()

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


class ScanRequest(BaseModel):
    text: str
    source: str
    target: str
    mode: str


def span_priority(span: dict[str, object]) -> tuple[int, int]:
    label = str(span["label"])
    width = int(span["end"]) - int(span["start"])
    return (1 if label == "secret" else 0, width)


def merge_spans(spans: list[dict[str, object]]) -> list[dict[str, object]]:
    ordered = sorted(
        spans,
        key=lambda item: (
            int(item["start"]),
            int(item["end"]),
            -span_priority(item)[0],
            -span_priority(item)[1],
        ),
    )
    merged: list[dict[str, object]] = []
    for span in ordered:
        if not merged:
            merged.append(span)
            continue

        previous = merged[-1]
        if int(span["start"]) < int(previous["end"]):
            if span_priority(span) > span_priority(previous):
                merged[-1] = span
            continue
        merged.append(span)
    return merged


def collect_spans(text: str) -> list[dict[str, object]]:
    spans = detect_with_runtime(text) + detect_regex_secret_spans(text)
    return merge_spans(spans)


def apply_redaction(text: str, spans: list[dict[str, object]]) -> str:
    pieces: list[str] = []
    cursor = 0
    for span in spans:
        start = int(span["start"])
        end = int(span["end"])
        if start < cursor:
            continue
        pieces.append(text[cursor:start])
        pieces.append(PLACEHOLDERS.get(str(span["label"]), "<REDACTED>"))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def build_summary(spans: list[dict[str, object]]) -> dict[str, int]:
    return {
        "span_count": len(spans),
        "secret_count": sum(1 for span in spans if span["label"] == "secret"),
        "pii_count": sum(1 for span in spans if span["label"] != "secret"),
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (Path(__file__).parent / "ui" / "index.html").read_text(encoding="utf-8")


@app.post("/scan")
def scan(request: ScanRequest) -> dict[str, object]:
    spans = collect_spans(request.text)
    decision = decide_action(spans, request.source, request.target, request.mode)
    return {
        "spans": spans,
        "risk_level": decision["risk_level"],
        "summary": build_summary(spans),
        "recommended_action": decision["decision"],
    }


@app.post("/decide")
def decide(request: ScanRequest) -> dict[str, str]:
    spans = collect_spans(request.text)
    return decide_action(spans, request.source, request.target, request.mode)


@app.post("/redact")
def redact(request: ScanRequest) -> dict[str, object]:
    spans = collect_spans(request.text)
    decision = decide_action(spans, request.source, request.target, request.mode)
    return {
        "decision": decision["decision"],
        "risk_level": decision["risk_level"],
        "reason": decision["reason"],
        "spans": spans,
        "redacted_text": apply_redaction(request.text, spans),
    }
