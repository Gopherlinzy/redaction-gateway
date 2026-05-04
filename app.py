from contextlib import asynccontextmanager
from collections import deque
import asyncio
import io
import os
import re
import logging
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from time import perf_counter

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from detectors.opf_runtime import detect_with_runtime, get_runtime_cache_stats
from detectors.secret_candidates import generate_secret_candidates
from detectors.secret_scores import filter_candidates_for_mode
from detectors.regex_backstop import detect_regex_secret_spans, detect_regex_pii_spans
from detectors.file_extractor import (
    extract_text,
    extract_chunks,
    redact_pdf_bytes,
    redact_docx_bytes,
    UnsupportedFileTypeError,
)
from policy import decide_action

# Reuse uvicorn's configured logger so INFO-level timing logs surface in local runs.
logger = logging.getLogger("uvicorn.error")
DETECTION_MODE_DEFAULT = "balanced"
OPF_PREWARM_ENV = "PRIVACY_FILTER_PREWARM_ON_STARTUP"
OPF_SKIP_THRESHOLD = 500  # chars — short text covered well by parser+regex alone
_opf_executor = ThreadPoolExecutor(max_workers=1)  # OPF is not thread-safe
TIMING_LOGS_ENV = "PRIVACY_FILTER_TIMING_LOGS"
OPF_WARMUP_TEXT = (
    "OPENAI_API_KEY=sk-prewarmsecretvalue1234567890\n"
    "email=user@example.com"
)
REQUEST_TIMING_WINDOW = 20
TEXT_LENGTH_BUCKETS = (
    (255, "0-255"),
    (1023, "256-1023"),
    (4095, "1024-4095"),
    (None, "4096+"),
)

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
    detection_mode: str = DETECTION_MODE_DEFAULT


_runtime_status_lock = Lock()
_runtime_status: dict[str, object] = {
    "runtime_ready": False,
    "prewarm_enabled": True,
    "prewarm_attempted": False,
    "prewarm_succeeded": False,
    "last_prewarm_seconds": None,
    "last_prewarm_error": None,
    "last_ready_source": None,
}

_request_metrics_lock = Lock()
_request_timings: deque[dict[str, object]] = deque(maxlen=REQUEST_TIMING_WINDOW)
_request_count = 0
_last_request_timing: dict[str, object] | None = None


def _should_prewarm_runtime() -> bool:
    if os.getenv("PYTEST_CURRENT_TEST"):
        return False

    value = os.getenv(OPF_PREWARM_ENV, "1").strip().lower()
    return value not in {"0", "false", "no", "off"}


def _should_log_timing() -> bool:
    value = os.getenv(TIMING_LOGS_ENV, "0").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _set_runtime_status(**updates: object) -> None:
    with _runtime_status_lock:
        _runtime_status.update(updates)


def _mark_runtime_ready(source: str) -> None:
    _set_runtime_status(runtime_ready=True, last_ready_source=source)


def get_runtime_status_snapshot() -> dict[str, object]:
    with _runtime_status_lock:
        snapshot = dict(_runtime_status)
    if snapshot["runtime_ready"]:
        snapshot["status"] = "ready"
    elif snapshot["last_prewarm_error"]:
        snapshot["status"] = "failed"
    else:
        snapshot["status"] = "warming"
    return snapshot


def _text_length_bucket(length: int) -> str:
    for upper_bound, label in TEXT_LENGTH_BUCKETS:
        if upper_bound is None or length <= upper_bound:
            return label
    return TEXT_LENGTH_BUCKETS[-1][1]


def _hit_type_bucket(secret_count: int, pii_count: int) -> str:
    if secret_count > 0 and pii_count > 0:
        return "mixed"
    if secret_count > 0:
        return "secret_only"
    if pii_count > 0:
        return "pii_only"
    return "no_hit"


def _round_timing(timing: dict[str, object]) -> dict[str, object]:
    rounded = dict(timing)
    for key in ("opf_seconds", "parser_seconds", "regex_seconds", "merge_seconds", "total_seconds"):
        rounded[key] = round(float(rounded[key]), 6)
    return rounded


def _record_request_timing(timing: dict[str, object]) -> None:
    global _request_count, _last_request_timing
    rounded = _round_timing(timing)
    rounded["endpoint"] = str(rounded.get("endpoint", "collect_spans"))
    rounded["text_length"] = int(rounded.get("text_length", 0))
    rounded["text_length_bucket"] = _text_length_bucket(int(rounded["text_length"]))
    rounded["secret_count"] = int(rounded.get("secret_count", 0))
    rounded["pii_count"] = int(rounded.get("pii_count", 0))
    rounded["hit_type_bucket"] = _hit_type_bucket(
        int(rounded["secret_count"]),
        int(rounded["pii_count"]),
    )
    with _request_metrics_lock:
        _request_count += 1
        _last_request_timing = rounded
        _request_timings.append(rounded)


def get_request_metrics_snapshot() -> dict[str, object]:
    with _request_metrics_lock:
        recent = [dict(item) for item in _request_timings]
        total_requests = _request_count
        last = dict(_last_request_timing) if _last_request_timing is not None else None

    averages = {
        "opf_seconds": 0.0,
        "parser_seconds": 0.0,
        "regex_seconds": 0.0,
        "merge_seconds": 0.0,
        "total_seconds": 0.0,
    }
    if recent:
        for key in averages:
            averages[key] = round(
                sum(float(item[key]) for item in recent) / len(recent),
                6,
            )

    buckets: dict[str, dict[str, dict[str, object]]] = {}
    hit_type_buckets: dict[str, dict[str, dict[str, object]]] = {}
    for item in recent:
        endpoint = str(item["endpoint"])
        bucket = str(item["text_length_bucket"])
        endpoint_buckets = buckets.setdefault(endpoint, {})
        bucket_entry = endpoint_buckets.setdefault(
            bucket,
            {
                "count": 0,
                "average_total_seconds": 0.0,
                "average_opf_seconds": 0.0,
            },
        )
        bucket_entry["count"] += 1
        bucket_entry["average_total_seconds"] += float(item["total_seconds"])
        bucket_entry["average_opf_seconds"] += float(item["opf_seconds"])

        hit_type = str(item["hit_type_bucket"])
        endpoint_hit_types = hit_type_buckets.setdefault(endpoint, {})
        hit_type_entry = endpoint_hit_types.setdefault(
            hit_type,
            {
                "count": 0,
                "average_total_seconds": 0.0,
                "average_opf_seconds": 0.0,
            },
        )
        hit_type_entry["count"] += 1
        hit_type_entry["average_total_seconds"] += float(item["total_seconds"])
        hit_type_entry["average_opf_seconds"] += float(item["opf_seconds"])

    for endpoint_buckets in buckets.values():
        for bucket_entry in endpoint_buckets.values():
            count = int(bucket_entry["count"])
            bucket_entry["average_total_seconds"] = round(
                float(bucket_entry["average_total_seconds"]) / count,
                6,
            )
            bucket_entry["average_opf_seconds"] = round(
                float(bucket_entry["average_opf_seconds"]) / count,
                6,
            )

    for endpoint_hit_types in hit_type_buckets.values():
        for hit_type_entry in endpoint_hit_types.values():
            count = int(hit_type_entry["count"])
            hit_type_entry["average_total_seconds"] = round(
                float(hit_type_entry["average_total_seconds"]) / count,
                6,
            )
            hit_type_entry["average_opf_seconds"] = round(
                float(hit_type_entry["average_opf_seconds"]) / count,
                6,
            )

    return {
        "total_requests": total_requests,
        "recent_window": REQUEST_TIMING_WINDOW,
        "recent_count": len(recent),
        "last_timing": last,
        "average_timing": averages,
        "buckets": buckets,
        "hit_type_buckets": hit_type_buckets,
    }


def get_last_request_timing() -> dict[str, object] | None:
    snapshot = get_request_metrics_snapshot()
    return snapshot["last_timing"]


def prewarm_runtime() -> bool:
    prewarm_enabled = _should_prewarm_runtime()
    _set_runtime_status(prewarm_enabled=prewarm_enabled)

    if not prewarm_enabled:
        return False

    start = perf_counter()
    _set_runtime_status(
        prewarm_attempted=True,
        prewarm_succeeded=False,
        last_prewarm_seconds=None,
        last_prewarm_error=None,
    )
    try:
        detect_with_runtime(OPF_WARMUP_TEXT)
    except Exception as exc:
        _set_runtime_status(last_prewarm_error=str(exc))
        logger.warning("OPF runtime prewarm failed, leaving lazy init in place: %s", exc)
        return False

    elapsed = perf_counter() - start
    _set_runtime_status(
        prewarm_succeeded=True,
        last_prewarm_seconds=round(elapsed, 6),
        last_prewarm_error=None,
    )
    _mark_runtime_ready("prewarm")
    logger.info("OPF runtime prewarmed in %.2fs", elapsed)
    return True


@asynccontextmanager
async def lifespan(_app: FastAPI):
    prewarm_runtime()
    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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


_URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)


def _filter_opf_url_false_positives(spans: list[dict[str, object]]) -> list[dict[str, object]]:
    result = []
    for span in spans:
        if span.get("source") == "opf" and span.get("label") == "secret":
            text = str(span.get("text", ""))
            if _URL_PATTERN.match(text):
                continue
        result.append(span)
    return result


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


async def _detect_opf_async(text: str) -> tuple[list[dict[str, object]], float, bool]:
    """Run OPF in thread pool — non-blocking. Returns (spans, elapsed_seconds, opf_available)."""
    if len(text) < OPF_SKIP_THRESHOLD:
        return [], 0.0, True
    loop = asyncio.get_event_loop()
    start = perf_counter()
    try:
        spans = await loop.run_in_executor(_opf_executor, detect_with_runtime, text)
        _mark_runtime_ready("request")
        return spans, perf_counter() - start, True
    except Exception as exc:
        logger.warning("OPF runtime unavailable, falling back to regex-only detection: %s", exc)
        return [], perf_counter() - start, False


def _run_opf_on_chunk(chunk_text: str, offset: int) -> list[dict[str, object]]:
    """Run OPF on one chunk and shift span offsets to full-text coordinates."""
    try:
        spans = detect_with_runtime(chunk_text)
    except Exception as exc:
        logger.warning("OPF chunk detection failed (offset=%d): %s", offset, exc)
        return []
    shifted: list[dict[str, object]] = []
    for sp in spans:
        sp = dict(sp)
        sp["start"] = int(sp["start"]) + offset
        sp["end"] = int(sp["end"]) + offset
        # re-materialize text from shifted coordinates is handled by merge_spans caller
        shifted.append(sp)
    return shifted


async def _detect_opf_chunked(
    full_text: str,
    chunks: list[tuple[str, int]],
) -> tuple[list[dict[str, object]], float, bool]:
    """
    Run OPF per paragraph chunk and merge results into full-text offsets.
    Falls back to whole-text OPF when chunks are unavailable.
    Returns (spans, elapsed_seconds, opf_available).
    """
    if not chunks:
        return await _detect_opf_async(full_text)

    loop = asyncio.get_event_loop()
    start = perf_counter()
    all_spans: list[dict[str, object]] = []
    opf_available = True

    for chunk_text, offset in chunks:
        if len(chunk_text) < OPF_SKIP_THRESHOLD:
            continue
        try:
            chunk_spans = await loop.run_in_executor(
                _opf_executor, _run_opf_on_chunk, chunk_text, offset
            )
            all_spans.extend(chunk_spans)
            _mark_runtime_ready("request")
        except Exception as exc:
            logger.warning("OPF chunked detection unavailable: %s", exc)
            opf_available = False
            break

    return all_spans, perf_counter() - start, opf_available


def collect_spans(
    text: str,
    detection_mode: str = DETECTION_MODE_DEFAULT,
    endpoint: str = "collect_spans",
    precomputed_opf: list[dict[str, object]] | None = None,
    precomputed_opf_seconds: float = 0.0,
) -> list[dict[str, object]]:
    total_start = perf_counter()
    runtime_spans: list[dict[str, object]]
    if precomputed_opf is not None:
        runtime_spans = precomputed_opf
        opf_seconds = precomputed_opf_seconds
    else:
        opf_start = perf_counter()
        try:
            runtime_spans = detect_with_runtime(text)
            _mark_runtime_ready("request")
        except Exception as exc:
            logger.warning("OPF runtime unavailable, falling back to regex-only detection: %s", exc)
            runtime_spans = []
        opf_seconds = perf_counter() - opf_start

    parser_start = perf_counter()
    parser_candidates = filter_candidates_for_mode(
        generate_secret_candidates(text),
        detection_mode,
    )
    parser_seconds = perf_counter() - parser_start

    regex_start = perf_counter()
    legacy_regex_spans = detect_regex_secret_spans(text, detection_mode)
    pii_regex_spans = detect_regex_pii_spans(text)
    regex_seconds = perf_counter() - regex_start

    merge_start = perf_counter()
    filtered_runtime_spans = _filter_opf_url_false_positives(runtime_spans)
    spans = filtered_runtime_spans + legacy_regex_spans + pii_regex_spans + parser_candidates
    merged = merge_spans(spans)
    merge_seconds = perf_counter() - merge_start
    total_seconds = perf_counter() - total_start

    if _should_log_timing():
        logger.info(
            "collect_spans timings opf=%.4fs parser=%.4fs regex=%.4fs merge=%.4fs total=%.4fs spans=%d mode=%s",
            opf_seconds,
            parser_seconds,
            regex_seconds,
            merge_seconds,
            total_seconds,
            len(merged),
            detection_mode,
        )

    _record_request_timing(
        {
            "endpoint": endpoint,
            "text_length": len(text),
            "opf_seconds": opf_seconds,
            "parser_seconds": parser_seconds,
            "regex_seconds": regex_seconds,
            "merge_seconds": merge_seconds,
            "total_seconds": total_seconds,
            "span_count": len(merged),
            "secret_count": sum(1 for span in merged if span["label"] == "secret"),
            "pii_count": sum(1 for span in merged if span["label"] != "secret"),
            "detection_mode": detection_mode,
        }
    )
    return merged


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


@app.get("/ready")
def ready() -> dict[str, object]:
    snapshot = get_runtime_status_snapshot()
    if snapshot["runtime_ready"]:
        return snapshot
    return JSONResponse(status_code=503, content=snapshot)


@app.get("/stats")
def stats() -> dict[str, object]:
    return {
        "runtime": get_runtime_status_snapshot(),
        "cache": get_runtime_cache_stats(),
        "requests": get_request_metrics_snapshot(),
    }


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (Path(__file__).parent / "ui" / "index.html").read_text(encoding="utf-8")


@app.post("/scan")
async def scan(request: ScanRequest) -> dict[str, object]:
    opf_spans, opf_seconds, opf_available = await _detect_opf_async(request.text)
    spans = collect_spans(request.text, request.detection_mode, endpoint="/scan",
                          precomputed_opf=opf_spans, precomputed_opf_seconds=opf_seconds)
    decision = decide_action(spans, request.source, request.target, request.mode)
    return {
        "spans": spans,
        "risk_level": decision["risk_level"],
        "summary": build_summary(spans),
        "recommended_action": decision["decision"],
        "opf_available": opf_available,
        "timings": get_last_request_timing(),
    }


@app.post("/decide")
async def decide(request: ScanRequest) -> dict[str, object]:
    opf_spans, opf_seconds, opf_available = await _detect_opf_async(request.text)
    spans = collect_spans(request.text, request.detection_mode, endpoint="/decide",
                          precomputed_opf=opf_spans, precomputed_opf_seconds=opf_seconds)
    decision = decide_action(spans, request.source, request.target, request.mode)
    decision["timings"] = get_last_request_timing()
    decision["opf_available"] = opf_available
    return decision


@app.post("/redact")
async def redact(request: ScanRequest) -> dict[str, object]:
    opf_spans, opf_seconds, opf_available = await _detect_opf_async(request.text)
    spans = collect_spans(request.text, request.detection_mode, endpoint="/redact",
                          precomputed_opf=opf_spans, precomputed_opf_seconds=opf_seconds)
    decision = decide_action(spans, request.source, request.target, request.mode)
    return {
        "decision": decision["decision"],
        "risk_level": decision["risk_level"],
        "reason": decision["reason"],
        "spans": spans,
        "redacted_text": apply_redaction(request.text, spans),
        "opf_available": opf_available,
        "timings": get_last_request_timing(),
    }


@app.post("/redact-file")
async def redact_file(
    file: UploadFile = File(...),
    source: str = Form("manual_ui"),
    target: str = Form("ai_model"),
    mode: str = Form("warn"),
    detection_mode: str = Form(DETECTION_MODE_DEFAULT),
) -> dict[str, object]:
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in (".pdf", ".docx"):
        return JSONResponse(
            status_code=422,
            content={"error": f"Unsupported file type '{suffix}'; supported: .pdf, .docx"},
        )

    raw = await file.read()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(raw)
        tmp_path = tmp.name

    try:
        try:
            text = extract_text(tmp_path, suffix)
        except UnsupportedFileTypeError as exc:
            return JSONResponse(status_code=422, content={"error": str(exc)})

        if not text.strip():
            return JSONResponse(status_code=422, content={"error": "No text could be extracted from the file"})

        chunks = extract_chunks(text)
        opf_spans, opf_seconds, opf_available = await _detect_opf_chunked(text, chunks)
        spans = collect_spans(text, detection_mode, endpoint="/redact-file",
                              precomputed_opf=opf_spans, precomputed_opf_seconds=opf_seconds)
        decision = decide_action(spans, source, target, mode)
        return {
            "filename": file.filename,
            "file_type": suffix.lstrip("."),
            "char_count": len(text),
            "source_text": text,
            "decision": decision["decision"],
            "risk_level": decision["risk_level"],
            "reason": decision["reason"],
            "spans": spans,
            "redacted_text": apply_redaction(text, spans),
            "summary": build_summary(spans),
            "opf_available": opf_available,
            "timings": get_last_request_timing(),
        }
    finally:
        Path(tmp_path).unlink(missing_ok=True)


_FILE_MEDIA_TYPES = {
    ".pdf":  "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


@app.post("/redact-file/download")
async def redact_file_download(
    file: UploadFile = File(...),
    source: str = Form("manual_ui"),
    target: str = Form("ai_model"),
    mode: str = Form("warn"),
    detection_mode: str = Form(DETECTION_MODE_DEFAULT),
    active_categories: str = Form(None),
) -> StreamingResponse:
    """
    返回脱敏后的原格式文件（PDF 或 DOCX）供下载。
    PDF：用 PyMuPDF redaction API 画黑块覆盖密钥。
    DOCX：在 run 级别替换密钥文字为 <SECRET>。
    """
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in _FILE_MEDIA_TYPES:
        return JSONResponse(
            status_code=422,
            content={"error": f"Unsupported file type '{suffix}'; supported: .pdf, .docx"},
        )

    raw = await file.read()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(raw)
        tmp_path = tmp.name

    try:
        try:
            text = extract_text(tmp_path, suffix)
        except UnsupportedFileTypeError as exc:
            return JSONResponse(status_code=422, content={"error": str(exc)})

        if not text.strip():
            return JSONResponse(status_code=422, content={"error": "No text could be extracted from the file"})

        chunks = extract_chunks(text)
        opf_spans, opf_seconds, _opf_av = await _detect_opf_chunked(text, chunks)
        spans = collect_spans(text, detection_mode, endpoint="/redact-file/download",
                              precomputed_opf=opf_spans, precomputed_opf_seconds=opf_seconds)

        # Filter spans by active_categories if provided
        import json as _json
        if active_categories:
            try:
                allowed = set(_json.loads(active_categories))
                active_spans = [s for s in spans if s.get("label") in allowed]
            except Exception:
                active_spans = spans
        else:
            active_spans = spans

        # Redact only the active spans
        redact_values = list({
            text[int(s["start"]):int(s["end"])]
            for s in active_spans
            if text[int(s["start"]):int(s["end"])].strip()
        })
        secret_count = sum(1 for s in active_spans if s.get("label") == "secret")

        if suffix == ".pdf":
            file_bytes = redact_pdf_bytes(tmp_path, redact_values)
        else:
            file_bytes = redact_docx_bytes(tmp_path, redact_values)

        stem = Path(file.filename or "document").stem
        download_name = f"{stem}_redacted{suffix}"
        return StreamingResponse(
            io.BytesIO(file_bytes),
            media_type=_FILE_MEDIA_TYPES[suffix],
            headers={
                "Content-Disposition": f'attachment; filename="{download_name}"',
                "X-Privacy-Secrets-Found": str(secret_count),
                "X-Privacy-Spans-Total": str(len(spans)),
            },
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)
