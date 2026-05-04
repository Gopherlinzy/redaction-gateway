import hashlib
import os
from collections import OrderedDict
from functools import lru_cache
from threading import Lock

RUNTIME_CACHE_MAX_ENTRIES = 32
_runtime_cache: OrderedDict[str, tuple[dict[str, object], ...]] = OrderedDict()
_runtime_cache_lock = Lock()
_runtime_cache_hits = 0
_runtime_cache_misses = 0


@lru_cache(maxsize=1)
def get_redactor():
    from opf import OPF

    device = os.getenv("PRIVACY_FILTER_DEVICE", "cpu")
    return OPF(device=device, output_mode="typed", output_text_only=False)


def _normalize_span(span: object) -> dict[str, object]:
    if isinstance(span, dict):
        label = span["label"]
        start = span["start"]
        end = span["end"]
        text = span["text"]
        placeholder = span["placeholder"]
        source = span.get("source", "opf")
    else:
        label = getattr(span, "label")
        start = getattr(span, "start")
        end = getattr(span, "end")
        text = getattr(span, "text")
        placeholder = getattr(span, "placeholder")
        source = getattr(span, "source", "opf")

    if label == "private_email" and isinstance(text, str) and text.startswith("="):
        start += 1
        text = text[1:]

    return {
        "label": label,
        "start": start,
        "end": end,
        "text": text,
        "placeholder": placeholder,
        "source": source,
    }


def _runtime_cache_key(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"{len(text)}:{digest}"


def _cacheable_span(span: dict[str, object]) -> dict[str, object]:
    return {
        "label": span["label"],
        "start": span["start"],
        "end": span["end"],
        "placeholder": span["placeholder"],
        "source": span["source"],
    }


def _materialize_cached_spans(
    text: str,
    cached_spans: tuple[dict[str, object], ...],
) -> list[dict[str, object]]:
    materialized: list[dict[str, object]] = []
    for span in cached_spans:
        item = dict(span)
        item["text"] = text[int(item["start"]) : int(item["end"])]
        materialized.append(item)
    return materialized


def clear_runtime_cache() -> None:
    global _runtime_cache_hits, _runtime_cache_misses
    with _runtime_cache_lock:
        _runtime_cache.clear()
        _runtime_cache_hits = 0
        _runtime_cache_misses = 0


def get_runtime_cache_stats() -> dict[str, object]:
    with _runtime_cache_lock:
        requests = _runtime_cache_hits + _runtime_cache_misses
        hit_rate = (_runtime_cache_hits / requests) if requests else 0.0
        return {
            "entries": len(_runtime_cache),
            "max_entries": RUNTIME_CACHE_MAX_ENTRIES,
            "hits": _runtime_cache_hits,
            "misses": _runtime_cache_misses,
            "requests": requests,
            "hit_rate": round(hit_rate, 4),
        }


def detect_with_runtime(text: str) -> list[dict[str, object]]:
    global _runtime_cache_hits, _runtime_cache_misses
    cache_key = _runtime_cache_key(text)
    with _runtime_cache_lock:
        cached = _runtime_cache.get(cache_key)
        if cached is not None:
            _runtime_cache_hits += 1
            _runtime_cache.move_to_end(cache_key)
            return _materialize_cached_spans(text, cached)
        _runtime_cache_misses += 1

    result = get_redactor().redact(text)
    if hasattr(result, "detected_spans"):
        spans = [_normalize_span(span) for span in result.detected_spans]
    elif isinstance(result, dict):
        spans = [_normalize_span(span) for span in result.get("detected_spans", [])]
    else:
        raise TypeError(f"Unsupported OPF result type: {type(result)!r}")

    with _runtime_cache_lock:
        _runtime_cache[cache_key] = tuple(_cacheable_span(span) for span in spans)
        _runtime_cache.move_to_end(cache_key)
        while len(_runtime_cache) > RUNTIME_CACHE_MAX_ENTRIES:
            _runtime_cache.popitem(last=False)

    return spans
