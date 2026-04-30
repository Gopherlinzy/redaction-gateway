import os
from functools import lru_cache


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


def detect_with_runtime(text: str) -> list[dict[str, object]]:
    result = get_redactor().redact(text)
    if hasattr(result, "detected_spans"):
        return [_normalize_span(span) for span in result.detected_spans]

    if isinstance(result, dict):
        return [_normalize_span(span) for span in result.get("detected_spans", [])]

    raise TypeError(f"Unsupported OPF result type: {type(result)!r}")
