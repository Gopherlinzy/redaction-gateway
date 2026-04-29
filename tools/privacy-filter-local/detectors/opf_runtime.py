import os
from functools import lru_cache


@lru_cache(maxsize=1)
def get_redactor():
    from opf import OPF

    device = os.getenv("PRIVACY_FILTER_DEVICE", "cpu")
    return OPF(device=device, output_mode="typed", output_text_only=False)


def detect_with_runtime(text: str) -> list[dict[str, object]]:
    result = get_redactor().redact(text)
    return list(result.get("detected_spans", []))
