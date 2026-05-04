def build_redact_payload(text: str, source: str = "linear_comment") -> dict[str, str]:
    return {
        "text": text,
        "source": source,
        "target": "linear",
        "mode": "redact",
    }
