def build_decide_payload(text: str, source: str = "symphony_prompt") -> dict[str, str]:
    return {
        "text": text,
        "source": source,
        "target": "ai_model",
        "mode": "block",
    }
