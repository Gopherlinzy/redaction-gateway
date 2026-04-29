SECRET_LABELS = {"secret"}
REDACT_LABELS = {"private_email", "private_phone", "account_number"}
SOFT_LABELS = {"private_url", "private_address", "private_person", "private_date"}
VALID_FALLBACK_MODES = {"warn", "redact"}


def decide_action(
    spans: list[dict[str, object]],
    source: str,
    target: str,
    mode: str,
) -> dict[str, str]:
    del source

    labels = {str(span["label"]) for span in spans}
    if SECRET_LABELS & labels and target in {"ai_model", "linear"}:
        return {"decision": "block", "risk_level": "high", "reason": "secret detected"}
    if REDACT_LABELS & labels:
        return {"decision": "redact", "risk_level": "medium", "reason": "sensitive pii"}
    if SOFT_LABELS & labels and target == "local_review":
        return {
            "decision": "warn",
            "risk_level": "low",
            "reason": "review before sharing",
        }
    if SOFT_LABELS & labels:
        return {"decision": "redact", "risk_level": "medium", "reason": "external target"}
    return {
        "decision": mode if mode in VALID_FALLBACK_MODES else "allow",
        "risk_level": "low",
        "reason": "no match",
    }
