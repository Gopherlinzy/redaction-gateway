# Legacy fallback detector:
# - still scans whole text
# - still over-matches some assignment structures
# - remains in place as a safety net while the parser-first detector takes over primary secret handling
import re

SECRET_PATTERN_SPECS = [
    {"kind": "api_key", "pattern": re.compile(r"sk-[A-Za-z0-9_-]{12,}")},
    {"kind": "api_key", "pattern": re.compile(r"github_pat_[A-Za-z0-9_]{20,}")},
    {"kind": "api_key", "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9]{12,}")},
    {"kind": "api_key", "pattern": re.compile(r"AKIA[0-9A-Z]{16}")},
    {"kind": "api_key", "pattern": re.compile(r"hf_[A-Za-z0-9]{16,}")},
    {"kind": "bearer", "pattern": re.compile(r"Bearer\s+[A-Za-z0-9._=-]{12,}", re.IGNORECASE)},
    {
        "kind": "jwt",
        "pattern": re.compile(
            r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
    },
    {
        "kind": "session",
        "pattern": re.compile(
            r"(?:Set-Cookie:\s*)?(?:sessionid|session|connect\.sid|sid)=[^;\s]{8,}",
            re.IGNORECASE,
        ),
    },
    {
        "kind": "db_connection",
        "pattern": re.compile(
            r"\b(?:postgres|postgresql|mysql|mongodb):\/\/[^:\s]+:[^@\s]+@[^\/\s]+\/[^\s]+",
            re.IGNORECASE,
        ),
    },
    {
        "kind": "webhook_secret",
        "pattern": re.compile(
            r"\b(?:webhook_secret|signing_secret|client_secret|app_secret)\s*[:=]\s*[A-Za-z0-9._-]{8,}",
            re.IGNORECASE,
        ),
    },
    {
        "kind": "token",
        "pattern": re.compile(
            r"\b(?:token|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*[A-Za-z0-9._-]{10,}",
            re.IGNORECASE,
        ),
    },
]

MODE_CONFIG = {
    "high_recall": {"include_generic_labels": True},
    "balanced": {"include_generic_labels": True},
    "high_precision": {"include_generic_labels": False},
}

SPAN_METADATA = {
    "api_key": {"score": 0.9, "reason_codes": ["regex_pattern_match"]},
    "bearer": {"score": 0.8, "reason_codes": ["regex_pattern_match"]},
    "jwt": {"score": 0.9, "reason_codes": ["regex_pattern_match"]},
    "session": {"score": 0.8, "reason_codes": ["regex_pattern_match"]},
    "db_connection": {"score": 0.9, "reason_codes": ["regex_pattern_match"]},
    "webhook_secret": {"score": 0.9, "reason_codes": ["regex_pattern_match"]},
    "token": {"score": 0.75, "reason_codes": ["regex_pattern_match"]},
    "verification_code": {"score": 0.65, "reason_codes": ["regex_pattern_match", "context_match"]},
}

CONTEXTUAL_SECRET_SPECS = {
    "high_recall": [
        (
            "verification_code",
            re.compile(
                r"(?:动态口令|初始动态口令|一次性口令|一次性密码|验证码|校验码|短信码|OTP|MFA code|verification code|passcode|code)"
                r"\s*(?:is|are|for|为|是|=)?\s*(?::|：)?\s*([A-Za-z0-9-]{4,10})",
                re.IGNORECASE,
            ),
            1,
        ),
    ],
    "balanced": [
        (
            "verification_code",
            re.compile(
                r"(?:动态口令|初始动态口令|一次性口令|一次性密码|验证码|校验码|短信码|OTP|MFA code|verification code|passcode)"
                r"\s*(?:is|are|for|为|是|=)?\s*(?::|：)?\s*([A-Za-z0-9-]{4,10})",
                re.IGNORECASE,
            ),
            1,
        ),
    ],
    "high_precision": [],
}


def build_secret_span(match: re.Match[str], kind: str, group: int = 0) -> dict[str, object]:
    metadata = SPAN_METADATA[kind]
    return {
        "start": match.start(group),
        "end": match.end(group),
        "label": "secret",
        "kind": kind,
        "source": "regex",
        "score": metadata["score"],
        "reason_codes": metadata["reason_codes"],
        "text": match.group(group),
    }


def normalize_detection_mode(detection_mode: str) -> str:
    return detection_mode if detection_mode in MODE_CONFIG else "balanced"


def detect_regex_secret_spans(text: str, detection_mode: str = "balanced") -> list[dict[str, object]]:
    mode = normalize_detection_mode(detection_mode)

    spans: list[dict[str, object]] = []
    for spec in SECRET_PATTERN_SPECS:
        if spec["kind"] == "token" and not MODE_CONFIG[mode]["include_generic_labels"]:
            continue
        for match in spec["pattern"].finditer(text):
            spans.append(build_secret_span(match, spec["kind"]))

    for kind, pattern, group in CONTEXTUAL_SECRET_SPECS[mode]:
        for match in pattern.finditer(text):
            spans.append(build_secret_span(match, kind, group))

    return spans
