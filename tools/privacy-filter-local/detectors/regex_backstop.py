import re

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{12,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"hf_[A-Za-z0-9]{16,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._=-]{12,}", re.IGNORECASE),
]


def detect_regex_secret_spans(text: str) -> list[dict[str, object]]:
    spans: list[dict[str, object]] = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            spans.append(
                {
                    "start": match.start(),
                    "end": match.end(),
                    "label": "secret",
                    "source": "regex",
                    "text": match.group(0),
                }
            )
    return spans
