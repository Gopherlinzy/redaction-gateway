# Legacy fallback detector:
# - still scans whole text
# - still over-matches some assignment structures
# - remains in place as a safety net while the parser-first detector takes over primary secret handling
import base64
import json
import math
import re

SECRET_PATTERN_SPECS = [
    # ── API keys (prefix-anchored, low false-positive) ────────────────────
    {"kind": "api_key", "pattern": re.compile(r"sk[-_][A-Za-z0-9_-]{12,}")},
    {"kind": "api_key", "pattern": re.compile(r"github_pat_[A-Za-z0-9_]{20,}")},
    {"kind": "api_key", "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9]{12,}")},
    {"kind": "api_key", "pattern": re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b")},
    {"kind": "api_key", "pattern": re.compile(r"hf_[A-Za-z0-9_-]{16,}")},
    # Slack
    {"kind": "api_key", "pattern": re.compile(r"xoxb-[0-9A-Za-z\-]{50,}")},
    {"kind": "api_key", "pattern": re.compile(r"xoxp-[0-9A-Za-z\-]{71,}")},
    {"kind": "api_key", "pattern": re.compile(r"xoxa-[0-9A-Za-z\-]{50,}")},
    # Stripe webhook signing secret
    {"kind": "api_key", "pattern": re.compile(r"whsec_[0-9a-zA-Z_]{20,}")},
    # SendGrid
    {"kind": "api_key", "pattern": re.compile(r"SG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}")},
    # PyPI upload token
    {"kind": "api_key", "pattern": re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}")},
    # npm auth token
    {"kind": "api_key", "pattern": re.compile(r"npm_[A-Za-z0-9_]{36,}")},
    # GCP / Firebase
    {"kind": "api_key", "pattern": re.compile(r"AIza[A-Za-z0-9\-_]{35,}")},
    # Discord bot token
    {"kind": "api_key", "pattern": re.compile(r"[MN][A-Za-z\d_\-]{23,25}\.[A-Za-z\d_\-]{6,7}\.[A-Za-z\d_\-]{27}")},
    # Mailgun
    {"kind": "api_key", "pattern": re.compile(r"key-[0-9a-z]{32}")},

    # ── Bearer / JWT ──────────────────────────────────────────────────────
    {"kind": "bearer", "pattern": re.compile(r"Bearer\s+([A-Za-z0-9._=-]{12,})", re.IGNORECASE), "group": 1},
    {"kind": "jwt",    "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")},

    # ── OAuth & URL-embedded secrets ─────────────────────────────────────
    # OAuth authorization code (URL query param)
    {
        "kind": "oauth_code",
        "pattern": re.compile(r"[?&]code=([A-Za-z0-9\-_]{20,200})", re.IGNORECASE),
        "group": 1,
    },
    # AWS signed URL — both query-string styles
    {
        "kind": "aws_signature",
        "pattern": re.compile(r"X-Amz-Signature=([a-f0-9]{64})", re.IGNORECASE),
        "group": 1,
    },
    {
        "kind": "aws_signature",
        "pattern": re.compile(r"[?&]Signature=([A-Za-z0-9%+/]{40,})", re.IGNORECASE),
        "group": 1,
    },
    # Slack incoming webhook URL
    {
        "kind": "webhook_url",
        "pattern": re.compile(
            r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/([a-zA-Z0-9_]{24})",
            re.IGNORECASE,
        ),
        "group": 1,
    },

    # ── Session / DB / PEM ───────────────────────────────────────────────
    {
        "kind": "session",
        "pattern": re.compile(
            r"(?:Set-Cookie:\s*)?(?:sessionid|session|connect\.sid|sid)=([^;\s]{8,})",
            re.IGNORECASE,
        ),
        "group": 1,
    },
    {
        "kind": "db_connection",
        "pattern": re.compile(
            r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^:\s]+:([^@\s]+)@[^\/\s]+\/[^\s]+",
            re.IGNORECASE,
        ),
        "group": 1,
    },
    {
        "kind": "private_key",
        "pattern": re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----",
            re.MULTILINE,
        ),
    },

    # ── Named secret assignments ──────────────────────────────────────────
    {
        "kind": "webhook_secret",
        "pattern": re.compile(
            r"\b(?:webhook_secret|signing_secret|client_secret|app_secret)\s*[:=]\s*([A-Za-z0-9._-]{8,})",
            re.IGNORECASE,
        ),
        "group": 1,
    },
    {
        "kind": "token",
        "pattern": re.compile(
            r"\b(?:token|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*([A-Za-z0-9._-]{10,})",
            re.IGNORECASE,
        ),
        "group": 1,
    },
]

MODE_CONFIG = {
    "high_recall": {"include_generic_labels": True},
    "balanced": {"include_generic_labels": True},
    "high_precision": {"include_generic_labels": False},
}

SPAN_METADATA = {
    "api_key":          {"score": 0.9,  "reason_codes": ["regex_pattern_match"]},
    "bearer":           {"score": 0.8,  "reason_codes": ["regex_pattern_match"]},
    "jwt":              {"score": 0.9,  "reason_codes": ["regex_pattern_match"]},
    "session":          {"score": 0.8,  "reason_codes": ["regex_pattern_match"]},
    "db_connection":    {"score": 0.9,  "reason_codes": ["regex_pattern_match"]},
    "private_key":      {"score": 0.95, "reason_codes": ["regex_pattern_match", "pem_block_match"]},
    "webhook_secret":   {"score": 0.9,  "reason_codes": ["regex_pattern_match"]},
    "webhook_url":      {"score": 0.85, "reason_codes": ["regex_pattern_match"]},
    "token":            {"score": 0.75, "reason_codes": ["regex_pattern_match"]},
    "oauth_code":       {"score": 0.8,  "reason_codes": ["regex_pattern_match", "url_param_match"]},
    "aws_signature":    {"score": 0.85, "reason_codes": ["regex_pattern_match", "url_param_match"]},
    "verification_code":{"score": 0.65, "reason_codes": ["regex_pattern_match", "context_match"]},
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


# ── Local validity checks (no API calls) ─────────────────────────────────

def _entropy(s: str) -> float:
    """Shannon entropy. Real secrets typically ≥ 3.5."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _valid_aws_key(key: str) -> bool:
    """AKIA keys use base32 alphabet (A-Z2-7) in positions 4-19."""
    return len(key) == 20 and bool(re.fullmatch(r"[A-Z2-7]{16}", key[4:]))


def _valid_jwt(token: str) -> bool:
    """Verify JWT has a valid base64url-encoded JSON header containing 'alg'."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    h = parts[0]
    pad = 4 - len(h) % 4
    if pad != 4:
        h += "=" * pad
    try:
        return "alg" in json.loads(base64.urlsafe_b64decode(h))
    except Exception:
        return False


_ENTROPY_MIN: dict[str, float] = {
    "api_key":          3.5,
    "bearer":           3.5,
    "jwt":              0.0,   # structure check is sufficient
    "token":            3.2,
    "webhook_secret":   3.2,
    "webhook_url":      0.0,   # full URL pattern is specific enough
    "session":          3.0,
    "db_connection":    2.5,
    "private_key":      0.0,   # PEM block always valid if regex matches
    "oauth_code":       3.0,
    "aws_signature":    3.5,
    "verification_code":0.0,
}


def _is_valid(kind: str, value: str) -> bool:
    """Return False if matched value is likely a placeholder or test string."""
    if kind == "api_key" and value.startswith("AKIA"):
        return _valid_aws_key(value)
    if kind == "jwt":
        return _valid_jwt(value)
    threshold = _ENTROPY_MIN.get(kind, 3.0)
    return threshold == 0.0 or _entropy(value) >= threshold


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


_CN_PII_SPECS = [
    # 中国居民身份证号（18位：6位地区码 + 8位生日 + 3位顺序码 + 1位校验码(数字或X)）
    {
        "kind": "cn_id_number",
        "label": "pii",
        "score": 0.9,
        "pattern": re.compile(r"\b([1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])\b"),
    },
    # 中国护照号（E + 8位数字，或 G/D/S/P/H + 8位数字）
    {
        "kind": "cn_passport",
        "label": "pii",
        "score": 0.85,
        "pattern": re.compile(r"\b([EeGgDdSsPpHh]\d{8})\b"),
    },
    # 中国手机号（1[3-9]xxxxxxxxx）
    {
        "kind": "cn_phone",
        "label": "pii",
        "score": 0.8,
        "pattern": re.compile(r"(?<!\d)(1[3-9]\d{9})(?!\d)"),
    },
    # 电子邮箱
    {
        "kind": "email",
        "label": "pii",
        "score": 0.85,
        "pattern": re.compile(r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})"),
    },
    # 住房公积金账号（结合关键词上下文，10-14位数字）
    {
        "kind": "housing_fund_account",
        "label": "pii",
        "score": 0.85,
        "pattern": re.compile(r"(?:公积金账号|公积金帐号|公积金账户|公积金帐户)\D{0,40}?(\d{10,14})"),
    },
    # 中文姓名（关键词锚：2-6个汉字）
    {
        "kind": "cn_name",
        "label": "pii",
        "score": 0.75,
        "pattern": re.compile(
            r"(?:联系人|收件人|姓名|客户|员工|签署人|申请人|经办人|负责人|开户人)\s*[：:]\s*([^\s，,。、\n]{2,6})",
        ),
    },
    # 中文地址（关键词锚：5-80字符）
    {
        "kind": "cn_address",
        "label": "pii",
        "score": 0.8,
        "pattern": re.compile(
            r"(?:地址|住址|收货地址|通讯地址|居住地|注册地址|办公地址)\s*[：:]\s*([^\n]{5,80})",
        ),
    },
    # 银行卡号（关键词锚 + 13-19位数字）
    {
        "kind": "bank_card",
        "label": "pii",
        "score": 0.85,
        "pattern": re.compile(
            r"(?:银行卡号|账号|卡号|借记卡|信用卡号)\s*[：:]\s*(\d[\d\s\-]{11,22}\d)",
        ),
    },
    # 统一社会信用代码（18位固定格式：数字+大写字母，首位1-9或大写字母）
    {
        "kind": "cn_uscc",
        "label": "pii",
        "score": 0.9,
        "pattern": re.compile(
            r"(?:统一社会信用代码|社会信用代码|信用代码)\s*[：:＊*]?\s*([0-9A-HJ-NP-RT-Y]{18})",
        ),
    },
]


def detect_regex_pii_spans(text: str) -> list[dict[str, object]]:
    spans: list[dict[str, object]] = []
    for spec in _CN_PII_SPECS:
        for match in spec["pattern"].finditer(text):
            spans.append({
                "start": match.start(1),
                "end": match.end(1),
                "label": spec["label"],
                "kind": spec["kind"],
                "source": "regex",
                "score": spec["score"],
                "reason_codes": ["regex_pattern_match"],
                "text": match.group(1),
            })
    return spans


def detect_regex_secret_spans(text: str, detection_mode: str = "balanced") -> list[dict[str, object]]:
    mode = normalize_detection_mode(detection_mode)

    spans: list[dict[str, object]] = []
    for spec in SECRET_PATTERN_SPECS:
        if spec["kind"] == "token" and not MODE_CONFIG[mode]["include_generic_labels"]:
            continue
        grp = int(spec.get("group", 0))
        for match in spec["pattern"].finditer(text):
            value = match.group(grp)
            if not _is_valid(spec["kind"], value):
                continue
            spans.append(build_secret_span(match, spec["kind"], grp))

    for kind, pattern, group in CONTEXTUAL_SECRET_SPECS[mode]:
        for match in pattern.finditer(text):
            spans.append(build_secret_span(match, kind, group))

    return spans
