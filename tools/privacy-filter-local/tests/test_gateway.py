from fastapi.testclient import TestClient
from unittest.mock import patch

from app import app, collect_spans


def test_health_endpoint_returns_ok() -> None:
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_uses_runtime_and_returns_spans() -> None:
    client = TestClient(app)

    with patch(
        "app.detect_with_runtime",
        return_value=[
            {
                "start": 0,
                "end": 5,
                "label": "private_email",
                "source": "opf",
                "text": "a@b.c",
            }
        ],
    ):
        response = client.post(
            "/scan",
            json={"text": "a@b.c", "source": "manual_ui", "target": "ai_model", "mode": "warn"},
        )

    assert response.status_code == 200
    assert response.json()["spans"][0]["label"] == "private_email"


def test_decide_endpoint_warns_secret_for_ai_model() -> None:
    client = TestClient(app)
    spans = [
        {
            "start": 9,
            "end": 22,
            "label": "secret",
            "kind": "api_key",
            "source": "regex",
            "text": "sk-testsecret",
        }
    ]

    with patch("app.collect_spans", return_value=spans):
        response = client.post(
            "/decide",
            json={
                "text": "token is sk-testsecret",
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
                "detection_mode": "balanced",
            },
        )

    assert response.status_code == 200
    assert response.json()["decision"] == "warn"
    assert response.json()["risk_level"] == "high"


def test_redact_endpoint_replaces_sensitive_text() -> None:
    client = TestClient(app)
    spans = [
        {
            "start": 7,
            "end": 12,
            "label": "private_email",
            "source": "opf",
            "text": "a@b.c",
        }
    ]

    with patch("app.collect_spans", return_value=spans):
        response = client.post(
            "/redact",
            json={"text": "email: a@b.c", "source": "manual_ui", "target": "ai_model", "mode": "warn"},
        )

    assert response.status_code == 200
    assert "<PRIVATE_EMAIL>" in response.json()["redacted_text"]


def test_collect_spans_prefers_secret_on_overlap() -> None:
    client = TestClient(app)
    spans = [
        {
            "start": 4,
            "end": 20,
            "label": "private_url",
            "source": "opf",
            "text": "https://internal",
        },
        {
            "start": 12,
            "end": 20,
            "label": "secret",
            "source": "regex",
            "text": "internal",
        },
    ]

    with patch("app.detect_with_runtime", return_value=[spans[0]]), patch(
        "app.detect_regex_secret_spans",
        return_value=[spans[1]],
    ):
        response = client.post(
            "/redact",
            json={"text": "see https://internal", "source": "manual_ui", "target": "ai_model", "mode": "warn"},
        )

    assert response.status_code == 200
    assert response.json()["spans"][0]["label"] == "secret"


def test_collect_spans_prefers_parser_value_spans_over_broad_opf_secret() -> None:
    text = (
        "Authorization: Bearer "
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.signaturepart\n"
        "DATABASE_URL=postgres://appuser:supersecret@db.internal:5432/app"
    )

    runtime_spans = [
        {
            "start": 22,
            "end": len(text),
            "label": "secret",
            "source": "opf",
            "text": text[22:],
        }
    ]
    regex_spans = [
        {
            "start": 15,
            "end": 98,
            "label": "secret",
            "kind": "bearer",
            "source": "regex",
            "text": text[15:98],
        },
        {
            "start": 99,
            "end": len(text),
            "label": "secret",
            "kind": "db_connection",
            "source": "regex",
            "text": text[99:],
        },
    ]

    with patch("app.detect_with_runtime", return_value=runtime_spans), patch(
        "app.detect_regex_secret_spans",
        return_value=regex_spans,
    ):
        spans = collect_spans(text, "balanced")

    assert spans == [
        {
            "label": "secret",
            "kind": "jwt",
            "source": "parser_rule",
            "score": 0.9,
            "reason_codes": ["structure_match", "value_shape_match"],
            "start": 22,
            "end": 95,
            "text": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYifQ.signaturepart",
        },
        {
            "label": "secret",
            "kind": "db_connection",
            "source": "parser_rule",
            "score": 0.9,
            "reason_codes": ["structure_match", "value_shape_match"],
            "start": 109,
            "end": 160,
            "text": "postgres://appuser:supersecret@db.internal:5432/app",
        },
    ]


def test_root_serves_manual_ui() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert "Privacy Filter Local" in response.text
    assert "textarea" in response.text
    assert "Copy Redacted Text" in response.text
    assert "Detections" in response.text


def test_redact_response_contains_decision_metadata() -> None:
    client = TestClient(app)

    with patch("app.collect_spans", return_value=[]):
        response = client.post(
            "/redact",
            json={"text": "hello", "source": "manual_ui", "target": "local_review", "mode": "warn"},
        )

    assert response.status_code == 200
    assert "decision" in response.json()
    assert "risk_level" in response.json()


def test_redact_uses_parser_candidates_when_runtime_unavailable() -> None:
    client = TestClient(app)

    with patch("app.detect_with_runtime", side_effect=RuntimeError("checkpoint incomplete")):
        response = client.post(
            "/redact",
            json={
                "text": "token=sk-testsecretvalue1234567890",
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
            },
        )

    assert response.status_code == 200
    assert response.json()["spans"] == [
        {
            "label": "secret",
            "kind": "api_key",
            "source": "parser_rule",
            "score": 0.9,
            "reason_codes": ["structure_match", "value_shape_match"],
            "start": 6,
            "end": 34,
            "text": "sk-testsecretvalue1234567890",
        }
    ]
    assert response.json()["redacted_text"] == "token=<SECRET>"


def test_redact_endpoint_forwards_detection_mode_to_secret_backstop() -> None:
    client = TestClient(app)

    with patch("app.detect_with_runtime", return_value=[]), patch(
        "app.detect_regex_secret_spans",
        return_value=[],
    ) as regex_detector:
        response = client.post(
            "/redact",
            json={
                "text": "token=demo",
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
                "detection_mode": "high_recall",
            },
        )

    assert response.status_code == 200
    regex_detector.assert_called_once_with("token=demo", "high_recall")


def test_redact_preserves_assignment_keys_and_only_replaces_values() -> None:
    client = TestClient(app)

    response = client.post(
        "/redact",
        json={
            "text": "\n".join(
                [
                    "OPENAI_API_KEY=sk-testsecretvalue1234567890",
                    "token = vx_api_token_1234567890abcdef",
                    "access_token = demo_access_token_abcdef1234567890",
                    "refresh_token=refresh_demo_token_abcdef1234567890",
                ]
            ),
            "source": "manual_ui",
            "target": "ai_model",
            "mode": "warn",
            "detection_mode": "balanced",
        },
    )

    assert response.status_code == 200
    assert response.json()["redacted_text"] == "\n".join(
        [
            "OPENAI_API_KEY=<SECRET>",
            "token = <SECRET>",
            "access_token = <SECRET>",
            "refresh_token=<SECRET>",
        ]
    )


def test_root_ui_includes_status_feedback_and_copy_fallback() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'id="statusMessage"' in response.text
    assert 'response.ok' in response.text
    assert 'document.execCommand("copy")' in response.text


def test_root_ui_includes_industrial_console_sections() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'class="app-shell"' in response.text
    assert 'id="inputPanel"' in response.text
    assert 'id="riskPanel"' in response.text
    assert 'id="nextStepPanel"' in response.text
    assert 'id="replacementMapping"' in response.text
    assert "Input Buffer" in response.text
    assert "Recommended Next Step" in response.text
    assert "Replacement Mapping" in response.text


def test_root_ui_includes_score_and_reason_debug_fields() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert "score" in response.text
    assert "reason_codes" in response.text
    assert "source" in response.text


def test_collect_spans_prefers_parser_value_span_for_token_assignment() -> None:
    text = "token = vx_api_token_1234567890abcdef"

    spans = collect_spans(text, "balanced")

    assert spans == [
        {
            "label": "secret",
            "kind": "token",
            "source": "parser_rule",
            "score": 0.75,
            "reason_codes": ["structure_match", "key_name_match", "value_shape_match"],
            "start": 8,
            "end": len(text),
            "text": "vx_api_token_1234567890abcdef",
        }
    ]


def test_root_ui_includes_explanation_first_helpers() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert "function buildRecommendationMessage" in response.text
    assert "function renderReplacementMapping" in response.text
    assert "Detected secret. Replace it before sending externally." in response.text
    assert "Detected private email. Redact it if the text will leave local review." in response.text
    assert "红线 = 原文里将被替换掉的敏感内容" in response.text
    assert "绿线 = 脱敏后保留下来的安全占位符" in response.text


def test_root_ui_includes_detection_mode_selector() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'id="detectionMode"' in response.text
    assert "High Recall" in response.text
    assert "Balanced" in response.text
    assert "High Precision" in response.text
    assert 'id="modeDescription"' in response.text


def test_root_ui_posts_detection_mode_and_renders_secret_first_sections() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'detection_mode: detectionMode.value' in response.text
    assert 'id="primaryRiskList"' in response.text
    assert 'id="secondarySignalsList"' in response.text
    assert "Detected bearer credential. Replace it before sending externally." in response.text
    assert "Secondary Signals" in response.text


def test_root_ui_supports_file_protocol_api_base() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'const API_BASE = window.location.protocol === "file:" ? "http://127.0.0.1:7861" : "";' in response.text
    assert 'fetch(`${API_BASE}/redact`' in response.text


def test_cors_preflight_allows_file_protocol_requests() -> None:
    client = TestClient(app)

    response = client.options(
        "/redact",
        headers={
            "Origin": "null",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "*"


def test_redact_endpoint_returns_secret_first_output_with_secondary_pii() -> None:
    client = TestClient(app)
    spans = [
        {
            "start": 0,
            "end": 29,
            "label": "secret",
            "kind": "verification_code",
            "source": "regex",
            "text": "verification code is 246810",
        },
        {
            "start": 37,
            "end": 53,
            "label": "private_email",
            "source": "opf",
            "text": "user@example.com",
        },
    ]

    with patch("app.collect_spans", return_value=spans):
        response = client.post(
            "/redact",
            json={
                "text": "verification code is 246810 email user@example.com",
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
                "detection_mode": "balanced",
            },
        )

    assert response.status_code == 200
    assert response.json()["decision"] == "warn"
    assert response.json()["risk_level"] == "high"
    assert response.json()["spans"][0]["label"] == "secret"
    assert "<SECRET>" in response.json()["redacted_text"]
    assert "<PRIVATE_EMAIL>" in response.json()["redacted_text"]
