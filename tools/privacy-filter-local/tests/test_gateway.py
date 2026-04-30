from fastapi.testclient import TestClient
from unittest.mock import patch

from app import app


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


def test_decide_endpoint_blocks_secret_for_ai_model() -> None:
    client = TestClient(app)
    spans = [
        {
            "start": 9,
            "end": 22,
            "label": "secret",
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
            },
        )

    assert response.status_code == 200
    assert response.json()["decision"] == "block"


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


def test_redact_falls_back_to_regex_when_runtime_unavailable() -> None:
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
    assert response.json()["spans"][0]["source"] == "regex"
    assert "<SECRET>" in response.json()["redacted_text"]


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
