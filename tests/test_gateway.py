import os
from fastapi.testclient import TestClient
from unittest.mock import patch

import app as app_module
from app import app, collect_spans, get_request_metrics_snapshot, prewarm_runtime, _record_request_timing, _filter_opf_url_false_positives


def test_health_endpoint_returns_ok() -> None:
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ready_endpoint_returns_runtime_snapshot() -> None:
    client = TestClient(app)

    with patch(
        "app.get_runtime_status_snapshot",
        return_value={"status": "ready", "runtime_ready": True, "prewarm_succeeded": True},
    ):
        response = client.get("/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["runtime_ready"] is True


def test_ready_endpoint_returns_503_until_runtime_is_ready() -> None:
    client = TestClient(app)

    with patch(
        "app.get_runtime_status_snapshot",
        return_value={"status": "warming", "runtime_ready": False, "prewarm_succeeded": False},
    ):
        response = client.get("/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "warming"


def test_stats_endpoint_returns_runtime_cache_and_request_metrics() -> None:
    client = TestClient(app)

    with patch(
        "app.get_runtime_status_snapshot",
        return_value={"status": "ready", "runtime_ready": True},
    ), patch(
        "app.get_runtime_cache_stats",
        return_value={"entries": 1, "hits": 2, "misses": 1},
    ), patch(
        "app.get_request_metrics_snapshot",
        return_value={"total_requests": 3, "recent_count": 3},
    ):
        response = client.get("/stats")

    assert response.status_code == 200
    assert response.json()["runtime"]["status"] == "ready"
    assert response.json()["cache"]["hits"] == 2
    assert response.json()["requests"]["total_requests"] == 3


def test_request_metrics_snapshot_groups_timing_by_endpoint_and_length_bucket() -> None:
    app_module._request_timings.clear()
    app_module._request_count = 0
    app_module._last_request_timing = None

    _record_request_timing(
        {
            "endpoint": "/redact",
            "text_length": 48,
            "opf_seconds": 0.6,
            "parser_seconds": 0.001,
            "regex_seconds": 0.001,
            "merge_seconds": 0.001,
            "total_seconds": 0.603,
            "span_count": 2,
            "detection_mode": "balanced",
        }
    )
    _record_request_timing(
        {
            "endpoint": "/redact",
            "text_length": 1200,
            "opf_seconds": 1.2,
            "parser_seconds": 0.002,
            "regex_seconds": 0.002,
            "merge_seconds": 0.001,
            "total_seconds": 1.205,
            "span_count": 3,
            "detection_mode": "balanced",
        }
    )

    snapshot = get_request_metrics_snapshot()

    assert snapshot["buckets"]["/redact"]["0-255"]["count"] == 1
    assert snapshot["buckets"]["/redact"]["1024-4095"]["count"] == 1


def test_request_metrics_snapshot_groups_timing_by_hit_type_bucket() -> None:
    app_module._request_timings.clear()
    app_module._request_count = 0
    app_module._last_request_timing = None

    _record_request_timing(
        {
            "endpoint": "/redact",
            "text_length": 48,
            "opf_seconds": 0.6,
            "parser_seconds": 0.001,
            "regex_seconds": 0.001,
            "merge_seconds": 0.001,
            "total_seconds": 0.603,
            "span_count": 2,
            "secret_count": 2,
            "pii_count": 0,
            "detection_mode": "balanced",
        }
    )
    _record_request_timing(
        {
            "endpoint": "/redact",
            "text_length": 128,
            "opf_seconds": 0.8,
            "parser_seconds": 0.001,
            "regex_seconds": 0.001,
            "merge_seconds": 0.001,
            "total_seconds": 0.803,
            "span_count": 2,
            "secret_count": 1,
            "pii_count": 1,
            "detection_mode": "balanced",
        }
    )

    snapshot = get_request_metrics_snapshot()

    assert snapshot["hit_type_buckets"]["/redact"]["secret_only"]["count"] == 1
    assert snapshot["hit_type_buckets"]["/redact"]["mixed"]["count"] == 1


def test_prewarm_runtime_calls_detect_when_enabled() -> None:
    with patch.dict(os.environ, {"PRIVACY_FILTER_PREWARM_ON_STARTUP": "1"}, clear=True), patch(
        "app.detect_with_runtime",
        return_value=[],
    ) as detect_runtime:
        assert prewarm_runtime() is True

    detect_runtime.assert_called_once()


def test_prewarm_runtime_skips_during_pytest() -> None:
    with patch.dict(
        os.environ,
        {
            "PRIVACY_FILTER_PREWARM_ON_STARTUP": "1",
            "PYTEST_CURRENT_TEST": "tests/test_gateway.py::test_prewarm_runtime_skips_during_pytest",
        },
        clear=True,
    ), patch("app.detect_with_runtime", return_value=[]) as detect_runtime:
        assert prewarm_runtime() is False

    detect_runtime.assert_not_called()


def test_collect_spans_logs_timing_breakdown_when_enabled() -> None:
    with patch.dict(os.environ, {"PRIVACY_FILTER_TIMING_LOGS": "1"}, clear=True), patch(
        "app.detect_with_runtime",
        return_value=[],
    ), patch(
        "app.generate_secret_candidates",
        return_value=[],
    ), patch(
        "app.filter_candidates_for_mode",
        return_value=[],
    ), patch(
        "app.detect_regex_secret_spans",
        return_value=[],
    ), patch("app.logger.info") as log_info:
        assert collect_spans("hello", "balanced") == []

    log_info.assert_called_once()
    assert "collect_spans timings" in log_info.call_args.args[0]


def test_scan_uses_runtime_and_returns_spans() -> None:
    client = TestClient(app)
    # Text must exceed OPF_SKIP_THRESHOLD (500 chars) so _detect_opf_async calls the runtime
    long_text = "user@example.com " + "x" * 500

    with patch(
        "app.detect_with_runtime",
        return_value=[
            {
                "start": 0,
                "end": 16,
                "label": "private_email",
                "source": "opf",
                "text": "user@example.com",
            }
        ],
    ):
        response = client.post(
            "/scan",
            json={"text": long_text, "source": "manual_ui", "target": "ai_model", "mode": "warn"},
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

    with patch("app.collect_spans", return_value=spans), patch(
        "app.get_last_request_timing",
        return_value={"total_seconds": 0.1},
    ):
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
    assert response.json()["timings"]["total_seconds"] == 0.1


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

    with patch("app.collect_spans", return_value=spans), patch(
        "app.get_last_request_timing",
        return_value={"total_seconds": 0.2},
    ):
        response = client.post(
            "/redact",
            json={"text": "email: a@b.c", "source": "manual_ui", "target": "ai_model", "mode": "warn"},
        )

    assert response.status_code == 200
    assert "<PRIVATE_EMAIL>" in response.json()["redacted_text"]
    assert response.json()["timings"]["total_seconds"] == 0.2


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
            "start": 128,
            "end": 139,
            "text": "supersecret",
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
    assert "Debug Timing And Cache" in response.text


def test_redact_response_contains_decision_metadata() -> None:
    client = TestClient(app)

    with patch("app.collect_spans", return_value=[]), patch(
        "app.get_last_request_timing",
        return_value={"total_seconds": 0.3},
    ):
        response = client.post(
            "/redact",
            json={"text": "hello", "source": "manual_ui", "target": "local_review", "mode": "warn"},
        )

    assert response.status_code == 200
    assert "decision" in response.json()
    assert "risk_level" in response.json()
    assert response.json()["timings"]["total_seconds"] == 0.3


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


def test_redact_masks_mongodb_srv_password_when_runtime_unavailable() -> None:
    client = TestClient(app)
    text = "mongodb+srv://analytics:AnalyTics!Pass@cluster0.abcde.mongodb.net/prod"

    with patch("app.detect_with_runtime", side_effect=RuntimeError("checkpoint incomplete")):
        response = client.post(
            "/redact",
            json={
                "text": text,
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
                "detection_mode": "balanced",
            },
        )

    assert response.status_code == 200
    assert response.json()["redacted_text"] == "mongodb+srv://analytics:<SECRET>@cluster0.abcde.mongodb.net/prod"


def test_redact_masks_private_key_block_as_single_placeholder_when_runtime_unavailable() -> None:
    client = TestClient(app)
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQCqGK7UO5jX4Z...\n-----END RSA PRIVATE KEY-----"

    with patch("app.detect_with_runtime", side_effect=RuntimeError("checkpoint incomplete")):
        response = client.post(
            "/redact",
            json={
                "text": text,
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
                "detection_mode": "balanced",
            },
        )

    assert response.status_code == 200
    assert response.json()["redacted_text"] == "<SECRET>"


def test_redact_masks_full_hf_token_value_when_runtime_unavailable() -> None:
    client = TestClient(app)
    text = "HF_TOKEN = hf_ThisIsATestTokenWithPad_1234567890ABCDEF"

    with patch("app.detect_with_runtime", side_effect=RuntimeError("checkpoint incomplete")):
        response = client.post(
            "/redact",
            json={
                "text": text,
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
                "detection_mode": "balanced",
            },
        )

    assert response.status_code == 200
    assert response.json()["redacted_text"] == "HF_TOKEN = <SECRET>"


def test_redact_preserves_cookie_name_while_masking_refresh_token_value() -> None:
    client = TestClient(app)
    text = "Set-Cookie: refresh_token=7a8s9d0f1g2h3j4k5l6; HttpOnly; Path=/; SameSite=Strict"

    with patch("app.detect_with_runtime", side_effect=RuntimeError("checkpoint incomplete")):
        response = client.post(
            "/redact",
            json={
                "text": text,
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
                "detection_mode": "balanced",
            },
        )

    assert response.status_code == 200
    assert response.json()["redacted_text"] == "Set-Cookie: refresh_token=<SECRET>; HttpOnly; Path=/; SameSite=Strict"


def test_redact_preserves_signing_key_assignment_shape_with_single_placeholder() -> None:
    client = TestClient(app)
    text = 'signing_key = "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADAN...\\n-----END PRIVATE KEY-----"'

    with patch("app.detect_with_runtime", side_effect=RuntimeError("checkpoint incomplete")):
        response = client.post(
            "/redact",
            json={
                "text": text,
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
                "detection_mode": "balanced",
            },
        )

    assert response.status_code == 200
    assert response.json()["redacted_text"] == 'signing_key = "<SECRET>"'


def test_redact_preserves_db_connection_shape_and_masks_only_password() -> None:
    client = TestClient(app)
    text = "DATABASE_URL=postgres://appuser:supersecret@db.internal:5432/app"

    with patch("app.detect_with_runtime", side_effect=RuntimeError("checkpoint incomplete")):
        response = client.post(
            "/redact",
            json={
                "text": text,
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
                "detection_mode": "balanced",
            },
        )

    assert response.status_code == 200
    assert response.json()["redacted_text"] == "DATABASE_URL=postgres://appuser:<SECRET>@db.internal:5432/app"


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
    assert 'id="inputInspector"' in response.text
    assert "Input Buffer" in response.text
    assert "Recommended Next Step" in response.text
    assert "Redacted Review" in response.text


def test_root_ui_replacement_mapping_uses_before_after_layout_and_label_legend() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert "Input Highlight → Redacted" in response.text
    assert "Input Highlight" in response.text
    assert "Redacted" in response.text
    assert "Email" in response.text
    assert "URL" in response.text
    assert "Secret" in response.text


def test_root_ui_uses_clickable_inspector_tabs_with_runtime_visible() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'id="inspectorTabs"' in response.text
    assert 'data-inspector-target="riskPanel"' in response.text
    assert 'data-inspector-target="runtimePanel"' in response.text
    assert "function setActiveInspectorTab" in response.text
    assert '<details id="debugPanel">' not in response.text
    assert 'id="runtimePanel"' in response.text


def test_root_ui_uses_fixed_scrollable_text_surfaces() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert "--surface-height-lg:" in response.text
    assert "--surface-height-md:" in response.text
    assert "resize: none;" in response.text
    assert "overflow: auto;" in response.text
    assert "height: var(--surface-height-lg);" in response.text
    assert "height: var(--surface-height-md);" in response.text


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
    assert "function summarizeSecretKinds" in response.text
    assert "Detected secret. Replace it before sending externally." in response.text
    assert "Detected private email. Redact it if the text will leave local review." in response.text
    assert "左侧显示输入中的命中片段；右侧保留可直接复制的脱敏结果。" in response.text


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


def test_root_ui_includes_file_upload_entry_and_review_metadata() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'id="fileInput"' in response.text
    assert "Upload PDF or DOCX" in response.text
    assert 'id="selectedFileName"' in response.text
    assert 'id="reviewFileMeta"' in response.text
    assert "pdf / docx review" in response.text


def test_root_ui_posts_multipart_form_data_to_redact_file() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'const file = fileInput.files[0];' in response.text
    assert 'new FormData()' in response.text
    assert '.append("file",' in response.text
    assert 'fetch(`${API_BASE}/redact-file`' in response.text


def test_root_ui_includes_download_redacted_file_action() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'id="downloadFileButton"' in response.text
    assert "Download Redacted File" in response.text


def test_root_ui_posts_multipart_form_data_to_redact_file_download() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'fetch(`${API_BASE}/redact-file/download`' in response.text
    assert 'URL.createObjectURL' in response.text
    assert 'link.download = filename;' in response.text


def test_root_ui_includes_stats_panel() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'id="statsPanel"' in response.text
    assert 'statsPiiPct' in response.text
    assert 'statsSpanCount' in response.text
    assert 'renderStats' in response.text


def test_root_ui_includes_category_sidebar() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'id="catSidebar"' in response.text
    assert 'id="catList"' in response.text
    assert 'catSelectAll' in response.text
    assert 'catClearAll' in response.text


def test_root_ui_includes_toggle_cat_function() -> None:
    client = TestClient(app)

    response = client.get("/")

    assert response.status_code == 200
    assert 'function toggleCat(' in response.text
    assert 'data-cat=' in response.text
    assert '.entity.off' in response.text


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


def test_opf_url_false_positive_filter_removes_url_secret_spans() -> None:
    spans = [
        {"label": "secret", "source": "opf", "start": 20, "end": 80,
         "text": "https://docs.example.com/api?api_key=demo&token=example"},
        {"label": "secret", "source": "opf", "start": 0, "end": 15,
         "text": "sk-realkey12345"},
        {"label": "private_email", "source": "opf", "start": 85, "end": 105,
         "text": "https://url-as-pii.com"},
    ]

    result = _filter_opf_url_false_positives(spans)

    texts = [s["text"] for s in result]
    assert "sk-realkey12345" in texts
    assert "https://docs.example.com/api?api_key=demo&token=example" not in texts
    assert "https://url-as-pii.com" in texts


def test_opf_url_secret_not_redacted_via_collect_spans() -> None:
    client = TestClient(app)
    url_secret_span = {
        "label": "secret", "source": "opf", "start": 18, "end": 72,
        "text": "https://docs.example.com/api?api_key=demo&token=example",
        "placeholder": "<SECRET>",
    }

    with patch("app.detect_with_runtime", return_value=[url_secret_span]):
        response = client.post(
            "/redact",
            json={
                "text": 'public_docs_url = "https://docs.example.com/api?api_key=demo&token=example"',
                "source": "manual_ui",
                "target": "ai_model",
                "mode": "warn",
            },
        )

    assert response.status_code == 200
    redacted = response.json()["redacted_text"]
    assert "https://docs.example.com" in redacted
    assert "<SECRET>" not in redacted
