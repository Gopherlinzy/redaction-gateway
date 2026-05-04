from types import SimpleNamespace
from unittest.mock import Mock, patch

from detectors.opf_runtime import clear_runtime_cache, detect_with_runtime, get_runtime_cache_stats


def test_detect_with_runtime_normalizes_private_email_object_spans() -> None:
    clear_runtime_cache()
    fake_result = SimpleNamespace(
        detected_spans=(
            SimpleNamespace(
                label="private_email",
                start=6,
                end=23,
                text="=user@example.com",
                placeholder="<PRIVATE_EMAIL>",
            ),
        )
    )

    with patch("detectors.opf_runtime.get_redactor", return_value=SimpleNamespace(redact=lambda _text: fake_result)):
        spans = detect_with_runtime("邮箱 =user@example.com")

    assert spans == [
        {
            "label": "private_email",
            "start": 7,
            "end": 23,
            "text": "user@example.com",
            "placeholder": "<PRIVATE_EMAIL>",
            "source": "opf",
        }
    ]


def test_detect_with_runtime_supports_redaction_result_dicts() -> None:
    clear_runtime_cache()
    fake_result = {
        "detected_spans": [
            {
                "label": "private_email",
                "start": 6,
                "end": 23,
                "text": "=user@example.com",
                "placeholder": "<PRIVATE_EMAIL>",
            }
        ]
    }

    with patch("detectors.opf_runtime.get_redactor", return_value=SimpleNamespace(redact=lambda _text: fake_result)):
        spans = detect_with_runtime("邮箱 =user@example.com")

    assert spans == [
        {
            "label": "private_email",
            "start": 7,
            "end": 23,
            "text": "user@example.com",
            "placeholder": "<PRIVATE_EMAIL>",
            "source": "opf",
        }
    ]


def test_detect_with_runtime_caches_identical_text_results() -> None:
    clear_runtime_cache()
    fake_result = SimpleNamespace(
        detected_spans=(
            SimpleNamespace(
                label="private_email",
                start=6,
                end=22,
                text="user@example.com",
                placeholder="<PRIVATE_EMAIL>",
            ),
        )
    )
    redact = Mock(return_value=fake_result)

    with patch(
        "detectors.opf_runtime.get_redactor",
        return_value=SimpleNamespace(redact=redact),
    ):
        first = detect_with_runtime("email user@example.com")
        first[0]["label"] = "mutated"
        second = detect_with_runtime("email user@example.com")

    assert redact.call_count == 1
    assert second == [
        {
            "label": "private_email",
            "start": 6,
            "end": 22,
            "text": "user@example.com",
            "placeholder": "<PRIVATE_EMAIL>",
            "source": "opf",
        }
    ]
    assert get_runtime_cache_stats()["hits"] == 1
    assert get_runtime_cache_stats()["misses"] == 1
