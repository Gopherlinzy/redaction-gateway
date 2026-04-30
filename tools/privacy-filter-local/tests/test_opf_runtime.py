from types import SimpleNamespace
from unittest.mock import patch

from detectors.opf_runtime import detect_with_runtime


def test_detect_with_runtime_normalizes_private_email_object_spans() -> None:
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
