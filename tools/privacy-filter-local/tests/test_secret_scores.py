from detectors.secret_scores import filter_candidates_for_mode


def test_high_recall_accepts_context_only_short_code() -> None:
    candidate = {
        "label": "secret",
        "kind": "verification_code",
        "source": "parser_rule",
        "score": 0.65,
        "reason_codes": ["structure_match", "context_match"],
        "start": 21,
        "end": 27,
        "text": "128841",
    }
    accepted = filter_candidates_for_mode([candidate], "high_recall")
    assert accepted == [candidate]


def test_high_precision_rejects_context_only_short_code() -> None:
    candidate = {
        "label": "secret",
        "kind": "verification_code",
        "source": "parser_rule",
        "score": 0.65,
        "reason_codes": ["structure_match", "context_match"],
        "start": 21,
        "end": 27,
        "text": "128841",
    }
    accepted = filter_candidates_for_mode([candidate], "high_precision")
    assert accepted == []


def test_balanced_accepts_strong_assignment_secret() -> None:
    candidate = {
        "label": "secret",
        "kind": "token",
        "source": "parser_rule",
        "score": 0.75,
        "reason_codes": ["structure_match", "key_name_match", "value_shape_match"],
        "start": 15,
        "end": 49,
        "text": "demo_access_token_abcdef1234567890",
    }
    accepted = filter_candidates_for_mode([candidate], "balanced")
    assert accepted == [candidate]


def test_unknown_mode_falls_back_to_balanced_behavior() -> None:
    candidate = {
        "label": "secret",
        "kind": "token",
        "source": "parser_rule",
        "score": 0.7,
        "reason_codes": ["structure_match", "key_name_match", "value_shape_match"],
        "start": 15,
        "end": 49,
        "text": "demo_access_token_abcdef1234567890",
    }
    accepted = filter_candidates_for_mode([candidate], "mystery_mode")
    assert accepted == [candidate]


def test_exact_threshold_score_is_accepted() -> None:
    candidate = {
        "label": "secret",
        "kind": "token",
        "source": "parser_rule",
        "score": 0.8,
        "reason_codes": ["structure_match", "key_name_match", "value_shape_match"],
        "start": 15,
        "end": 49,
        "text": "demo_access_token_abcdef1234567890",
    }
    accepted = filter_candidates_for_mode([candidate], "high_precision")
    assert accepted == [candidate]
