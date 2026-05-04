from detectors.regex_backstop import normalize_detection_mode


MODE_THRESHOLDS = {
    "high_recall": 0.6,
    "balanced": 0.7,
    "high_precision": 0.8,
}


def filter_candidates_for_mode(
    candidates: list[dict[str, object]],
    detection_mode: str,
) -> list[dict[str, object]]:
    mode = normalize_detection_mode(detection_mode)
    threshold = MODE_THRESHOLDS[mode]
    return [candidate for candidate in candidates if _candidate_score(candidate) >= threshold]


def _candidate_score(candidate: dict[str, object]) -> float:
    if "score" not in candidate:
        raise KeyError("candidate is missing required 'score' field")

    score = candidate["score"]
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise TypeError(f"candidate score must be numeric, got {type(score).__name__}")

    return float(score)
