"""Transparent 0–100 risk scoring from Layer 1 indicators fused with Layer 2.

This score reflects detected indicators of a potential threat, not proven
maliciousness. Layer 2 never erases strong Layer 1 evidence.
"""

from __future__ import annotations

from typing import Iterable

SEVERITY_POINTS = {
    "low": 12,
    "medium": 22,
    "high": 34,
    "critical": 42,
}

TYPE_BONUS = {
    "instruction_override": 8,
    "role_manipulation": 8,
    "data_exfiltration": 12,
    "zero_width_unicode": 10,
    "suspicious_base64": 10,
    "instruction_delimiter": 10,
    "social_engineering": 4,
}

SEMANTIC_SEVERITY_POINTS = {
    "low": 12,
    "medium": 22,
    "high": 32,
    "critical": 40,
}


def score_indicators(indicators: Iterable[dict]) -> int:
    total = 0
    types_seen: set[str] = set()
    for item in indicators:
        severity = item.get("severity", "low")
        total += SEVERITY_POINTS.get(severity, 10)
        kind = item.get("type", "")
        if kind not in types_seen:
            types_seen.add(kind)
            total += TYPE_BONUS.get(kind, 0)
    return max(0, min(100, total))


def fuse_risk(
    heuristic_score: int,
    *,
    is_threat: bool,
    severity: str,
    confidence: float,
    classifier_source: str,
) -> int:
    """Combine heuristic score with an independent semantic signal.

    Deterministic fallback is derived from the same Layer 1 hits, so it must
    not inflate the score. Gemini can raise risk for subtle attacks but cannot
    lower a high heuristic score.
    """
    base = max(0, min(100, int(heuristic_score)))
    conf = max(0.0, min(1.0, float(confidence)))

    if classifier_source != "gemini":
        return base

    if not is_threat:
        return base

    semantic_pts = int(round(SEMANTIC_SEVERITY_POINTS.get(severity, 16) * conf))

    if base >= 40 and conf >= 0.7:
        fused = base + semantic_pts + 8
    elif base < 30 and conf >= 0.75:
        # Subtle / indirect injections Layer 1 may miss.
        floor = 62 if conf >= 0.9 else 36
        fused = max(base + semantic_pts, floor)
    elif base == 0 and conf < 0.55:
        fused = min(semantic_pts, 24)
    else:
        fused = base + semantic_pts

    return max(0, min(100, fused))


def risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def decide_action(level: str) -> str:
    if level in {"HIGH", "CRITICAL"}:
        return "BLOCK"
    if level == "MEDIUM":
        return "REVIEW"
    return "ALLOW"


def classify_from_indicators(indicators: list[dict], fallback: str) -> str:
    types = {item.get("type") for item in indicators}
    if "instruction_override" in types or "role_manipulation" in types:
        return "Prompt Injection"
    if "data_exfiltration" in types:
        return "Data Exfiltration Attempt"
    if "zero_width_unicode" in types or "suspicious_base64" in types or "instruction_delimiter" in types:
        return "Obfuscated Instruction"
    if "social_engineering" in types:
        return "Social Engineering"
    return fallback


def fused_classification(
    indicators: list[dict],
    *,
    semantic_category: str,
    is_threat: bool,
    classifier_source: str,
) -> str:
    heuristic_label = classify_from_indicators(indicators, "Benign")
    if heuristic_label != "Benign":
        return heuristic_label
    if classifier_source == "gemini" and is_threat:
        return semantic_category
    return semantic_category if semantic_category else heuristic_label
