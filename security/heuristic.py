"""Layer 1: deterministic pattern inspection for prompt-injection indicators.

Submitted text is treated strictly as untrusted data. Patterns are matched;
instructions inside the text are never followed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from security.obfuscation import inspect_obfuscation


@dataclass
class HeuristicHit:
    type: str
    description: str
    severity: str
    evidence: str | None = None


# Compiled, case-insensitive phrase/pattern groups.
OVERRIDE_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "instruction_override"),
    (r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions", "instruction_override"),
    (r"forget\s+(your\s+)?(instructions|rules|guidelines|system prompt)", "instruction_override"),
    (r"override\s+(the\s+)?(system|safety|previous)\s+(prompt|rules|instructions)", "instruction_override"),
    (r"do\s+not\s+follow\s+(your\s+)?(original|previous|system)\s+(instructions|rules)", "instruction_override"),
    (r"reset\s+your\s+(instructions|constraints|alignment)", "instruction_override"),
]

ROLE_PATTERNS = [
    (r"you\s+are\s+now\b", "role_manipulation"),
    (r"act\s+as\s+(the\s+)?system\b", "role_manipulation"),
    (r"act\s+as\s+(an?\s+)?unrestricted\b", "role_manipulation"),
    (r"system\s+message", "role_manipulation"),
    (r"developer\s+message", "role_manipulation"),
    (r"new\s+system\s+prompt", "role_manipulation"),
    (r"from\s+now\s+on\s+you\s+are", "role_manipulation"),
    (r"unrestricted\s+administrator", "role_manipulation"),
    (r"jailbreak", "role_manipulation"),
    (r"dan\s+mode", "role_manipulation"),
]

EXFIL_PATTERNS = [
    (r"\bapi[_ -]?keys?\b", "data_exfiltration"),
    (r"\bpasswords?\b", "data_exfiltration"),
    (r"\bcredentials?\b", "data_exfiltration"),
    (r"\b(access|secret|bearer|auth(entication)?)\s+tokens?\b", "data_exfiltration"),
    (r"\benvironment\s+variables?\b", "data_exfiltration"),
    (r"\bsystem\s+prompt\b", "data_exfiltration"),
    (r"\bsecrets?\b", "data_exfiltration"),
    (r"\bcontact\s+lists?\b", "data_exfiltration"),
    (r"export\s+all\s+(api[_ -]?keys?|secrets?|credentials?)", "data_exfiltration"),
    (r"reveal\s+(the\s+)?(system prompt|api[_ -]?key|secrets?)", "data_exfiltration"),
    (r"send\s+.+\s+to\s+[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "data_exfiltration"),
]

SOCIAL_PATTERNS = [
    (r"\burgent\b", "social_engineering"),
    (r"\bimmediately\b", "social_engineering"),
    (r"verify\s+now", "social_engineering"),
    (r"security\s+update", "social_engineering"),
    (r"account\s+suspended", "social_engineering"),
    (r"\bemergency\b", "social_engineering"),
    (r"verify\s+your\s+account", "social_engineering"),
]

DESCRIPTIONS = {
    "instruction_override": "Detected an attempt to override previous / system instructions.",
    "role_manipulation": "Detected an attempt to redefine role or inject privileged system/developer context.",
    "data_exfiltration": "Detected potential intent to extract keys, secrets, prompts, or sensitive data.",
    "social_engineering": "Detected urgency or social-engineering language often used to pressure unsafe actions.",
}

SEVERITY = {
    "instruction_override": "high",
    "role_manipulation": "high",
    "data_exfiltration": "critical",
    "social_engineering": "medium",
}

SANITIZE_REPLACEMENTS = [
    (re.compile(p, re.IGNORECASE), "[removed: instruction-override]")
    for p, kind in OVERRIDE_PATTERNS
    if kind == "instruction_override"
] + [
    (re.compile(p, re.IGNORECASE), "[removed: role-manipulation]")
    for p, _ in ROLE_PATTERNS
]


def _collect_hits(text: str, patterns: list[tuple[str, str]]) -> list[HeuristicHit]:
    hits: list[HeuristicHit] = []
    seen: set[str] = set()
    for pattern, kind in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if not match:
            continue
        key = f"{kind}:{match.group(0).lower()}"
        if key in seen:
            continue
        seen.add(key)
        evidence = match.group(0)
        # Do not persist long user text; keep a short snippet for transparency.
        if len(evidence) > 80:
            evidence = evidence[:80] + "…"
        hits.append(
            HeuristicHit(
                type=kind,
                description=DESCRIPTIONS[kind],
                severity=SEVERITY[kind],
                evidence=evidence,
            )
        )
    return hits


def inspect_text(text: str) -> dict:
    obfuscation, normalized, decoded_payloads = inspect_obfuscation(text)
    corpus = [normalized, *decoded_payloads]

    hits: list[HeuristicHit] = []
    for chunk in corpus:
        hits.extend(_collect_hits(chunk, OVERRIDE_PATTERNS))
        hits.extend(_collect_hits(chunk, ROLE_PATTERNS))
        hits.extend(_collect_hits(chunk, EXFIL_PATTERNS))
        hits.extend(_collect_hits(chunk, SOCIAL_PATTERNS))

    # Deduplicate by type+evidence
    unique: list[HeuristicHit] = []
    seen_keys: set[str] = set()
    for hit in hits:
        key = f"{hit.type}:{hit.evidence}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        unique.append(hit)

    return {
        "hits": unique,
        "obfuscation": obfuscation,
        "normalized": normalized,
        "decoded_payloads": decoded_payloads,
    }


def sanitize_preview(text: str) -> str:
    """Neutralize obvious injection phrases. This is a preview, not a safety guarantee."""
    from security.obfuscation import strip_zero_width

    preview = strip_zero_width(text)
    for regex, replacement in SANITIZE_REPLACEMENTS:
        preview = regex.sub(replacement, preview)
    preview = re.sub(
        r"send\s+.{0,80}\s+to\s+[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
        "[removed: destination-exfil]",
        preview,
        flags=re.IGNORECASE,
    )
    return preview.strip()
