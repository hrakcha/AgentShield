"""Layer 1 helpers: detect encoded, hidden, or delimiter-wrapped instructions.

Decoded payloads are inspected as text only. They are never executed as code.
"""

from __future__ import annotations

import base64
import re
import string
from dataclasses import dataclass

ZERO_WIDTH_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u2061": "FUNCTION APPLICATION",
    "\u2062": "INVISIBLE TIMES",
    "\u2063": "INVISIBLE SEPARATOR",
    "\u2064": "INVISIBLE PLUS",
}

SUSPICIOUS_DELIMITERS = [
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"\[INST\]",
    r"\[/INST\]",
    r"<<SYS>>",
    r"<</SYS>>",
    r"###\s*System",
    r"###\s*Instruction",
    r"```system",
    r"```developer",
    r"<system>",
    r"</system>",
    r"\[system\]",
    r"\[developer\]",
]

# Long-ish base64-looking tokens (padding optional).
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/])")
HEX_BLOB_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{40,})(?![0-9a-fA-F])")


@dataclass
class ObfuscationFinding:
    type: str
    description: str
    severity: str
    evidence: str | None = None
    decoded_hint: str | None = None


def strip_zero_width(text: str) -> str:
    return "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARS)


def find_zero_width(text: str) -> list[ObfuscationFinding]:
    counts: dict[str, int] = {}
    for ch in text:
        if ch in ZERO_WIDTH_CHARS:
            counts[ch] = counts.get(ch, 0) + 1
    if not counts:
        return []
    names = ", ".join(f"{ZERO_WIDTH_CHARS[ch]} x{n}" for ch, n in counts.items())
    return [
        ObfuscationFinding(
            type="zero_width_unicode",
            description=f"Hidden Unicode characters detected ({names}). These can conceal instructions.",
            severity="high" if sum(counts.values()) >= 3 else "medium",
            evidence="[zero-width characters omitted from evidence]",
        )
    ]


def _looks_like_base64_payload(token: str) -> bool:
    alphabet = set(string.ascii_letters + string.digits + "+/=")
    if any(ch not in alphabet for ch in token):
        return False
    if token.count("=") > 2:
        return False
    # Avoid flagging ordinary English by requiring mixed charset typical of encoding.
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    has_digit = any(c.isdigit() for c in token)
    return (has_upper and has_lower) or (has_digit and (has_upper or has_lower))


def _safe_b64_decode(token: str) -> str | None:
    """Decode candidate Base64 for inspection only — never eval/exec."""
    padded = token + "=" * ((4 - len(token) % 4) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except Exception:
        return None
    if not raw:
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in decoded) / max(len(decoded), 1)
    if printable < 0.85:
        return None
    return decoded


def find_encoded_blobs(text: str) -> tuple[list[ObfuscationFinding], list[str]]:
    findings: list[ObfuscationFinding] = []
    decoded_payloads: list[str] = []
    seen: set[str] = set()

    for match in BASE64_RE.finditer(text):
        token = match.group(1)
        if token in seen or not _looks_like_base64_payload(token):
            continue
        seen.add(token)
        decoded = _safe_b64_decode(token)
        if decoded and len(decoded) >= 8:
            decoded_payloads.append(decoded)
            findings.append(
                ObfuscationFinding(
                    type="suspicious_base64",
                    description="Base64-looking payload decoded to readable text during inspection.",
                    severity="high",
                    evidence=token[:48] + ("…" if len(token) > 48 else ""),
                    decoded_hint=decoded[:200],
                )
            )
        elif len(token) >= 40:
            findings.append(
                ObfuscationFinding(
                    type="suspicious_base64",
                    description="Long Base64-looking string detected; contents could hide instructions.",
                    severity="medium",
                    evidence=token[:48] + ("…" if len(token) > 48 else ""),
                )
            )

    for match in HEX_BLOB_RE.finditer(text):
        blob = match.group(1)
        if blob.lower() in seen:
            continue
        seen.add(blob.lower())
        findings.append(
            ObfuscationFinding(
                type="hex_blob",
                description="Long hexadecimal blob that may be used to hide payload data.",
                severity="low",
                evidence=blob[:48] + ("…" if len(blob) > 48 else ""),
            )
        )
    return findings, decoded_payloads


def find_delimiter_wrappers(text: str) -> list[ObfuscationFinding]:
    findings: list[ObfuscationFinding] = []
    for pattern in SUSPICIOUS_DELIMITERS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            findings.append(
                ObfuscationFinding(
                    type="instruction_delimiter",
                    description="Suspicious prompt-template delimiter that can wrap privileged instructions.",
                    severity="high",
                    evidence=pattern,
                )
            )
    return findings


def inspect_obfuscation(text: str) -> tuple[list[ObfuscationFinding], str, list[str]]:
    normalized = strip_zero_width(text)
    findings: list[ObfuscationFinding] = []
    findings.extend(find_zero_width(text))
    encoded, decoded_payloads = find_encoded_blobs(text)
    findings.extend(encoded)
    findings.extend(find_delimiter_wrappers(text))
    return findings, normalized, decoded_payloads
