from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Action = Literal["ALLOW", "REVIEW", "BLOCK"]
Severity = Literal["low", "medium", "high", "critical"]

# Single source of truth for Layer 2 text limits (shared with the Gemini prompt/schema).
CATEGORY_MAX = 80
INTENT_MAX = 80
REASON_MAX = 600


class Indicator(BaseModel):
    type: str
    description: str
    severity: Severity
    evidence: str | None = None


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=12000)

    @field_validator("text")
    @classmethod
    def strip_and_reject_empty(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("text must not be empty")
        return value


class SemanticAnalysis(BaseModel):
    """Validated Layer 2 model output. Arbitrary model text cannot bypass this schema."""

    is_threat: bool
    category: str = Field(min_length=1, max_length=CATEGORY_MAX)
    intent: str = Field(min_length=1, max_length=INTENT_MAX)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    reason: str = Field(min_length=1, max_length=REASON_MAX)

    @field_validator("category", "intent", "reason")
    @classmethod
    def strip_control_chars(cls, value: str) -> str:
        cleaned = "".join(ch for ch in value if ch.isprintable() or ch in "\n\t").strip()
        if not cleaned:
            raise ValueError("field must not be empty")
        return cleaned


class AnalyzeResponse(BaseModel):
    detected: bool
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    classification: str
    action: Action
    indicators: list[Indicator]
    detected_obfuscation: list[Indicator]
    sanitized_preview: str
    processing_time_ms: float
    notes: str
    classifier_source: Literal["gemini", "deterministic_fallback"]
    semantic_confidence: float = Field(ge=0.0, le=1.0)
    semantic_reason: str
    semantic_analysis: SemanticAnalysis
    fallback_reason: str | None = None


class InboxAnalyzeRequest(BaseModel):
    subject: str = Field(default="", max_length=500)
    sender: str = Field(default="", max_length=320)
    body: str = Field(..., min_length=1, max_length=12000)


class InboxAnalyzeResponse(AnalyzeResponse):
    subject: str
    sender: str


class HealthResponse(BaseModel):
    status: str
    service: str
    heuristic_engine: str
    classifier: str
    operational: bool
    gemini_configured: bool


class DemoStats(BaseModel):
    """Sample/demo numbers used only for analytics visualization."""

    label: str = "demo_sample"
    category_counts: dict[str, int]
    note: str


class LiveStats(BaseModel):
    requests_scanned: int
    threats_blocked: int
    high_critical_threats: int
    current_risk_level: RiskLevel
    recent_classifications: dict[str, int]


class LogEvent(BaseModel):
    time: str
    type: str
    risk: int
    risk_level: RiskLevel
    classification: str
    action: Action


class StatsResponse(BaseModel):
    live: LiveStats
    demo: DemoStats
    recent_events: list[LogEvent]
