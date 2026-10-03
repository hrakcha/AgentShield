"""AgentShield FastAPI application.

Analyzed request bodies are untrusted data. The service never executes them,
never follows embedded instructions, and never returns environment secrets.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from models.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
    InboxAnalyzeRequest,
    InboxAnalyzeResponse,
    Indicator,
    DemoStats,
    LiveStats,
    LogEvent,
    StatsResponse,
)
from security.classifier import gemini_is_configured, get_classifier
from security.heuristic import inspect_text, sanitize_preview
from security.risk_engine import (
    decide_action,
    fuse_risk,
    fused_classification,
    risk_level,
    score_indicators,
)

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = FastAPI(
    title="AgentShield",
    description="Runtime security gateway for autonomous AI agents (MVP).",
    version="0.1.0",
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

_stats_lock = threading.Lock()
_live = {
    "requests_scanned": 0,
    "threats_blocked": 0,
    "high_critical_threats": 0,
    "current_risk_level": "LOW",
    "recent_classifications": {},
}
_recent_log: deque[dict] = deque(maxlen=40)

DEMO_CATEGORY_COUNTS = {
    "Prompt Injection": 18,
    "Obfuscated Instruction": 7,
    "Data Exfiltration Attempt": 9,
    "Social Engineering": 11,
    "Benign": 42,
}

NOTES = (
    "Scores reflect detected indicators of a potential threat. "
    "This is not a guarantee of maliciousness or safety."
)


def _hit_to_indicator(hit) -> Indicator:
    return Indicator(
        type=hit.type,
        description=hit.description,
        severity=hit.severity,  # type: ignore[arg-type]
        evidence=hit.evidence,
    )


def _obf_to_indicator(item) -> Indicator:
    return Indicator(
        type=item.type,
        description=item.description,
        severity=item.severity,  # type: ignore[arg-type]
        evidence=item.evidence,
    )


def run_analysis(text: str) -> AnalyzeResponse:
    started = time.perf_counter()
    inspection = inspect_text(text)
    indicators = [_hit_to_indicator(h) for h in inspection["hits"]]
    obfuscation = [_obf_to_indicator(o) for o in inspection["obfuscation"]]

    payload = [i.model_dump() for i in indicators] + [o.model_dump() for o in obfuscation]
    heuristic_score = score_indicators(payload)

    classifier = get_classifier()
    heuristic_types = [i.type for i in indicators] + [o.type for o in obfuscation]
    semantic = classifier.classify(text, heuristic_types)
    source = semantic.provider if semantic.provider in {"gemini", "deterministic_fallback"} else "deterministic_fallback"

    score = fuse_risk(
        heuristic_score,
        is_threat=semantic.analysis.is_threat,
        severity=semantic.analysis.severity,
        confidence=semantic.analysis.confidence,
        classifier_source=source,
    )
    level = risk_level(score)
    action = decide_action(level)
    classification = fused_classification(
        payload,
        semantic_category=semantic.analysis.category,
        is_threat=semantic.analysis.is_threat,
        classifier_source=source,
    )

    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    detected = bool(payload) or (
        source == "gemini" and semantic.analysis.is_threat and semantic.analysis.confidence >= 0.55
    )

    result = AnalyzeResponse(
        detected=detected,
        risk_score=score,
        risk_level=level,  # type: ignore[arg-type]
        classification=classification,
        action=action,  # type: ignore[arg-type]
        indicators=indicators,
        detected_obfuscation=obfuscation,
        sanitized_preview=sanitize_preview(text),
        processing_time_ms=elapsed_ms,
        notes=NOTES,
        classifier_source=source,  # type: ignore[arg-type]
        semantic_confidence=semantic.analysis.confidence,
        semantic_reason=semantic.analysis.reason,
        semantic_analysis=semantic.analysis,
        fallback_reason=semantic.fallback_reason,
    )

    with _stats_lock:
        _live["requests_scanned"] += 1
        _live["current_risk_level"] = level
        if action == "BLOCK":
            _live["threats_blocked"] += 1
        if level in {"HIGH", "CRITICAL"}:
            _live["high_critical_threats"] += 1
        counts = _live["recent_classifications"]
        counts[classification] = counts.get(classification, 0) + 1
        _recent_log.appendleft(
            {
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "type": "obfuscation" if obfuscation and not indicators else "content",
                "risk": score,
                "risk_level": level,
                "classification": classification,
                "action": action,
            }
        )
    return result


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/api/health", response_model=HealthResponse)
async def health():
    classifier = get_classifier()
    provider = getattr(classifier, "__class__", type(classifier)).__name__
    return HealthResponse(
        status="ok",
        service="AgentShield",
        heuristic_engine="operational",
        classifier=provider,
        operational=True,
        gemini_configured=gemini_is_configured(),
    )


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(payload: AnalyzeRequest):
    # Never execute payload.text. Treat exclusively as inspection input.
    return run_analysis(payload.text)


@app.post("/api/inbox/analyze", response_model=InboxAnalyzeResponse)
async def inbox_analyze(payload: InboxAnalyzeRequest):
    combined = f"Subject: {payload.subject}\nFrom: {payload.sender}\n\n{payload.body}"
    result = run_analysis(combined)
    return InboxAnalyzeResponse(
        **result.model_dump(),
        subject=payload.subject,
        sender=payload.sender,
    )


@app.get("/api/stats", response_model=StatsResponse)
async def stats():
    with _stats_lock:
        live = LiveStats(
            requests_scanned=_live["requests_scanned"],
            threats_blocked=_live["threats_blocked"],
            high_critical_threats=_live["high_critical_threats"],
            current_risk_level=_live["current_risk_level"],  # type: ignore[arg-type]
            recent_classifications=dict(_live["recent_classifications"]),
        )
        events = [LogEvent(**item) for item in _recent_log]
    return StatsResponse(
        live=live,
        demo=DemoStats(
            label="demo_sample",
            category_counts=DEMO_CATEGORY_COUNTS,
            note="Chart defaults use sample demo counts. Live counts update after real analyses.",
        ),
        recent_events=events,
    )


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("APP_HOST", "127.0.0.1")
    port = int(os.getenv("APP_PORT", "8000"))
    uvicorn.run("app:app", host=host, port=port, reload=True)
