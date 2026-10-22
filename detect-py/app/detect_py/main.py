"""FastAPI app for detect-py. Internal only; no LLM, no secrets (TECHNOLOGY.md §2, §4).

Run (dev): uvicorn detect_py.main:app --port 8001  (from detect-py/, with PYTHONPATH=app)
"""

import logging
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import FastAPI

from . import ml
from .models import DetectRequest, DetectResponse, Signal
from .rdap import domain_age_days
from .rules import RuleEngine
from .url_features import extract_urls, url_signals

log = logging.getLogger("detect-py")
# Never log message content (TECHNOLOGY.md §3 rule applies repo-wide).


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.rules = RuleEngine.load()
    app.state.ml = ml.load_if_present()
    if app.state.ml is None:
        log.warning("ML model file missing; /detect will return ml_score=null")
    yield


app = FastAPI(title="scam-shield-detect-py", lifespan=lifespan, docs_url=None, redoc_url=None)

_YOUNG_DOMAIN_DAYS = 30


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "ml_loaded": getattr(app.state, "ml", None) is not None}


@app.post("/detect", response_model=DetectResponse)
async def detect(req: DetectRequest) -> DetectResponse:
    rules: RuleEngine = app.state.rules
    text = req.text or ""
    lang = rules.detect_lang(text)
    rule_score, raw_signals, hint = rules.score(text)
    signals = [Signal(type=t, detail=d) for t, d in raw_signals]
    signals.extend(Signal(type=t, detail=d) for t, d in url_signals(text))

    ml_score: float | None = None
    if app.state.ml is not None and text.strip():
        try:
            ml_score = ml.predict_score(app.state.ml, text)
        except Exception:  # model failure must not fail the request
            signals.append(Signal(type="ml_error", detail="prediction failed"))
    elif app.state.ml is None:
        signals.append(Signal(type="ml_missing", detail="model file absent"))

    # RDAP domain age: best-effort, never fails the request (§4).
    for url in extract_urls(text)[:3]:
        host = (urlparse(url).hostname or "").lower()
        if host.count(".") >= 1:
            domain = ".".join(host.rsplit(".", 2)[-2:])
            age = await domain_age_days(domain)
            if age is None:
                signals.append(Signal(type="rdap_fail", detail=domain))
            elif age < _YOUNG_DOMAIN_DAYS:
                signals.append(Signal(type="domain_young", detail=f"{domain}: {age}d"))

    combined = max(rule_score, ml_score or 0.0)
    label = rules.label_for(combined)
    return DetectResponse(
        ml_score=ml_score,
        rule_score=rule_score,
        label=label,
        lang=lang,
        scam_type_hint=hint,
        signals=signals,
    )
