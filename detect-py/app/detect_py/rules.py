"""Rule engine: loads shared/rules.json once at startup and scores text.

Single rule source for Dart (offline) and Python per TECHNOLOGY.md §2.
Deterministic, pure functions only. Negative weights act as benign controls.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

RULES_PATH = Path(__file__).resolve().parents[3] / "shared" / "rules.json"

# Devanagari Unicode ranges (TECHNOLOGY.md §4: detect Hindi vs English by script).
_DEVANAGARI = re.compile(r"[\u0900-\u097F]")


@dataclass
class CompiledRule:
    id: str
    kind: str  # "keyword" | "regex"
    lang: str  # "en" | "hi" | "any"
    weight: float
    values: list[str] = field(default_factory=list)
    pattern: re.Pattern[str] | None = None


@dataclass
class RuleEngine:
    thresholds: dict[str, float]
    hinglish_keywords: list[str]
    rules: list[CompiledRule]

    @classmethod
    def load(cls, path: Path = RULES_PATH) -> "RuleEngine":
        raw = json.loads(path.read_text(encoding="utf-8"))
        rules: list[CompiledRule] = []
        for r in raw["rules"]:
            compiled = re.compile(r["pattern"], re.IGNORECASE) if r["type"] == "regex" else None
            rules.append(
                CompiledRule(
                    id=r["id"],
                    kind=r["type"],
                    lang=r.get("lang", "any"),
                    weight=float(r["weight"]),
                    values=[v.lower() for v in r.get("values", [])],
                    pattern=compiled,
                )
            )
        return cls(
            thresholds=raw["thresholds"],
            hinglish_keywords=[k.lower() for k in raw.get("hinglish_keywords", [])],
            rules=rules,
        )

    def detect_lang(self, text: str) -> str:
        if _DEVANAGARI.search(text):
            return "hi"
        low = text.lower()
        if any(k in low for k in self.hinglish_keywords):
            return "hinglish"
        return "en" if text.strip() else "unknown"

    def score(self, text: str) -> tuple[float, list[tuple[str, str]], str | None]:
        """Return (rule_score in [0,1], [(signal_type, detail)], scam_type_hint)."""
        low = text.lower()
        total = 0.0
        # Saturation scale: raw weight sum / _SATURATION, capped to [0,1].
        # With weights ~0.2-0.35: 3 medium signals => AMBER, ~5 => RED. Calibrate on eval.
        _SATURATION = 1.5
        signals: list[tuple[str, str]] = []
        hint: str | None = None
        best_weight = 0.0
        for r in self.rules:
            hit = False
            if r.kind == "keyword":
                hit = any(v in low for v in r.values)
            elif r.pattern is not None:
                m = r.pattern.search(text)
                hit = m is not None
            if hit:
                total += r.weight
                signals.append((f"rule:{r.id}", r.id))
                if r.weight > best_weight:
                    best_weight = r.weight
                    hint = r.id if r.weight > 0 else hint
        normalized = max(0.0, min(1.0, total / _SATURATION))
        return normalized, signals, hint

    def label_for(self, score: float) -> str:
        if score >= self.thresholds["red"]:
            return "RED"
        if score >= self.thresholds["amber"]:
            return "AMBER"
        return "GREEN"
