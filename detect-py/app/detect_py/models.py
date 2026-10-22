"""Pydantic v2 models for /detect. Mirrors contracts/detect.schema.json."""

from typing import Literal

from pydantic import BaseModel, Field

Label = Literal["RED", "AMBER", "GREEN"]
Lang = Literal["en", "hi", "hinglish", "unknown"]


class Signal(BaseModel):
    type: str = Field(min_length=1, max_length=64)
    detail: str = Field(default="", max_length=200)


class DetectRequest(BaseModel):
    text: str = Field(default="", max_length=20000)
    lang_hint: Lang | None = None


class DetectResponse(BaseModel):
    ml_score: float | None = None
    rule_score: float = 0.0
    label: Label = "GREEN"
    lang: Lang = "unknown"
    scam_type_hint: str | None = None
    signals: list[Signal] = Field(default_factory=list)
