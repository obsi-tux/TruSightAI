"""Tests for detect-py (pytest + httpx TestClient per TECHNOLOGY.md §4)."""

import json

import pytest
from detect_py.main import app
from detect_py.rules import RuleEngine
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def rules():
    return RuleEngine.load()


def _schema_valid(payload: dict) -> bool:
    """Validate against contracts/detect.schema.json if jsonschema is installed."""
    try:
        import jsonschema
    except ImportError:
        pytest.skip("jsonschema not installed")
    from pathlib import Path

    schema_path = Path(__file__).resolve().parents[2] / "contracts" / "detect.schema.json"
    schema = json.loads(schema_path.read_text())
    jsonschema.validate(payload, schema)
    return True


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_detect_benign_green(client):
    r = client.post("/detect", json={"text": "Your OTP is 123456. Do not share it with anyone."})
    assert r.status_code == 200
    body = r.json()
    assert body["label"] == "GREEN"
    _schema_valid(body)


def test_detect_loan_scam_amber_or_red(client):
    text = (
        "Dear customer your loan approved! Immediately pay processing fee to release money, "
        "transfer now, do not tell anyone, install AnyDesk for quick help."
    )
    r = client.post("/detect", json={"text": text})
    body = r.json()
    assert body["label"] in ("AMBER", "RED")
    assert body["rule_score"] > 0.4


def test_detect_hindi_script(client):
    r = client.post("/detect", json={"text": "तुरंत पैसे भेजो नहीं तो खाता बंद हो जाएगा"})
    body = r.json()
    assert body["lang"] == "hi"


def test_detect_hinglish(client):
    text = "Apna account verify karo turant reply karo otp mang rahe hain"
    r = client.post("/detect", json={"text": text})
    body = r.json()
    assert body["lang"] == "hinglish"


def test_ml_missing_signal_when_no_model(client):
    if app.state.ml is None:
        r = client.post("/detect", json={"text": "hello there"})
        types = [s["type"] for s in r.json()["signals"]]
        assert "ml_missing" in types


def test_url_signals(client):
    r = client.post("/detect", json={"text": "Click http://192.168.1.1/login and http://bit.ly/x9"})
    types = [s["type"] for s in r.json()["signals"]]
    assert "ip_host" in types and "url_shortener" in types


def test_rules_negative_weight_caps_at_zero(rules):
    score, _, _ = rules.score("Congratulations you won a prize, never share your OTP with anyone")
    assert 0.0 <= score <= 1.0


def test_empty_text_ok(client):
    r = client.post("/detect", json={"text": ""})
    assert r.status_code == 200
    assert r.json()["label"] == "GREEN"
