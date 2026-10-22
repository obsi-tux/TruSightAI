//! Contract types for POST /analyze (frozen) and detect-py POST /detect.
use serde::{Deserialize, Serialize};

pub const SCAM_TYPES: [&str; 10] = [
    "otp_fraud",
    "fake_job",
    "kyc_bank",
    "parcel",
    "investment",
    "lottery",
    "impersonation",
    "phishing_link",
    "vishing",
    "none",
];

#[derive(Debug, Deserialize)]
pub struct AnalyzeReq {
    pub input_type: String,
    pub content: String,
    #[serde(default = "default_lang")]
    pub lang: String,
}

fn default_lang() -> String {
    "en".into()
}

#[derive(Debug, Serialize)]
pub struct Evidence {
    pub signal: String,
    pub detail: String,
    pub weight: f64,
}

#[derive(Debug, Serialize)]
pub struct AnalyzeRes {
    pub label: String,
    pub score: u8,
    pub scam_type: String,
    pub evidence: Vec<Evidence>,
    pub actions: Vec<String>,
    pub explanation: String,
    pub lang: String,
    pub source: String,
}

/// Response of detect-py POST /detect per the frozen contract in this prompt.
/// NOTE: repo file contracts/detect.schema.json describes a DIFFERENT shape
/// (rule_score/ml_score on 0..1, label, signals{type,detail}). Conflict is
/// recorded in docs/CONFLICTS.md; gateway accepts BOTH via field aliases.
#[derive(Debug, Deserialize)]
pub struct DetectSignal {
    #[serde(alias = "type")]
    pub signal: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub weight: f64,
}

#[derive(Debug, Deserialize)]
pub struct DetectRes {
    #[serde(default)]
    pub rule_score: f64,
    #[serde(default)]
    pub url_score: Option<f64>,
    pub ml_score: Option<f64>,
    #[serde(default)]
    pub force_red: bool,
    #[serde(default)]
    pub signals: Vec<DetectSignal>,
}

impl DetectRes {
    /// Normalize scores to 0..100. The placeholder schema uses 0..1 floats;
    /// the frozen contract uses 0..100. Heuristic: values <= 1.0 with no url
    /// field are treated as fractions only when flagged by schema_version —
    /// we instead trust the frozen contract (0..100) and clamp.
    pub fn rule_100(&self) -> f64 {
        self.rule_score.clamp(0.0, 100.0)
    }
    pub fn url_100(&self) -> f64 {
        self.url_score.unwrap_or(0.0).clamp(0.0, 100.0)
    }
    pub fn ml_100(&self) -> Option<f64> {
        self.ml_score.map(|v| v.clamp(0.0, 100.0))
    }
}
