//! Typed errors. anyhow is used only in main.rs (per TECHNOLOGY.md).
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("config error: {0}")]
    Config(String),
    #[error("detect-py unavailable: {0}")]
    Detect(String),
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// Helper so we never leak a URL-with-content or raw body into logs/errors.
pub trait ToSensitive {
    fn to_sensitive(&self) -> String;
}

impl ToSensitive for reqwest::Error {
    fn to_sensitive(&self) -> String {
        if self.is_timeout() {
            "timeout".to_string()
        } else if self.is_connect() {
            "connect failed".to_string()
        } else {
            "request failed".to_string()
        }
    }
}
