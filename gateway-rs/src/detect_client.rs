//! Client for detect-py POST /detect. Timeouts + fallback per resilience rules.
use std::time::Duration;

use crate::contract::DetectRes;
use crate::error::GatewayError;

pub struct DetectClient {
    http: reqwest::Client,
    url: String,
}

impl DetectClient {
    pub fn new(base: &str) -> Result<Self, GatewayError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|e| GatewayError::Config(e.to_string()))?;
        Ok(Self { http, url: format!("{base}/detect") })
    }

    /// Never logs content. On any failure returns Err -> caller degrades gracefully.
    pub async fn detect(&self, input_type: &str, content: &str) -> Result<DetectRes, GatewayError> {
        let body = serde_json::json!({ "input_type": input_type, "content": content });
        let resp = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| GatewayError::Detect(e.to_sensitive()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(GatewayError::Detect(format!("detect-py status {}", status.as_u16())));
        }
        // Tolerate the placeholder schema shape via serde aliases in DetectRes.
        let res: DetectRes = resp
            .json()
            .await
            .map_err(|e| GatewayError::Detect(format!("bad detect payload: {}", e.type_name())))?;
        Ok(res)
    }
}
