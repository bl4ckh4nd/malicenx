//! Types shared by the store, the engines and the HTTP API (see docs/api.md).

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub mime: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Threat,
    Clean,
    Pending,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Av,
    Intel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResultStatus {
    Running,
    Ok,
    Error,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResultVerdict {
    Threat,
    Clean,
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub engine: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub id: String,
    pub file: FileInfo,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub status: &'static str,
    pub verdict: Verdict,
    pub engines_expected: usize,
    pub engines_reported: usize,
    pub detections: Vec<Detection>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineResult {
    pub engine: String,
    pub category: Category,
    pub status: ResultStatus,
    pub verdict: Option<ResultVerdict>,
    pub signature: Option<String>,
    pub duration_ms: Option<u64>,
    pub error: Option<String>,
    pub data: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ScanDetail {
    #[serde(flatten)]
    pub summary: ScanSummary,
    pub results: Vec<EngineResult>,
}

#[derive(Debug, Serialize)]
pub struct Stats {
    pub scans_total: u64,
    pub scans_24h: u64,
    pub threats_24h: u64,
    pub running: u64,
    pub avg_duration_ms: Option<u64>,
}
