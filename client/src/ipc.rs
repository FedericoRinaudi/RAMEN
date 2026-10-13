use serde::{Deserialize, Serialize};
use crate::config::ServerConfig;

#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonCommand {
    List,
    Add(ServerConfig),
    Update { name: String, field: String, value: String },
    UpdateProbs {
        name: String,
        padding_prob_min: u8,
        padding_prob_max: u8,
        dummy_prob_min: u8,
        dummy_prob_max: u8,
        frag_prob_min: u8,
        frag_prob_max: u8,
    },
    Renew { name: String },
    Status,
    Shutdown,
    SetCleanupParams {
        interval: Option<u64>,
        cpu_threshold: Option<f32>,
        timestamp_threshold: Option<u64>,
        force_cleanup_every: Option<u32>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonResponse {
    Success(String),
    Error(String),
    ServerList(Vec<ServerInfo>),
    Status(StatusInfo),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub server_ip: String,
    pub http_port: u16,
    pub service_port: u16,
    pub endpoint: String,
    pub duration_seconds: u64,
    pub inserted_at: String,
    pub expires_at: String,
    pub padding_prob_min: u8,
    pub padding_prob_max: u8,
    pub dummy_prob_min: u8,
    pub dummy_prob_max: u8,
    pub frag_prob_min: u8,
    pub frag_prob_max: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusInfo {
    pub interface: String,
    pub check_interval_seconds: u64,
    pub servers_count: usize,
    pub uptime_seconds: u64,
    pub translation_cleanup_interval_seconds: u64,
    pub cpu_threshold: f32,
    pub timestamp_threshold_seconds: u64,
    pub force_cleanup_every: u32,
}
