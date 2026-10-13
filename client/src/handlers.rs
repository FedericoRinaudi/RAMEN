use crate::config::{ClientConfig, ServerConfig};
use crate::http_client::HttpClient;
use crate::ipc::{DaemonCommand, DaemonResponse};
use user::bpf::BpfLoader;
use std::sync::{Arc, Mutex};

fn load_config_to_ebpf(
    loader: &mut BpfLoader,
    server: &ServerConfig,
    padding_key: &[u8],
    dummy_key: &[u8],
) -> Result<(), String> {
    let client_ip = server.server_ip.parse::<std::net::IpAddr>()
        .map_err(|_| format!("Invalid IP: {}", server.server_ip))?;
    
    let expiration_timestamp = server.expiration_timestamp() as u64;
    let duration = expiration_timestamp.saturating_sub(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );
    
    let bpf_config = user::models::BpfConfig::new(
        padding_key.to_vec(),
        dummy_key.to_vec(),
        duration,
        client_ip,
        server.service_port,
        server.padding_prob_min,
        server.padding_prob_max,
        server.dummy_prob_min,
        server.dummy_prob_max,
        server.frag_prob_min,
        server.frag_prob_max,
    );

    loader.load_config(&bpf_config)
        .map_err(|e| format!("Error loading into eBPF: {}", e))
}

pub async fn handle_list_command(config_path: &str) -> DaemonResponse {
    match ClientConfig::from_file(config_path) {
        Ok(config) => {
            let servers: Vec<crate::ipc::ServerInfo> = config.servers.iter().map(|s| {
                let expiration = s.last_sent_at + chrono::Duration::seconds(s.duration_seconds as i64);
                crate::ipc::ServerInfo {
                    name: s.name.clone(),
                    server_ip: s.server_ip.clone(),
                    http_port: s.http_port,
                    service_port: s.service_port,
                    endpoint: s.endpoint.clone(),
                    duration_seconds: s.duration_seconds,
                    inserted_at: s.last_sent_at.to_rfc3339(),
                    expires_at: expiration.to_rfc3339(),
                    padding_prob_min: s.padding_prob_min,
                    padding_prob_max: s.padding_prob_max,
                    dummy_prob_min: s.dummy_prob_min,
                    dummy_prob_max: s.dummy_prob_max,
                    frag_prob_min: s.frag_prob_min,
                    frag_prob_max: s.frag_prob_max,
                }
            }).collect();
            
            DaemonResponse::ServerList(servers)
        }
        Err(e) => DaemonResponse::Error(format!("Error loading the configuration: {}", e)),
    }
}

pub async fn handle_add_command(
    config_path: &str,
    mut server: ServerConfig,
    bpf_loader: &Arc<Mutex<BpfLoader>>,
) -> DaemonResponse {
    let mut config = match ClientConfig::from_file(config_path) {
        Ok(c) => c,
        Err(e) => return DaemonResponse::Error(format!("Error loading the configuration: {}", e)),
    };
    
    if config.servers.iter().any(|s| s.name == server.name) {
        return DaemonResponse::Error(format!("Server '{}' already exists", server.name));
    }
    
    let (padding_key, dummy_key) = ServerConfig::generate_keys();
    let (padding_key_hex, dummy_key_hex) = (hex::encode(&padding_key), hex::encode(&dummy_key));
    
    let http_client = HttpClient::new();
    if let Err(e) = http_client.send_config_with_keys(&server, &padding_key_hex, &dummy_key_hex).await {
        return DaemonResponse::Error(format!("Error sending to the server: {}", e));
    }
    
    if let Ok(mut loader) = bpf_loader.lock() {
        let client_ip = match server.server_ip.parse::<std::net::IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return DaemonResponse::Error(format!("Invalid IP: {}", server.server_ip)),
        };
        
        let expiration_timestamp = server.expiration_timestamp() as u64;
        let duration = expiration_timestamp.saturating_sub(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        
        let bpf_config = user::models::BpfConfig::new(
            padding_key.to_vec(),
            dummy_key.to_vec(),
            duration,
            client_ip,
            server.service_port,
            server.padding_prob_min,
            server.padding_prob_max,
            server.dummy_prob_min,
            server.dummy_prob_max,
            server.frag_prob_min,
            server.frag_prob_max,
        );
        
        if let Err(e) = loader.load_config(&bpf_config) {
            return DaemonResponse::Error(format!("Error loading into eBPF: {}", e));
        }
    } else {
        return DaemonResponse::Error("Failed to lock the eBPF loader".to_string());
    }
    
    server.update_last_sent();
    
    config.servers.push(server.clone());
    if let Err(e) = config.save_to_file(config_path) {
        return DaemonResponse::Error(format!("Error saving the configuration: {}", e));
    }
    
    DaemonResponse::Success(format!("Server '{}' added successfully", server.name))
}

pub async fn handle_update_command(
    config_path: &str,
    name: String,
    field: String,
    value: String,
    bpf_loader: &Arc<Mutex<BpfLoader>>,
) -> DaemonResponse {
    let mut config = match ClientConfig::from_file(config_path) {
        Ok(c) => c,
        Err(e) => return DaemonResponse::Error(format!("Error loading the configuration: {}", e)),
    };
    
    let server = match config.servers.iter_mut().find(|s| s.name == name) {
        Some(s) => s,
        None => return DaemonResponse::Error(format!("Server '{}' not found", name)),
    };
    
    let result = match field.as_str() {
        "server_ip" => { server.server_ip = value; Ok(()) }
        "http_port" => value.parse().map(|v| server.http_port = v).map_err(|e| format!("{}", e)),
        "service_port" => value.parse().map(|v| server.service_port = v).map_err(|e| format!("{}", e)),
        "endpoint" => { server.endpoint = value; Ok(()) }
        "duration_seconds" => value.parse().map(|v| server.duration_seconds = v).map_err(|e| format!("{}", e)),
        "padding_prob_min" => value.parse().map(|v| server.padding_prob_min = v).map_err(|e| format!("{}", e)),
        "padding_prob_max" => value.parse().map(|v| server.padding_prob_max = v).map_err(|e| format!("{}", e)),
        "dummy_prob_min"   => value.parse().map(|v| server.dummy_prob_min = v).map_err(|e| format!("{}", e)),
        "dummy_prob_max"   => value.parse().map(|v| server.dummy_prob_max = v).map_err(|e| format!("{}", e)),
        "frag_prob_min"    => value.parse().map(|v| server.frag_prob_min = v).map_err(|e| format!("{}", e)),
        "frag_prob_max"    => value.parse().map(|v| server.frag_prob_max = v).map_err(|e| format!("{}", e)),
        _ => Err(format!("Invalid field '{}'", field)),
    };
    
    if let Err(e) = result {
        return DaemonResponse::Error(e);
    }
    
    let (padding_key, dummy_key) = ServerConfig::generate_keys();
    let (padding_key_hex, dummy_key_hex) = (hex::encode(&padding_key), hex::encode(&dummy_key));
    
    let http_client = HttpClient::new();
    if let Err(e) = http_client.send_config_with_keys(server, &padding_key_hex, &dummy_key_hex).await {
        return DaemonResponse::Error(format!("Error sending to the server: {}", e));
    }
    
    if let Ok(mut loader) = bpf_loader.lock() {
        if let Err(e) = load_config_to_ebpf(&mut loader, server, &padding_key, &dummy_key) {
            return DaemonResponse::Error(e);
        }
    } else {
        return DaemonResponse::Error("Failed to lock the eBPF loader".to_string());
    }
    
    server.update_last_sent();
    
    if let Err(e) = config.save_to_file(config_path) {
        return DaemonResponse::Error(format!("Error saving the configuration: {}", e));
    }
    
    DaemonResponse::Success(format!("Field '{}' updated for server '{}'", field, name))
}

pub async fn handle_update_probs_command(
    config_path: &str,
    name: String,
    padding_prob_min: u8,
    padding_prob_max: u8,
    dummy_prob_min: u8,
    dummy_prob_max: u8,
    frag_prob_min: u8,
    frag_prob_max: u8,
    bpf_loader: &Arc<Mutex<BpfLoader>>,
) -> DaemonResponse {
    let mut config = match ClientConfig::from_file(config_path) {
        Ok(c) => c,
        Err(e) => return DaemonResponse::Error(format!("Error loading the configuration: {}", e)),
    };

    let server = match config.servers.iter_mut().find(|s| s.name == name) {
        Some(s) => s,
        None => return DaemonResponse::Error(format!("Server '{}' not found", name)),
    };

    server.padding_prob_min = padding_prob_min;
    server.padding_prob_max = padding_prob_max;
    server.dummy_prob_min   = dummy_prob_min;
    server.dummy_prob_max   = dummy_prob_max;
    server.frag_prob_min    = frag_prob_min;
    server.frag_prob_max    = frag_prob_max;

    let (padding_key, dummy_key) = ServerConfig::generate_keys();
    let (padding_key_hex, dummy_key_hex) = (hex::encode(&padding_key), hex::encode(&dummy_key));

    let http_client = HttpClient::new();
    if let Err(e) = http_client.send_config_with_keys(server, &padding_key_hex, &dummy_key_hex).await {
        return DaemonResponse::Error(format!("Error sending to the server: {}", e));
    }

    if let Ok(mut loader) = bpf_loader.lock() {
        if let Err(e) = load_config_to_ebpf(&mut loader, server, &padding_key, &dummy_key) {
            return DaemonResponse::Error(e);
        }
    } else {
        return DaemonResponse::Error("Failed to lock the eBPF loader".to_string());
    }

    server.update_last_sent();

    if let Err(e) = config.save_to_file(config_path) {
        return DaemonResponse::Error(format!("Error saving the configuration: {}", e));
    }

    DaemonResponse::Success(format!("Probabilities updated for server '{}'", name))
}

pub async fn handle_renew_command(
    config_path: &str,
    name: String,
    bpf_loader: &Arc<Mutex<BpfLoader>>,
) -> DaemonResponse {
    let mut config = match ClientConfig::from_file(config_path) {
        Ok(c) => c,
        Err(e) => return DaemonResponse::Error(format!("Error loading the configuration: {}", e)),
    };
    
    let server = match config.servers.iter_mut().find(|s| s.name == name) {
        Some(s) => s,
        None => return DaemonResponse::Error(format!("Server '{}' not found", name)),
    };
    
    let (padding_key, dummy_key) = ServerConfig::generate_keys();
    let (padding_key_hex, dummy_key_hex) = (hex::encode(&padding_key), hex::encode(&dummy_key));
    
    let http_client = HttpClient::new();
    if let Err(e) = http_client.send_config_with_keys(server, &padding_key_hex, &dummy_key_hex).await {
        return DaemonResponse::Error(format!("Error sending to the server: {}", e));
    }
    
    if let Ok(mut loader) = bpf_loader.lock() {
        if let Err(e) = load_config_to_ebpf(&mut loader, server, &padding_key, &dummy_key) {
            return DaemonResponse::Error(e);
        }
    } else {
        return DaemonResponse::Error("Failed to lock the eBPF loader".to_string());
    }
    
    server.update_last_sent();
    
    if let Err(e) = config.save_to_file(config_path) {
        return DaemonResponse::Error(format!("Error saving the configuration: {}", e));
    }
    
    DaemonResponse::Success(format!("Keys renewed for server '{}'", name))
}

pub async fn handle_status_command(config_path: &str, uptime_seconds: u64) -> DaemonResponse {
    match ClientConfig::from_file(config_path) {
        Ok(config) => {
            let status = crate::ipc::StatusInfo {
                interface: config.interface,
                check_interval_seconds: config.check_interval_seconds,
                servers_count: config.servers.len(),
                uptime_seconds,
                translation_cleanup_interval_seconds: config.translation_cleanup_interval_seconds,
                cpu_threshold: config.cpu_threshold,
                timestamp_threshold_seconds: config.timestamp_threshold_seconds,
                force_cleanup_every: config.force_cleanup_every,
            };
            DaemonResponse::Status(status)
        }
        Err(e) => DaemonResponse::Error(format!("Error loading the configuration: {}", e)),
    }
}

async fn handle_set_cleanup_params(
    config_path: &str,
    interval: Option<u64>,
    cpu_threshold: Option<f32>,
    timestamp_threshold: Option<u64>,
    force_cleanup_every: Option<u32>,
) -> DaemonResponse {
    let mut config = match ClientConfig::from_file(config_path) {
        Ok(c) => c,
        Err(e) => return DaemonResponse::Error(format!("Error loading the configuration: {}", e)),
    };
    
    let mut changes = Vec::new();
    
    if let Some(val) = interval {
        config.translation_cleanup_interval_seconds = val;
        changes.push(format!("interval: {}s", val));
    }
    
    if let Some(val) = cpu_threshold {
        config.cpu_threshold = val;
        changes.push(format!("CPU threshold: {}%", val));
    }
    
    if let Some(val) = timestamp_threshold {
        config.timestamp_threshold_seconds = val;
        changes.push(format!("timestamp threshold: {}s", val));
    }
    
    if let Some(val) = force_cleanup_every {
        config.force_cleanup_every = val;
        changes.push(format!("forced cleanup every: {} iterations", val));
    }
    
    if changes.is_empty() {
        return DaemonResponse::Error("No parameter to change".to_string());
    }
    
    if let Err(e) = config.save_to_file(config_path) {
        return DaemonResponse::Error(format!("Error saving the configuration: {}", e));
    }
    
    let msg = format!("Cleanup parameters updated (effective after the next restart): {}", changes.join(", "));
    DaemonResponse::Success(msg)
}

pub async fn handle_command(
    command: DaemonCommand,
    config_path: &str,
    bpf_loader: &Arc<Mutex<BpfLoader>>,
    uptime_seconds: u64,
) -> DaemonResponse {
    match command {
        DaemonCommand::List => handle_list_command(config_path).await,
        DaemonCommand::Add(server) => handle_add_command(config_path, server, bpf_loader).await,
        DaemonCommand::Update { name, field, value } => {
            handle_update_command(config_path, name, field, value, bpf_loader).await
        }
        DaemonCommand::UpdateProbs {
            name, padding_prob_min, padding_prob_max,
            dummy_prob_min, dummy_prob_max, frag_prob_min, frag_prob_max
        } => {
            handle_update_probs_command(
                config_path, name,
                padding_prob_min, padding_prob_max,
                dummy_prob_min, dummy_prob_max,
                frag_prob_min, frag_prob_max,
                bpf_loader,
            ).await
        }
        DaemonCommand::Renew { name } => handle_renew_command(config_path, name, bpf_loader).await,
        DaemonCommand::Status => handle_status_command(config_path, uptime_seconds).await,
        DaemonCommand::SetCleanupParams { interval, cpu_threshold, timestamp_threshold, force_cleanup_every } => {
            handle_set_cleanup_params(config_path, interval, cpu_threshold, timestamp_threshold, force_cleanup_every).await
        }
        DaemonCommand::Shutdown => {
            DaemonResponse::Success("Daemon shutting down...".to_string())
        }
    }
}
