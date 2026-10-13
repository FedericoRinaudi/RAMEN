use crate::config::ClientConfig;
use crate::http_client::HttpClient;
use crate::ipc_server::IpcServer;
use user::bpf::BpfLoader;
use user::{BpfState, start_translation_cleanup_task};
use tokio::time::{sleep, Duration};
use std::sync::{Arc, Mutex};
use tokio::signal;

pub struct Daemon {
    config_path: String,
    config: ClientConfig,
    http_client: HttpClient,
    bpf_loader: Arc<Mutex<BpfLoader>>,
}

impl Daemon {
    pub fn new(config_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        log_info!("RAMEN Client Daemon\n");
        log_debug!("Loading configuration from: {}", config_path);
        
        let config = ClientConfig::from_file(config_path)?;
        log_info!("Configuration loaded: {} servers configured", config.servers.len());
        
        log_info!("\nLoading eBPF program on interface '{}'...", config.interface);
        let loader = BpfLoader::run(&config.interface)?;
        log_info!("eBPF program loaded successfully\n");
        let bpf_loader = Arc::new(Mutex::new(loader));
        
        let http_client = HttpClient::new();
        
        Ok(Self {
            config_path: config_path.to_string(),
            config,
            http_client,
            bpf_loader,
        })
    }
    
    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.load_initial_configs().await;
        
        let bpf_state = Arc::new(BpfState {
            loader: Arc::clone(&self.bpf_loader),
        });
        let timestamp_threshold_ns = self.config.timestamp_threshold_seconds * 1_000_000_000;
        start_translation_cleanup_task(
            bpf_state,
            self.config.translation_cleanup_interval_seconds,
            self.config.cpu_threshold,
            timestamp_threshold_ns,
            self.config.force_cleanup_every,
        );
        log_debug!("Translation map cleanup task started");
        log_debug!("  - Interval: {} seconds", self.config.translation_cleanup_interval_seconds);
        log_debug!("  - CPU threshold: {}%", self.config.cpu_threshold);
        log_debug!("  - Timestamp threshold: {} seconds", self.config.timestamp_threshold_seconds);
        log_debug!("  - Forced cleanup every: {} iterations\n", self.config.force_cleanup_every);
        
        let ipc_server = IpcServer::new(self.config_path.clone(), Arc::clone(&self.bpf_loader));
        tokio::spawn(async move {
            if let Err(e) = ipc_server.run().await {
                eprintln!("IPC server error: {}", e);
            }
        });
        
        // Wait a moment to make sure the IPC socket has been created
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        tokio::select! {
            result = self.main_loop() => result,
            _ = signal::ctrl_c() => {
                log_info!("\n\nReceived SIGINT (Ctrl+C), cleaning up...");
                self.cleanup();
                Ok(())
            }
            _ = Self::wait_for_sigterm() => {
                log_info!("\n\nReceived SIGTERM, cleaning up...");
                self.cleanup();
                Ok(())
            }
        }
    }
    
    async fn main_loop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            log_debug!("Checking configurations");
            
            self.reload_config();
            
            let config_changed = self.check_and_update_servers().await;
            
            if config_changed {
                self.save_config();
            }
            
            if let Ok(mut loader) = self.bpf_loader.lock() {
                match loader.cleanup_expired_configs() {
                    Ok(count) if count > 0 => {
                        log_debug!("Removed {} expired configurations from the eBPF map", count);
                    }
                    Err(e) => {
                        log_error!("\nError cleaning up expired configurations: {}", e);
                    }
                    _ => {}
                }
            }
            
            log_debug!("\nWaiting {} seconds before the next check\n", 
                     self.config.check_interval_seconds);
            sleep(Duration::from_secs(self.config.check_interval_seconds)).await;
        }
    }
    
    fn reload_config(&mut self) {
        match ClientConfig::from_file(&self.config_path) {
            Ok(new_config) => {
                self.config = new_config;
                log_debug!("Configuration reloaded from file");
            }
            Err(e) => {
                log_error!("Error reloading the configuration: {}", e);
                log_error!("  Continuing with the previous configuration");
            }
        }
    }
    
    async fn check_and_update_servers(&mut self) -> bool {
        let mut config_changed = false;
        
        // Clone bpf_loader to avoid borrow issues with the mutable loop
        let bpf_loader = Arc::clone(&self.bpf_loader);
        
        for server in &mut self.config.servers {
            log_debug!("\nServer: {}", server.name);
            log_debug!("  Endpoint: http://{}:{}{}", server.server_ip, server.http_port, server.endpoint);
            log_debug!("  Service Port: {}", server.service_port);
            log_debug!("  Last sent: {} (expires: {})", server.last_sent_at,
                server.last_sent_at + chrono::Duration::seconds(server.duration_seconds as i64));
            
            if server.needs_renewal() {
                log_info!("  Server '{}': keys expired, renewing...", server.name);
                
                let (padding_key, dummy_key) = crate::config::ServerConfig::generate_keys();
                let (padding_key_hex, dummy_key_hex) = (hex::encode(&padding_key), hex::encode(&dummy_key));
                
                match self.http_client.send_config_with_keys(
                    server, 
                    &padding_key_hex, 
                    &dummy_key_hex
                ).await {
                    Ok(_) => {
                        log_debug!("  Configuration sent to the HTTP server");
                        
                        if let Err(e) = Self::load_server_to_ebpf_with_keys(&bpf_loader, server, &padding_key, &dummy_key) {
                            log_error!("  Error loading into eBPF: {}", e);
                        } else {
                            server.update_last_sent();
                            config_changed = true;
                            
                            log_info!("  Server '{}': configuration renewed successfully", server.name);
                            log_debug!("  Expires: {}",
                                server.last_sent_at + chrono::Duration::seconds(server.duration_seconds as i64));
                        }
                    }
                    Err(e) => {
                        log_error!("  Error sending to server '{}': {}", server.name, e);
                    }
                }
            } else {
                log_debug!("  Keys still valid");
            }
        }
        
        config_changed
    }
    
    fn load_server_to_ebpf_with_keys(
        bpf_loader: &Arc<Mutex<BpfLoader>>, 
        server: &crate::config::ServerConfig,
        padding_key: &[u8],
        dummy_key: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let mut loader = bpf_loader.lock().map_err(|e| format!("Lock error: {}", e))?;
        
        let client_ip = match server.server_ip.parse::<std::net::IpAddr>() {
            Ok(ip) => ip,
            Err(e) => return Err(format!("Invalid IP '{}': {}", server.server_ip, e).into()),
        };
        
        // Use duration_seconds from the config directly instead of deriving it
        // from last_sent_at, which may be stale
        let duration = server.duration_seconds;
        
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
        
        loader.load_config(&bpf_config)?;
        
        Ok(())
    }
    
    async fn load_initial_configs(&mut self) {
        log_info!("\nLoading initial configurations into eBPF...");
        let mut loaded = 0;
        let mut renewed = 0;
        
        for server in &mut self.config.servers {
            log_debug!("  {}: sending configuration...", server.name);
            
            let (padding_key, dummy_key) = crate::config::ServerConfig::generate_keys();
            let (padding_key_hex, dummy_key_hex) = (hex::encode(&padding_key), hex::encode(&dummy_key));
            
            match self.http_client.send_config_with_keys(server, &padding_key_hex, &dummy_key_hex).await {
                Ok(_) => {
                    match Self::load_server_to_ebpf_with_keys(&self.bpf_loader, server, &padding_key, &dummy_key) {
                        Ok(_) => {
                            server.update_last_sent();
                            
                            if server.needs_renewal() {
                                log_info!("  {}: configuration renewed and loaded", server.name);
                                renewed += 1;
                            } else {
                                log_debug!("  {}: configuration sent and loaded", server.name);
                                loaded += 1;
                            }
                        }
                        Err(e) => {
                            log_error!("  {}: error loading into eBPF: {}", server.name, e);
                        }
                    }
                }
                Err(e) => {
                    log_error!("  {}: error sending to the HTTP server: {}", server.name, e);
                }
            }
        }
        
        log_info!("\nLoaded {} valid configurations, {} renewed", loaded, renewed);
        
        if renewed > 0 {
            self.save_config();
        }
    }
    
    fn save_config(&self) {
        if let Err(e) = self.config.save_to_file(&self.config_path) {
            log_error!("\nError saving the configuration: {}", e);
        } else {
            log_debug!("\nConfiguration saved to file");
        }
    }
    
    #[cfg(unix)]
    async fn wait_for_sigterm() {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to setup SIGTERM handler");
        sigterm.recv().await;
    }
    
    #[cfg(not(unix))]
    async fn wait_for_sigterm() {
        std::future::pending::<()>().await;
    }
    
    fn cleanup(&self) {
        log_info!("Detaching and removing the eBPF program...");
        
        // Release the lock and force the BpfLoader to be dropped
        // BpfLoader's Drop implementation detaches the TC programs automatically
        drop(self.bpf_loader.lock());
        
        log_info!("eBPF program detached and removed");
        log_info!("Daemon stopped");
    }
}
