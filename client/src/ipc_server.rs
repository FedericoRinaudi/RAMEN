use crate::handlers;
use crate::ipc::{DaemonCommand, DaemonResponse};
use user::bpf::BpfLoader;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;
use std::sync::{Arc, Mutex};
use std::path::Path;

const SOCKET_PATH: &str = "/tmp/RAMEN_client.sock";

/// Server IPC per ricevere comandi dal CLI
pub struct IpcServer {
    config_path: String,
    bpf_loader: Arc<Mutex<BpfLoader>>,
    start_time: Instant,
}

impl IpcServer {
    pub fn new(config_path: String, bpf_loader: Arc<Mutex<BpfLoader>>) -> Self {
        Self {
            config_path,
            bpf_loader,
            start_time: Instant::now(),
        }
    }
    
    /// Avvia il server IPC in ascolto sul socket Unix
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        // Rimuovi il socket se esiste già
        if Path::new(SOCKET_PATH).exists() {
            std::fs::remove_file(SOCKET_PATH)?;
        }
        
        let listener = UnixListener::bind(SOCKET_PATH)?;
        log_debug!("Server IPC in ascolto su {}", SOCKET_PATH);
        
        let server = Arc::new(self);
        
        loop {
            let (stream, _) = listener.accept().await?;
            let server_clone = Arc::clone(&server);
            
            tokio::spawn(async move {
                if let Err(e) = server_clone.handle_connection(stream).await {
                    log_error!("Errore nella gestione connessione IPC: {}", e);
                }
            });
        }
    }
    
    /// Gestisce una singola connessione IPC
    async fn handle_connection(&self, mut stream: UnixStream) -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = vec![0u8; 8192];
        let n = stream.read(&mut buffer).await?;
        
        let command: DaemonCommand = serde_json::from_slice(&buffer[..n])?;
        
        // Gestisci il comando di shutdown separatamente
        if matches!(command, DaemonCommand::Shutdown) {
            let response = DaemonResponse::Success("Daemon in chiusura...".to_string());
            let response_json = serde_json::to_vec(&response)?;
            stream.write_all(&response_json).await?;
            std::process::exit(0);
        }
        
        // Gestisci gli altri comandi
        let uptime_seconds = self.start_time.elapsed().as_secs();
        let response = handlers::handle_command(
            command,
            &self.config_path,
            &self.bpf_loader,
            uptime_seconds,
        ).await;
        
        let response_json = serde_json::to_vec(&response)?;
        stream.write_all(&response_json).await?;
        
        Ok(())
    }
}
