#[macro_use]
mod log_macros;

mod config;
mod http_client;
mod cli;
mod ipc;
mod handlers;
mod ipc_server;
mod daemon;

use daemon::Daemon;

const DEFAULT_CONFIG_PATH: &str = "/etc/RAMEN/config.yaml";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    // Se ci sono argomenti, invia il comando al daemon
    if args.len() > 1 {
        return cli::send_command_to_daemon(args).await;
    }
    
    // Usa sempre il percorso di configurazione di default
    let daemon = Daemon::new(DEFAULT_CONFIG_PATH)?;
    daemon.run().await
}

