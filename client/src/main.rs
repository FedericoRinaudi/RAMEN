#[macro_use]
extern crate user;

mod config;
mod http_client;
mod cli;
mod ipc;
mod handlers;
mod ipc_server;
mod daemon;

use daemon::Daemon;

const DEFAULT_CONFIG_PATH: &str = "/etc/ramen/config.yaml";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() > 1 {
        return cli::send_command_to_daemon(args).await;
    }
    
    let daemon = Daemon::new(DEFAULT_CONFIG_PATH)?;
    daemon.run().await
}

