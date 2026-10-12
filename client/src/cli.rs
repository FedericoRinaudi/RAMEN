use crate::config::ServerConfig;
use crate::ipc::{DaemonCommand, DaemonResponse};
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use chrono::Utc;

const SOCKET_PATH: &str = "/tmp/RAMEN_client.sock";

pub async fn send_command_to_daemon(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let command = args.get(1)
        .ok_or("Specificare un comando")?;
    
    match command.as_str() {
        "add" => handle_add(&args[2..]).await,
        "update" => handle_update(&args[2..]).await,
        "update-probs" => handle_update_probs(&args[2..]).await,
        "renew" => handle_renew(&args[2..]).await,
        "list" => handle_list().await,
        "status" => handle_status().await,
        "shutdown" => handle_shutdown().await,
        "set-cleanup" => handle_set_cleanup(&args[2..]).await,
        _ => {
            print_usage();
            Err("Comando non valido".into())
        }
    }
}

async fn send_command(command: DaemonCommand) -> Result<DaemonResponse, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(SOCKET_PATH).await
        .map_err(|_| "Impossibile connettersi al daemon. È in esecuzione?")?;
    
    let command_json = serde_json::to_vec(&command)?;
    stream.write_all(&command_json).await?;
    
    let mut buffer = vec![0u8; 8192];
    let n = stream.read(&mut buffer).await?;
    
    let response: DaemonResponse = serde_json::from_slice(&buffer[..n])?;
    Ok(response)
}

fn print_usage() {
    println!("Uso:");
    println!("  RAMEN-client                                           - Avvia il daemon (config: /etc/RAMEN/config.yaml)");
    println!("  RAMEN-client list                                      - Elenca i server configurati");
    println!("  RAMEN-client status                                    - Mostra lo stato del daemon");
    println!("  RAMEN-client add <name> <ip> <http_port> <service_port> [duration] [endpoint] [pad_min] [pad_max] [dummy_min] [dummy_max] [frag_min] [frag_max]");
    println!("                                                          - Aggiungi un nuovo server");
    println!("  RAMEN-client update <name> <campo> <valore>            - Aggiorna un campo del server");
    println!("  RAMEN-client update-probs <name> <p_min> <p_max> <d_min> <d_max> <f_min> <f_max>");
    println!("                                                          - Aggiorna tutte le probabilità in una sola chiamata");
    println!("  RAMEN-client renew <name>                              - Rigenera le chiavi per un server");
    println!("  RAMEN-client set-cleanup [--interval <sec>] [--cpu <threshold>] [--timestamp <sec>] [--force <n>]");
    println!("                                                          - Modifica parametri di cleanup delle mappe");
    println!("  RAMEN-client shutdown                                  - Arresta il daemon");
    println!();
    println!("Campi aggiornabili:");
    println!("  server_ip, http_port, service_port, endpoint, duration_seconds,");
    println!("  server_ip, http_port, service_port, endpoint, duration_seconds,
  padding_prob_min, padding_prob_max, dummy_prob_min, dummy_prob_max,
  frag_prob_min, frag_prob_max");
}

async fn handle_status() -> Result<(), Box<dyn std::error::Error>> {
    let response = send_command(DaemonCommand::Status).await?;
    
    match response {
        DaemonResponse::Status(status) => {
            println!("=== Stato Daemon ===\n");
            println!("Interfaccia: {}", status.interface);
            println!("Intervallo controllo: {}s", status.check_interval_seconds);
            println!("Server configurati: {}", status.servers_count);
            println!("Uptime: {}s", status.uptime_seconds);
            println!();
            println!("=== Parametri Cleanup Mappe ===\n");
            println!("Intervallo cleanup: {}s", status.translation_cleanup_interval_seconds);
            println!("Soglia CPU: {}%", status.cpu_threshold);
            println!("Threshold timestamp: {}s", status.timestamp_threshold_seconds);
            println!("Cleanup forzato ogni: {} iterazioni", status.force_cleanup_every);
        }
        DaemonResponse::Error(e) => eprintln!("Errore: {}", e),
        _ => eprintln!("Risposta inattesa dal daemon"),
    }
    
    Ok(())
}

async fn handle_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    let response = send_command(DaemonCommand::Shutdown).await?;
    
    match response {
        DaemonResponse::Success(msg) => println!("{}", msg),
        DaemonResponse::Error(e) => eprintln!("Errore: {}", e),
        _ => eprintln!("Risposta inattesa dal daemon"),
    }
    
    Ok(())
}

async fn handle_list() -> Result<(), Box<dyn std::error::Error>> {
    let response = send_command(DaemonCommand::List).await?;
    
    match response {
        DaemonResponse::ServerList(servers) => {
            println!("=== Server Configurati ===\n");
            
            for (i, server) in servers.iter().enumerate() {
                println!("{}. {}", i + 1, server.name);
                println!("   IP: {}", server.server_ip);
                println!("   HTTP Port: {}", server.http_port);
                println!("   Service Port: {}", server.service_port);
                println!("   Endpoint: {}", server.endpoint);
                println!("   Duration: {}s", server.duration_seconds);
                println!("   Padding:  {}%–{}%", server.padding_prob_min, server.padding_prob_max);
                println!("   Dummy:    {}%–{}%", server.dummy_prob_min, server.dummy_prob_max);
                println!("   Frag:     {}%–{}%", server.frag_prob_min, server.frag_prob_max);
                println!("   Ultimo invio: {} (scade: {})", server.inserted_at, server.expires_at);
                println!();
            }
        }
        DaemonResponse::Error(e) => eprintln!("Errore: {}", e),
        _ => eprintln!("Risposta inattesa dal daemon"),
    }
    
    Ok(())
}

async fn handle_add(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() < 4 {
        println!("Uso: RAMEN-client add <name> <ip> <http_port> <service_port> [duration] [endpoint] [pad_min] [pad_max] [dummy_min] [dummy_max] [frag_min] [frag_max]");
        return Err("Argomenti insufficienti".into());
    }
    
    let name = args[0].clone();
    let server_ip = args[1].clone();
    let http_port: u16 = args[2].parse()?;
    let service_port: u16 = args[3].parse()?;
    let duration_seconds: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(86400);
    let endpoint = args.get(5).map(|s| s.clone()).unwrap_or_else(|| "/config".to_string());
    let padding_prob_min: u8 = args.get(6).and_then(|s| s.parse().ok()).unwrap_or(0);
    let padding_prob_max: u8 = args.get(7).and_then(|s| s.parse().ok()).unwrap_or(100);
    let dummy_prob_min: u8 = args.get(8).and_then(|s| s.parse().ok()).unwrap_or(0);
    let dummy_prob_max: u8 = args.get(9).and_then(|s| s.parse().ok()).unwrap_or(100);
    let frag_prob_min: u8 = args.get(10).and_then(|s| s.parse().ok()).unwrap_or(0);
    let frag_prob_max: u8 = args.get(11).and_then(|s| s.parse().ok()).unwrap_or(100);

    let new_server = ServerConfig {
        name: name.clone(),
        server_ip,
        http_port,
        service_port,
        endpoint,
        last_sent_at: Utc::now(),
        duration_seconds,
        padding_prob_min,
        padding_prob_max,
        dummy_prob_min,
        dummy_prob_max,
        frag_prob_min,
        frag_prob_max,
    };
    
    println!("Aggiunta del server '{}'...", name);
    
    let response = send_command(DaemonCommand::Add(new_server)).await?;
    
    match response {
        DaemonResponse::Success(msg) => println!("✓ {}", msg),
        DaemonResponse::Error(e) => eprintln!("✗ Errore: {}", e),
        _ => eprintln!("Risposta inattesa dal daemon"),
    }
    
    Ok(())
}

async fn handle_update_probs(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() < 7 {
        println!("Uso: RAMEN-client update-probs <name> <p_min> <p_max> <d_min> <d_max> <f_min> <f_max>");
        return Err("Argomenti insufficienti".into());
    }

    let name                = args[0].clone();
    let padding_prob_min: u8 = args[1].parse()?;
    let padding_prob_max: u8 = args[2].parse()?;
    let dummy_prob_min: u8   = args[3].parse()?;
    let dummy_prob_max: u8   = args[4].parse()?;
    let frag_prob_min: u8    = args[5].parse()?;
    let frag_prob_max: u8    = args[6].parse()?;

    let response = send_command(crate::ipc::DaemonCommand::UpdateProbs {
        name,
        padding_prob_min, padding_prob_max,
        dummy_prob_min, dummy_prob_max,
        frag_prob_min, frag_prob_max,
    }).await?;

    match response {
        crate::ipc::DaemonResponse::Success(msg) => println!("✓ {}", msg),
        crate::ipc::DaemonResponse::Error(e) => eprintln!("✗ Errore: {}", e),
        _ => eprintln!("Risposta inattesa dal daemon"),
    }

    Ok(())
}

async fn handle_update(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() < 3 {
        println!("Uso: RAMEN-client update <name> <campo> <valore>");
        return Err("Argomenti insufficienti".into());
    }
    
    let name = args[0].clone();
    let field = args[1].clone();
    let value = args[2].clone();
    
    println!("Aggiornamento del server '{}'...", name);
    
    let response = send_command(DaemonCommand::Update { name, field: field.clone(), value }).await?;
    
    match response {
        DaemonResponse::Success(msg) => println!("✓ {}", msg),
        DaemonResponse::Error(e) => eprintln!("✗ Errore: {}", e),
        _ => eprintln!("Risposta inattesa dal daemon"),
    }
    
    Ok(())
}

async fn handle_renew(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        println!("Uso: RAMEN-client renew <name>");
        return Err("Specificare il nome del server".into());
    }
    
    let name = args[0].clone();
    
    println!("Rigenerazione chiavi per il server '{}'...", name);
    
    let response = send_command(DaemonCommand::Renew { name }).await?;
    
    match response {
        DaemonResponse::Success(msg) => println!("✓ {}", msg),
        DaemonResponse::Error(e) => eprintln!("✗ Errore: {}", e),
        _ => eprintln!("Risposta inattesa dal daemon"),
    }
    
    Ok(())
}

async fn handle_set_cleanup(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        println!("Uso: RAMEN-client set-cleanup [--interval <sec>] [--cpu <threshold>] [--timestamp <sec>] [--force <n>]");
        println!();
        println!("Esempi:");
        println!("  RAMEN-client set-cleanup --interval 10");
        println!("  RAMEN-client set-cleanup --cpu 10.0 --timestamp 120");
        println!("  RAMEN-client set-cleanup --force 30");
        return Err("Specificare almeno un parametro".into());
    }
    
    let mut interval = None;
    let mut cpu_threshold = None;
    let mut timestamp_threshold = None;
    let mut force_cleanup_every = None;
    
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--interval" => {
                i += 1;
                if i < args.len() {
                    interval = Some(args[i].parse()?);
                }
            }
            "--cpu" => {
                i += 1;
                if i < args.len() {
                    cpu_threshold = Some(args[i].parse()?);
                }
            }
            "--timestamp" => {
                i += 1;
                if i < args.len() {
                    timestamp_threshold = Some(args[i].parse()?);
                }
            }
            "--force" => {
                i += 1;
                if i < args.len() {
                    force_cleanup_every = Some(args[i].parse()?);
                }
            }
            _ => return Err(format!("Parametro sconosciuto: {}", args[i]).into()),
        }
        i += 1;
    }
    
    println!("Aggiornamento parametri di cleanup...");
    
    let response = send_command(DaemonCommand::SetCleanupParams {
        interval,
        cpu_threshold,
        timestamp_threshold,
        force_cleanup_every,
    }).await?;
    
    match response {
        DaemonResponse::Success(msg) => println!("✓ {}", msg),
        DaemonResponse::Error(e) => eprintln!("✗ Errore: {}", e),
        _ => eprintln!("Risposta inattesa dal daemon"),
    }
    
    Ok(())
}
