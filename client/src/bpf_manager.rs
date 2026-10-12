use user::bpf::BpfLoader;
use user::{ClientConfigKey, ClientConfigValue};
use crate::config::ServerConfig;
use std::sync::{Arc, Mutex};

/// Gestore per le operazioni eBPF
pub struct BpfManager {
    loader: Arc<Mutex<BpfLoader>>,
}

impl BpfManager {
    /// Crea un nuovo BpfManager e carica il programma eBPF sull'interfaccia
    pub fn new(interface: &str) -> Result<Self, Box<dyn std::error::Error>> {
        println!("\nCaricamento programma eBPF sull'interfaccia '{}'...", interface);
        let loader = BpfLoader::run(interface)?;
        println!("✓ Programma eBPF caricato con successo\n");
        
        Ok(Self {
            loader: Arc::new(Mutex::new(loader)),
        })
    }
    
    /// Ottiene un clone dell'Arc per condivisione tra thread
    pub fn get_shared(&self) -> Arc<Mutex<BpfLoader>> {
        Arc::clone(&self.loader)
    }
    
    /// Carica la configurazione di un server nella mappa eBPF
    pub fn load_server_config(&self, server: &ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
        let (padding_key, dummy_key) = server.decode_keys()?;
        
        let mut loader = self.loader.lock()
            .map_err(|e| format!("Errore nel lock del loader: {}", e))?;
        
        // Converti IP in u32
        let ip_u32 = server.server_ip.parse::<std::net::Ipv4Addr>()
            .map_err(|_| format!("IP non valido: {}", server.server_ip))?;
        let ip_u32 = u32::from_be_bytes(ip_u32.octets());
        
        let key = ClientConfigKey::new(ip_u32, server.service_port);
        let value = ClientConfigValue::new(
            &padding_key,
            &dummy_key,
            server.expiration_timestamp() as u64,
            server.padding_prob_min,
            server.padding_prob_max,
            server.dummy_prob_min,
            server.dummy_prob_max,
            server.frag_prob_min,
            server.frag_prob_max,
        );
        
        loader.maps().update(
            "client_config_map",
            key.as_bytes(),
            value.as_bytes(),
            libbpf_rs::MapFlags::ANY,
        )?;
        
        Ok(())
    }
    
    /// Rimuove una configurazione dalla mappa eBPF
    pub fn remove_server_config(&self, server_ip: &str, service_port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let mut loader = self.loader.lock()
            .map_err(|e| format!("Errore nel lock del loader: {}", e))?;
        
        let ip_u32 = server_ip.parse::<std::net::Ipv4Addr>()
            .map_err(|_| format!("IP non valido: {}", server_ip))?;
        let ip_u32 = u32::from_be_bytes(ip_u32.octets());
        
        let key = ClientConfigKey::new(ip_u32, service_port);
        loader.maps().delete("client_config_map", key.as_bytes())?;
        
        Ok(())
    }
    
    /// Pulisce le configurazioni scadute dalla mappa eBPF
    pub fn cleanup_expired_configs(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut loader = self.loader.lock()
            .map_err(|e| format!("Errore nel lock del loader: {}", e))?;
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let keys = loader.maps().iter_keys("client_config_map")?;
        
        for key in keys {
            if let Ok(Some(value_bytes)) = loader.maps().lookup("client_config_map", &key) {
                if value_bytes.len() >= 72 {
                    // expiration_time è a offset 64 (dopo le due chiavi da 32 byte)
                    let expiration = u64::from_ne_bytes([
                        value_bytes[64], value_bytes[65], value_bytes[66], value_bytes[67],
                        value_bytes[68], value_bytes[69], value_bytes[70], value_bytes[71],
                    ]);
                    
                    if expiration < now {
                        let _ = loader.maps().delete("client_config_map", &key);
                    }
                }
            }
        }
        
        Ok(())
    }
}
