use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Configurazione per un singolo server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Nome del server (per riferimento)
    pub name: String,
    
    /// Indirizzo IP del server
    pub server_ip: String,
    
    /// Porta del servizio HTTP del server (per la richiesta HTTP)
    pub http_port: u16,
    
    /// Porta del servizio WFSafe (da inserire nel body e usare come chiave eBPF)
    pub service_port: u16,
    
    /// URL dell'endpoint per inviare la configurazione
    pub endpoint: String,
    
    /// Timestamp dell'ultimo invio delle chiavi al server
    pub last_sent_at: DateTime<Utc>,
    
    /// Durata delle chiavi in secondi
    pub duration_seconds: u64,
    
    /// Probabilità minima padding (0-100)
    #[serde(default = "default_prob_min")]
    pub padding_prob_min: u8,

    /// Probabilità massima padding (0-100)
    #[serde(default = "default_prob_max")]
    pub padding_prob_max: u8,

    /// Probabilità minima dummy (0-100)
    #[serde(default = "default_prob_min")]
    pub dummy_prob_min: u8,

    /// Probabilità massima dummy (0-100)
    #[serde(default = "default_prob_max")]
    pub dummy_prob_max: u8,

    /// Probabilità minima frammentazione (0-100)
    #[serde(default = "default_prob_min")]
    pub frag_prob_min: u8,

    /// Probabilità massima frammentazione (0-100)
    #[serde(default = "default_prob_max")]
    pub frag_prob_max: u8,
}

fn default_prob_min() -> u8 {
    0
}

fn default_prob_max() -> u8 {
    100
}

impl ServerConfig {
    /// Verifica se le chiavi devono essere rinnovate (scadute o in scadenza entro 1 minuto)
    pub fn needs_renewal(&self) -> bool {
        let now = Utc::now();
        let expiration = self.last_sent_at + chrono::Duration::seconds(self.duration_seconds as i64);
        let expiration_with_buffer = expiration - chrono::Duration::seconds(60);
        now >= expiration_with_buffer
    }
    
    /// Calcola il timestamp di scadenza basato su quando sono state inviate le chiavi
    pub fn expiration_timestamp(&self) -> i64 {
        (self.last_sent_at + chrono::Duration::seconds(self.duration_seconds as i64)).timestamp()
    }
    
    /// Aggiorna il timestamp di invio al tempo corrente
    pub fn update_last_sent(&mut self) {
        self.last_sent_at = Utc::now();
    }
    
    /// Genera nuove chiavi casuali (non salvate nella configurazione)
    /// Ritorna (padding_key_bytes, dummy_key_bytes)
    pub fn generate_keys() -> (Vec<u8>, Vec<u8>) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        // Genera 32 byte casuali per padding_key
        let padding_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        
        // Genera 32 byte casuali per dummy_key
        let dummy_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        
        (padding_bytes, dummy_bytes)
    }
    
}

/// Configurazione completa del client con tutti i server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Interfaccia di rete su cui caricare eBPF
    pub interface: String,
    
    /// Intervallo di controllo in secondi
    #[serde(default = "default_check_interval")]
    pub check_interval_seconds: u64,
    
    /// Intervallo di cleanup delle mappe di traduzione in secondi
    #[serde(default = "default_translation_cleanup_interval")]
    pub translation_cleanup_interval_seconds: u64,
    
    /// Soglia CPU per il cleanup aggressivo
    #[serde(default = "default_cpu_threshold")]
    pub cpu_threshold: f32,
    
    /// Threshold timestamp in secondi per eliminare entry vecchie
    #[serde(default = "default_timestamp_threshold")]
    pub timestamp_threshold_seconds: u64,
    
    /// Cleanup forzato ogni N iterazioni
    #[serde(default = "default_force_cleanup_every")]
    pub force_cleanup_every: u32,
    
    /// Lista dei server configurati
    pub servers: Vec<ServerConfig>,
}

fn default_check_interval() -> u64 {
    60 // Controlla ogni minuto
}

fn default_translation_cleanup_interval() -> u64 {
    5 // Cleanup ogni 5 secondi
}

fn default_cpu_threshold() -> f32 {
    5.0 // Soglia CPU al 5%
}

fn default_timestamp_threshold() -> u64 {
    60 // 60 secondi (1 minuto)
}

fn default_force_cleanup_every() -> u32 {
    20 // Ogni 20 iterazioni
}

impl ClientConfig {
    /// Carica la configurazione da file YAML
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
    
    /// Salva la configurazione su file YAML
    pub fn save_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let yaml = serde_yaml::to_string(self)?;
        std::fs::write(path, yaml)?;
        Ok(())
    }
}
