use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub name: String,
    
    pub server_ip: String,
    
    pub http_port: u16,
    
    /// RAMEN service port (sent in the request body and used as the eBPF key)
    pub service_port: u16,
    
    pub endpoint: String,
    
    pub last_sent_at: DateTime<Utc>,
    
    pub duration_seconds: u64,
    
    #[serde(default = "default_prob_min")]
    pub padding_prob_min: u8,

    #[serde(default = "default_prob_max")]
    pub padding_prob_max: u8,

    #[serde(default = "default_prob_min")]
    pub dummy_prob_min: u8,

    #[serde(default = "default_prob_max")]
    pub dummy_prob_max: u8,

    #[serde(default = "default_prob_min")]
    pub frag_prob_min: u8,

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
    /// Checks whether the keys must be renewed (expired or expiring within 1 minute)
    pub fn needs_renewal(&self) -> bool {
        let now = Utc::now();
        let expiration = self.last_sent_at + chrono::Duration::seconds(self.duration_seconds as i64);
        let expiration_with_buffer = expiration - chrono::Duration::seconds(60);
        now >= expiration_with_buffer
    }
    
    pub fn expiration_timestamp(&self) -> i64 {
        (self.last_sent_at + chrono::Duration::seconds(self.duration_seconds as i64)).timestamp()
    }
    
    pub fn update_last_sent(&mut self) {
        self.last_sent_at = Utc::now();
    }
    
    /// Generates new random keys (not saved in the configuration)
    pub fn generate_keys() -> (Vec<u8>, Vec<u8>) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        let padding_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        
        let dummy_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        
        (padding_bytes, dummy_bytes)
    }
    
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub interface: String,
    
    #[serde(default = "default_check_interval")]
    pub check_interval_seconds: u64,
    
    #[serde(default = "default_translation_cleanup_interval")]
    pub translation_cleanup_interval_seconds: u64,
    
    #[serde(default = "default_cpu_threshold")]
    pub cpu_threshold: f32,
    
    #[serde(default = "default_timestamp_threshold")]
    pub timestamp_threshold_seconds: u64,
    
    #[serde(default = "default_force_cleanup_every")]
    pub force_cleanup_every: u32,
    
    pub servers: Vec<ServerConfig>,
}

fn default_check_interval() -> u64 {
    60
}

fn default_translation_cleanup_interval() -> u64 {
    5
}

fn default_cpu_threshold() -> f32 {
    5.0
}

fn default_timestamp_threshold() -> u64 {
    60
}

fn default_force_cleanup_every() -> u32 {
    20
}

impl ClientConfig {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
    
    pub fn save_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let yaml = serde_yaml::to_string(self)?;
        std::fs::write(path, yaml)?;
        Ok(())
    }
}
