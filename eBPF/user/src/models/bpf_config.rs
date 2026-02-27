/// Struttura per raggruppare i parametri di configurazione BPF
#[derive(Debug, Clone)]
pub struct BpfConfig {
    /// Chiave per il padding (32 byte)
    pub padding_key: Vec<u8>,

    /// Chiave per i pacchetti dummy (32 byte)
    pub dummy_key: Vec<u8>,

    /// Durata validità configurazione in secondi
    pub duration_seconds: u64,

    /// Indirizzo IP del client
    pub client_ip: std::net::IpAddr,

    /// Porta del server
    pub server_port: u16,

    /// Probabilità minima di padding (0-100)
    pub padding_prob_min: u8,

    /// Probabilità massima di padding (0-100)
    pub padding_prob_max: u8,

    /// Probabilità minima di dummy packets (0-100)
    pub dummy_prob_min: u8,

    /// Probabilità massima di dummy packets (0-100)
    pub dummy_prob_max: u8,

    /// Probabilità minima di frammentazione (0-100)
    pub frag_prob_min: u8,

    /// Probabilità massima di frammentazione (0-100)
    pub frag_prob_max: u8,
}

impl BpfConfig {
    /// Crea una nuova configurazione BPF
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        padding_key: Vec<u8>,
        dummy_key: Vec<u8>,
        duration_seconds: u64,
        client_ip: std::net::IpAddr,
        server_port: u16,
        padding_prob_min: u8,
        padding_prob_max: u8,
        dummy_prob_min: u8,
        dummy_prob_max: u8,
        frag_prob_min: u8,
        frag_prob_max: u8,
    ) -> Self {
        Self {
            padding_key,
            dummy_key,
            duration_seconds,
            client_ip,
            server_port,
            padding_prob_min,
            padding_prob_max,
            dummy_prob_min,
            dummy_prob_max,
            frag_prob_min,
            frag_prob_max,
        }
    }

    /// Ottiene l'IP come u32 (solo IPv4)
    pub fn ip_as_u32(&self) -> Result<u32, &'static str> {
        match self.client_ip {
            std::net::IpAddr::V4(ipv4) => Ok(u32::from_be_bytes(ipv4.octets())),
            std::net::IpAddr::V6(_) => Err("Solo IPv4 supportato"),
        }
    }

    /// Calcola il timestamp di scadenza
    pub fn calculate_expiration(&self) -> Result<u64, Box<dyn std::error::Error>> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        Ok(now.as_secs() + self.duration_seconds)
    }
}
