#[derive(Debug, Clone)]
pub struct BpfConfig {
    /// Padding key (32 bytes)
    pub padding_key: Vec<u8>,

    /// Dummy packet key (32 bytes)
    pub dummy_key: Vec<u8>,

    pub duration_seconds: u64,

    pub client_ip: std::net::IpAddr,

    pub server_port: u16,

    pub padding_prob_min: u8,

    pub padding_prob_max: u8,

    pub dummy_prob_min: u8,

    pub dummy_prob_max: u8,

    pub frag_prob_min: u8,

    pub frag_prob_max: u8,
}

impl BpfConfig {
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

    /// Returns the IP as u32 (IPv4 only)
    pub fn ip_as_u32(&self) -> Result<u32, &'static str> {
        match self.client_ip {
            std::net::IpAddr::V4(ipv4) => Ok(u32::from_be_bytes(ipv4.octets())),
            std::net::IpAddr::V6(_) => Err("Only IPv4 is supported"),
        }
    }

    pub fn calculate_expiration(&self) -> Result<u64, Box<dyn std::error::Error>> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
        Ok(now.as_secs() + self.duration_seconds)
    }
}
