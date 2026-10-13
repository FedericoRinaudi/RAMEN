use rocket::serde::Deserialize;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct ClientConfig {
    pub padding_key: String,      // 64 hex characters (32 bytes)
    pub dummy_key: String,        // 64 hex characters (32 bytes)
    pub duration_seconds: u64,
    pub server_port: u16,
    pub padding_prob_min: Option<u8>,
    pub padding_prob_max: Option<u8>,
    pub dummy_prob_min: Option<u8>,
    pub dummy_prob_max: Option<u8>,
    pub frag_prob_min: Option<u8>,
    pub frag_prob_max: Option<u8>,
}

impl ClientConfig {
    pub fn with_default_probabilities(
        mut self,
        default_padding_min: u8,
        default_padding_max: u8,
        default_dummy_min: u8,
        default_dummy_max: u8,
        default_frag_min: u8,
        default_frag_max: u8,
    ) -> Self {
        if self.padding_prob_min.is_none() { self.padding_prob_min = Some(default_padding_min); }
        if self.padding_prob_max.is_none() { self.padding_prob_max = Some(default_padding_max); }
        if self.dummy_prob_min.is_none()   { self.dummy_prob_min   = Some(default_dummy_min); }
        if self.dummy_prob_max.is_none()   { self.dummy_prob_max   = Some(default_dummy_max); }
        if self.frag_prob_min.is_none()    { self.frag_prob_min    = Some(default_frag_min); }
        if self.frag_prob_max.is_none()    { self.frag_prob_max    = Some(default_frag_max); }
        self
    }

    /// Returns the final probability values (unwrap is safe after with_default_probabilities)
    pub fn get_probabilities(&self) -> (u8, u8, u8, u8, u8, u8) {
        (
            self.padding_prob_min.unwrap_or(0),
            self.padding_prob_max.unwrap_or(100),
            self.dummy_prob_min.unwrap_or(0),
            self.dummy_prob_max.unwrap_or(100),
            self.frag_prob_min.unwrap_or(0),
            self.frag_prob_max.unwrap_or(100),
        )
    }
    pub fn parse_keys(&self) -> Result<(Vec<u8>, Vec<u8>), ()> {
        let padding_key = hex_to_bytes(&self.padding_key)?;
        let dummy_key = hex_to_bytes(&self.dummy_key)?;
        
        if padding_key.len() != 32 || dummy_key.len() != 32 {
            return Err(());
        }
        
        Ok((padding_key, dummy_key))
    }
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, ()> {
    if hex.len() % 2 != 0 {
        return Err(());
    }
    
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
