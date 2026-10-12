use rocket::serde::Deserialize;

/// Struttura per ricevere la configurazione del client via JSON
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct ClientConfig {
    pub padding_key: String,      // 64 caratteri esadecimali (32 byte)
    pub dummy_key: String,        // 64 caratteri esadecimali (32 byte)
    pub duration_seconds: u64,    // Durata validità configurazione in secondi
    pub server_port: u16,         // Porta del server
    pub padding_prob_min: Option<u8>,  // Probabilità minima (0-100) di applicare padding
    pub padding_prob_max: Option<u8>,  // Probabilità massima (0-100) di applicare padding
    pub dummy_prob_min: Option<u8>,    // Probabilità minima (0-100) di inserire dummy packets
    pub dummy_prob_max: Option<u8>,    // Probabilità massima (0-100) di inserire dummy packets
    pub frag_prob_min: Option<u8>,     // Probabilità minima (0-100) di frammentare pacchetti
    pub frag_prob_max: Option<u8>,     // Probabilità massima (0-100) di frammentare pacchetti
}

impl ClientConfig {
    /// Imposta le probabilità di default dalla configurazione se non sono presenti nel JSON
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

    /// Ottieni i valori finali delle probabilità (con unwrap sicuro dopo with_default_probabilities)
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
    /// Converti le chiavi esadecimali in byte array
    pub fn parse_keys(&self) -> Result<(Vec<u8>, Vec<u8>), ()> {
        let padding_key = hex_to_bytes(&self.padding_key)?;
        let dummy_key = hex_to_bytes(&self.dummy_key)?;
        
        if padding_key.len() != 32 || dummy_key.len() != 32 {
            return Err(());
        }
        
        Ok((padding_key, dummy_key))
    }
}

/// Helper per convertire stringa esadecimale in bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, ()> {
    if hex.len() % 2 != 0 {
        return Err(());
    }
    
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
