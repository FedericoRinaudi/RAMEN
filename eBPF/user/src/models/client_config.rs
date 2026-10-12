use std::mem;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClientConfigKey {
    pub ip_addr: u32,
    pub server_port: u16,
    pub _padding: u16, // Padding esplicito per l'allineamento
}

impl ClientConfigKey {
    pub fn new(ip_addr: u32, server_port: u16) -> Self {
        Self { ip_addr, server_port, _padding: 0 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                mem::size_of::<Self>()
            )
        }
    }
}

/// Struttura valore per la mappa BPF (corrisponde a struct client_config in C).
///
/// Layout (offset / size):
///  0  32  padding_key
/// 32  32  dummy_key
/// 64   8  expiration_time (u64)
/// 72   1  padding_probability  (corrente, aggiornata da eBPF)
/// 73   1  padding_prob_min
/// 74   1  padding_prob_max
/// 75   1  dummy_probability    (corrente)
/// 76   1  dummy_prob_min
/// 77   1  dummy_prob_max
/// 78   1  frag_probability     (corrente)
/// 79   1  frag_prob_min
/// 80   1  frag_prob_max
/// 81   7  _pad                 (allineamento a 8 byte)
/// 88   8  prob_timestamp (u64) (ktime_get_ns dell'ultimo refresh)
/// totale: 96 byte
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClientConfigValue {
    pub padding_key: [u8; 32],
    pub dummy_key: [u8; 32],
    pub expiration_time: u64,
    pub padding_probability: u8,
    pub padding_prob_min: u8,
    pub padding_prob_max: u8,
    pub dummy_probability: u8,
    pub dummy_prob_min: u8,
    pub dummy_prob_max: u8,
    pub frag_probability: u8,
    pub frag_prob_min: u8,
    pub frag_prob_max: u8,
    pub _pad: [u8; 7],
    pub prob_timestamp: u64,
}

impl ClientConfigValue {
    pub fn new(
        padding_key: &[u8],
        dummy_key: &[u8],
        expiration_time: u64,
        padding_prob_min: u8,
        padding_prob_max: u8,
        dummy_prob_min: u8,
        dummy_prob_max: u8,
        frag_prob_min: u8,
        frag_prob_max: u8,
    ) -> Self {
        let mut value = Self {
            padding_key: [0u8; 32],
            dummy_key: [0u8; 32],
            expiration_time,
            // Probabilità correnti inizializzate a min; eBPF le sovrascrive al primo pacchetto
            // perché prob_timestamp = 0 garantisce che il refresh scatti immediatamente.
            padding_probability: padding_prob_min,
            padding_prob_min,
            padding_prob_max,
            dummy_probability: dummy_prob_min,
            dummy_prob_min,
            dummy_prob_max,
            frag_probability: frag_prob_min,
            frag_prob_min,
            frag_prob_max,
            _pad: [0u8; 7],
            prob_timestamp: 0,
        };
        value.padding_key.copy_from_slice(padding_key);
        value.dummy_key.copy_from_slice(dummy_key);
        value
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                mem::size_of::<Self>()
            )
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != mem::size_of::<Self>() {
            return Err("Lunghezza byte non valida per ClientConfigValue");
        }

        let value = unsafe {
            std::ptr::read(bytes.as_ptr() as *const Self)
        };
        Ok(value)
    }

    /// Verifica se le chiavi sono scadute
    pub fn is_expired(&self, current_time: u64) -> bool {
        self.expiration_time < current_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_key_size() {
        // 4 IP + 2 port + 2 padding = 8 bytes
        assert_eq!(mem::size_of::<ClientConfigKey>(), 8);
    }

    #[test]
    fn test_client_config_value_size() {
        // 32 + 32 + 8 + 9 + 7 + 8 = 96 bytes
        assert_eq!(mem::size_of::<ClientConfigValue>(), 96);
    }

    #[test]
    fn test_client_config_value_expiration() {
        let value = ClientConfigValue::new(&[0u8; 32], &[0u8; 32], 100, 30, 70, 30, 70, 30, 70);
        assert!(!value.is_expired(50));
        assert!(value.is_expired(150));
    }

    #[test]
    fn test_initial_prob_set_to_min() {
        let value = ClientConfigValue::new(&[0u8; 32], &[0u8; 32], 100, 20, 80, 10, 60, 5, 50);
        assert_eq!(value.padding_probability, 20);
        assert_eq!(value.dummy_probability, 10);
        assert_eq!(value.frag_probability, 5);
        assert_eq!(value.prob_timestamp, 0);
    }
}
