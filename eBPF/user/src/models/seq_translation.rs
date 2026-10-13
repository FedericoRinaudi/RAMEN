/// Matches `struct map_key` in seq_num_translation.h
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MapKey {
    pub flow: FlowInfo,
    pub seq: u32,
}

/// Matches `struct flow_info` in network_utils.h
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FlowInfo {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
}

/// Matches `struct map_value` in seq_num_translation.h
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MapValue {
    pub translated_seq: u32,
    pub prev_seq: u32,
    pub timestamp_ns: u64,
    pub is_fin_ack: u8,
}

impl MapKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let size = std::mem::size_of::<MapKey>();
        let ptr = self as *const MapKey as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, size).to_vec() }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        if bytes.len() != std::mem::size_of::<MapKey>() {
            return Err("Invalid byte length for MapKey".into());
        }
        let ptr = bytes.as_ptr() as *const MapKey;
        Ok(unsafe { *ptr })
    }
}

impl MapValue {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let expected = std::mem::size_of::<MapValue>();
        if bytes.len() != expected {
            return Err(format!(
                "Invalid byte length for MapValue: expected {} bytes, got {} bytes. \
                MapValue layout: translated_seq(4) + prev_seq(4) + timestamp_ns(8) + is_fin_ack(1) = {} total",
                expected, bytes.len(), expected
            ).into());
        }
        let ptr = bytes.as_ptr() as *const MapValue;
        Ok(unsafe { *ptr })
    }
}
