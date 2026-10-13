use crate::models::MapValue;
use crate::bpf::BpfLoader;
use std::sync::{Arc, Mutex};

pub struct BpfState {
    pub loader: Arc<Mutex<BpfLoader>>,
}

pub fn cleanup_by_timestamp(
    bpf_state: &BpfState,
    map_name: &str,
    threshold_ns: u64,
) -> Result<usize, Box<dyn std::error::Error>> {
    // Use monotonic time (since boot) to match bpf_ktime_get_ns()
    // Time since boot is read from /proc/uptime (in seconds): it matches bpf_ktime_get_ns() as long as the machine is never suspended
    let uptime_str = std::fs::read_to_string("/proc/uptime")?;
    let uptime_secs: f64 = uptime_str
        .split_whitespace()
        .next()
        .ok_or("Cannot read uptime")?
        .parse()?;
    let current_time_ns = (uptime_secs * 1_000_000_000.0) as u64;
    
    let mut cleaned = 0;
    
    let keys = {
        let loader = bpf_state.loader.lock().unwrap();
        loader.read_map_keys(map_name)?
    };
    
    for key_bytes in keys {
        let value_bytes = {
            let loader = bpf_state.loader.lock().unwrap();
            loader.read_map_value(map_name, &key_bytes)?
        };
        
        if let Some(vb) = value_bytes {
            if let Ok(value) = MapValue::from_bytes(&vb) {
                let age_ns = current_time_ns.saturating_sub(value.timestamp_ns);
                
                if age_ns > threshold_ns {
                    let mut loader = bpf_state.loader.lock().unwrap();
                    let mut maps = loader.maps();
                    if maps.delete(map_name, &key_bytes).is_ok() {
                        cleaned += 1;
                    }
                }
            }
        }
    }
    
    Ok(cleaned)
}

pub fn cleanup_all_maps_by_timestamp(
    bpf_state: &BpfState,
    threshold_ns: u64,
) -> usize {
    let seq_maps = [
        "network_to_host_seq_map",
        "host_to_network_seq_map",
    ];
    let ack_maps = [
        "host_to_network_ack_map",
        "network_to_host_ack_map",
    ];
    
    let mut total = 0;
    
    for map_name in &seq_maps {
        if let Ok(count) = cleanup_by_timestamp(bpf_state, map_name, threshold_ns) {
            total += count;
        }
    }
    
    for map_name in &ack_maps {
        if let Ok(count) = cleanup_by_timestamp(bpf_state, map_name, threshold_ns) {
            total += count;
        }
    }
    
    if total > 0 {
        println!("[CLEANUP] Age-based cleanup: {} entries removed", total);
    }
    
    total
}
