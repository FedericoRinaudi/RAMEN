use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use crate::models::MapKey;

use super::monitoring::get_cpu_usage;
use super::timestamp_cleanup::{BpfState, cleanup_all_maps_by_timestamp};

fn reverse_flow_in_key(mut key: MapKey) -> MapKey {
    let tmp_addr = key.flow.saddr;
    let tmp_port = key.flow.sport;
    key.flow.saddr = key.flow.daddr;
    key.flow.sport = key.flow.dport;
    key.flow.daddr = tmp_addr;
    key.flow.dport = tmp_port;
    key
}

/// Recursively cleans up SEQ entries and the matching ACK entries
/// Strategy:
/// - Look up the SEQ map with the given flow and seq_num
/// - For each entry found:
///   1. Remove the current SEQ entry
///   2. Use translated_seq with the reversed flow to find and remove the matching ACK
///   3. Continue recursively with prev_seq
/// Note: ACK entries are no longer processed recursively (prev_seq=0)
fn cleanup_seq_recursive(
    bpf_state: &BpfState,
    seq_map_name: &str,
    ack_map_name: &str,
    mut key: MapKey,
) -> Result<usize, Box<dyn std::error::Error>> {
    use crate::models::MapValue;
    
    let mut seq_count = 0;
    let mut ack_count = 0;
    
    loop {
        let mut loader = bpf_state.loader.lock().unwrap();
        let maps = loader.maps();
        
        let key_bytes = key.to_bytes();
        
        let value_bytes = match maps.lookup(seq_map_name, &key_bytes)? {
            Some(bytes) => bytes,
            None => {
                drop(maps);
                drop(loader);
                break;
            }
        };
        
        let value = MapValue::from_bytes(&value_bytes)?;
        let prev_seq = value.prev_seq;
        let translated_seq = value.translated_seq;
        
        drop(maps);
        
        let mut maps_mut = loader.maps();
        maps_mut.delete(seq_map_name, &key_bytes)?;
        seq_count += 1;
        drop(maps_mut);
        drop(loader);
        
        let mut ack_key = reverse_flow_in_key(key.clone());
        ack_key.seq = translated_seq;
        
        let mut loader = bpf_state.loader.lock().unwrap();
        let ack_key_bytes = ack_key.to_bytes();
        
        if let Ok(Some(_)) = loader.maps().lookup(ack_map_name, &ack_key_bytes) {
            drop(loader);
            let mut loader = bpf_state.loader.lock().unwrap();
            let mut maps_mut = loader.maps();
            
            if maps_mut.delete(ack_map_name, &ack_key_bytes).is_ok() {
                ack_count += 1;
            }
            drop(maps_mut);
            drop(loader);
        } else {
            drop(loader);
        }
        
        // prev_seq == 0 means we reached the start (SYN)
        if prev_seq == 0 {
            break;
        }
        
        key.seq = prev_seq;
    }
    
    Ok(seq_count + ack_count)
}

/// Processes a queue of completed flows and recursively cleans up the maps
/// Strategy:
/// - Pop from the queue: yields the translated seq_num with the flow already reversed
/// - Look up the SEQ map directly with these values
/// - Recursively remove all SEQ entries and the matching ACK entries
fn process_cleanup_queue(
    bpf_state: &BpfState,
    queue_name: &str,
    seq_map_name: &str,
    ack_map_name: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut total_cleaned = 0;
    let mut _flows_processed = 0;
    
    loop {
        let mut loader = bpf_state.loader.lock().unwrap();
        let maps = loader.maps();
        
        let key_bytes = match maps.pop_from_queue(queue_name)? {
            Some(bytes) => bytes,
            None => break,
        };
        
        let key = MapKey::from_bytes(&key_bytes)?;
        _flows_processed += 1;
        
        drop(maps);
        drop(loader);
        
        match cleanup_seq_recursive(bpf_state, seq_map_name, ack_map_name, key) {
            Ok(count) => {
                total_cleaned += count;
            }
            Err(e) => {
                eprintln!("[TRANSLATION_CLEANUP] Error during recursive cleanup: {}", e);
            }
        }
    }
    
    Ok(total_cleaned)
}

pub fn cleanup_translation_maps(
    bpf_state: &BpfState,
    cpu_threshold: f32,
    timestamp_threshold_ns: u64,
    iteration_count: u32,
    force_cleanup_every: u32,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut total = 0;
    
    // Flow completed on ingress (ACK received for a FIN we sent)
    if let Ok(count) = process_cleanup_queue(
        bpf_state,
        "completed_flow_ingress",
        "network_to_host_seq_map",
        "host_to_network_ack_map",
    ) {
        total += count;
    }
    
    // Flow completed on egress (ACK sent for a FIN we received)
    if let Ok(count) = process_cleanup_queue(
        bpf_state,
        "completed_flow_egress",
        "host_to_network_seq_map",
        "network_to_host_ack_map",
    ) {
        total += count;
    }
    
    let queue_cleaned = total;
    if queue_cleaned > 0 {
        println!("[CLEANUP] Completed flows cleanup: {} entries removed", queue_cleaned);
    }
    
    // Aggressive cleanup logic:
    // - CPU idle: always clean up preemptively
    // - CPU busy: skip cleanup to avoid overload
    // - Every N iterations: forced cleanup even when the CPU is busy
    let cpu_usage = get_cpu_usage().unwrap_or(0.0);
    let force_cleanup = iteration_count % force_cleanup_every == 0;
    
    if cpu_usage <= cpu_threshold || force_cleanup {
        let cleaned = cleanup_all_maps_by_timestamp(bpf_state, timestamp_threshold_ns);
        total += cleaned;
    }
    
    Ok(total)
}

pub fn start_translation_cleanup_task(
    bpf_state: Arc<BpfState>,
    interval_secs: u64,
    cpu_threshold: f32,
    timestamp_threshold_ns: u64,
    force_cleanup_every: u32,
) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(interval_secs));
        let mut iteration_count: u32 = 1;
        
        loop {
            interval.tick().await;
            
            match cleanup_translation_maps(
                &bpf_state,
                cpu_threshold,
                timestamp_threshold_ns,
                iteration_count,
                force_cleanup_every,
            ) {
                Ok(_) => {},
                Err(_) => {}
            }
            iteration_count = iteration_count.wrapping_add(1);
        }
    });
}
