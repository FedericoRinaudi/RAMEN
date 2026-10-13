use std::net::IpAddr;
use std::sync::Arc;
use crate::BpfState;
use user::models::BpfConfig;

pub struct ClientConfigService;

impl ClientConfigService {
    pub fn insert_config(
        bpf_state: &Arc<BpfState>,
        config: BpfConfig,
    ) -> Result<(IpAddr, u16, u64), Box<dyn std::error::Error>> {
        let expiration_time = config.calculate_expiration()?;
        let client_ip = config.client_ip;
        let server_port = config.server_port;
        
        let mut loader = bpf_state.loader.lock().unwrap();
        loader.load_config(&config)?;
        
        Ok((client_ip, server_port, expiration_time))
    }
}
