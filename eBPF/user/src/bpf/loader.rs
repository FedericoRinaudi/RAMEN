use libbpf_rs::skel::{SkelBuilder, Skel, OpenSkel};
use libbpf_rs::{TcHookBuilder, TC_EGRESS, TC_INGRESS, MapCore};
use std::os::fd::AsFd;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

use super::maps::BpfMapManager;
use crate::{ClientConfigKey, ClientConfigValue};

// Include the generated libbpf skeleton so the types are available at compile time
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/wfsafebpf_skel.rs"));

pub struct BpfLoader {
    skel: WfsafebpfSkel<'static>,
    ifindex: i32,
}

impl BpfLoader {
    /// Esegue il caricamento e l'attivazione dei programmi eBPF
    pub fn run(ifname: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let ifindex = nix::net::if_::if_nametoindex(ifname)? as i32;
        // Open and load the skeleton
        let open_obj_box = Box::leak(Box::new(std::mem::MaybeUninit::<libbpf_rs::OpenObject>::uninit()));
        let skel = WfsafebpfSkelBuilder::default().open(open_obj_box)?.load()?;
        
        // Attach ingress program manually using TC hook
        let mut ingress_hook = TcHookBuilder::new(skel.progs.handle_ingress.as_fd())
            .ifindex(ifindex)
            .replace(true)
            .handle(1)
            .priority(1)
            .hook(TC_INGRESS);
        
        ingress_hook.create()?;
        ingress_hook.attach()?;
        
        // Attach egress program manually using TC hook
        let mut egress_hook = TcHookBuilder::new(skel.progs.handle_egress.as_fd())
            .ifindex(ifindex)
            .replace(true)
            .handle(1)
            .priority(1)
            .hook(TC_EGRESS);
        
        egress_hook.create()?;
        egress_hook.attach()?;
        
        println!("Programmi eBPF attaccati correttamente a {}", ifname);
        
        Ok(BpfLoader { skel, ifindex })
    }
    
    /// Ottiene un manager per gestire le operazioni sulle mappe eBPF
    pub fn maps(&mut self) -> BpfMapManager<'_> {
        // Convert from skeleton to the underlying libbpf_rs::Object
        BpfMapManager::new(self.skel.object_mut())
    }
    
    /// Conta le entry in una mappa (solo lettura)
    pub fn count_map_entries(&self, map_name: &str) -> Result<usize, Box<dyn std::error::Error>> {
        use std::os::fd::AsRawFd;
        
        let map = self.skel.object()
            .maps()
            .find(|m| m.name().to_string_lossy() == map_name)
            .ok_or_else(|| format!("Mappa '{}' non trovata", map_name))?;
        
        let key_size = map.key_size() as usize;
        let mut count = 0;
        let mut current_key: Option<Vec<u8>> = None;
        
        loop {
            let mut next_key = vec![0u8; key_size];
            let result = unsafe {
                libbpf_rs::libbpf_sys::bpf_map_get_next_key(
                    map.as_fd().as_raw_fd(),
                    current_key.as_ref().map_or(std::ptr::null(), |k| k.as_ptr() as *const std::ffi::c_void),
                    next_key.as_mut_ptr() as *mut std::ffi::c_void,
                )
            };
            
            if result == 0 {
                count += 1;
                current_key = Some(next_key);
            } else {
                break;
            }
        }
        
        Ok(count)
    }
    
    /// Legge tutte le chiavi di una mappa (solo lettura)
    pub fn read_map_keys(&self, map_name: &str) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        use std::os::fd::AsRawFd;
        
        let map = self.skel.object()
            .maps()
            .find(|m| m.name().to_string_lossy() == map_name)
            .ok_or_else(|| format!("Mappa '{}' non trovata", map_name))?;
        
        let key_size = map.key_size() as usize;
        let mut keys = Vec::new();
        let mut current_key: Option<Vec<u8>> = None;
        
        loop {
            let mut next_key = vec![0u8; key_size];
            let result = unsafe {
                libbpf_rs::libbpf_sys::bpf_map_get_next_key(
                    map.as_fd().as_raw_fd(),
                    current_key.as_ref().map_or(std::ptr::null(), |k| k.as_ptr() as *const std::ffi::c_void),
                    next_key.as_mut_ptr() as *mut std::ffi::c_void,
                )
            };
            
            if result == 0 {
                keys.push(next_key.clone());
                current_key = Some(next_key);
            } else {
                break;
            }
        }
        
        Ok(keys)
    }
    
    /// Legge un valore da una mappa (solo lettura)
    pub fn read_map_value(&self, map_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let map = self.skel.object()
            .maps()
            .find(|m| m.name().to_string_lossy() == map_name)
            .ok_or_else(|| format!("Mappa '{}' non trovata", map_name))?;
        
        Ok(map.lookup(key, libbpf_rs::MapFlags::ANY)?)
    }
    
    /// Detach un programma TC ingress
    pub fn detach_ingress<F: AsFd>(&self, prog_fd: &F) -> Result<(), Box<dyn std::error::Error>> {
        let mut hook = TcHookBuilder::new(prog_fd.as_fd())
            .ifindex(self.ifindex)
            .replace(true)
            .handle(1)
            .priority(1)
            .hook(TC_INGRESS);
        
        hook.detach()?;
        hook.destroy()?;
        Ok(())
    }
    
    /// Detach un programma TC egress
    pub fn detach_egress<F: AsFd>(&self, prog_fd: &F) -> Result<(), Box<dyn std::error::Error>> {
        let mut hook = TcHookBuilder::new(prog_fd.as_fd())
            .ifindex(self.ifindex)
            .replace(true)
            .handle(1)
            .priority(1)
            .hook(TC_EGRESS);
        
        hook.detach()?;
        hook.destroy()?;
        Ok(())
    }
    
    /// Carica una configurazione nella mappa eBPF client_config_map
    /// 
    /// # Parametri
    /// - `config`: Configurazione BPF contenente tutti i parametri necessari
    pub fn load_config(
        &mut self,
        config: &crate::models::BpfConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ip = config.ip_as_u32()?;
        let expiration_time = config.calculate_expiration()?;
        
        let key = ClientConfigKey::new(ip, config.server_port);
        let value = ClientConfigValue::new(
            &config.padding_key,
            &config.dummy_key,
            expiration_time,
            config.padding_prob_min,
            config.padding_prob_max,
            config.dummy_prob_min,
            config.dummy_prob_max,
            config.frag_prob_min,
            config.frag_prob_max,
        );
        
        self.maps().update(
            "client_config_map",
            key.as_bytes(),
            value.as_bytes(),
            libbpf_rs::MapFlags::ANY,
        )?;
        
        Ok(())
    }
    
    /// Rimuove una configurazione dalla mappa eBPF client_config_map
    pub fn remove_config(&mut self, ip: u32, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let key = ClientConfigKey::new(ip, port);
        self.maps().delete("client_config_map", key.as_bytes())?;
        Ok(())
    }
    
    /// Pulisce le configurazioni scadute dalla mappa eBPF client_config_map
    pub fn cleanup_expired_configs(&mut self) -> Result<usize, Box<dyn std::error::Error>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        let keys = self.maps().iter_keys("client_config_map")?;
        let mut removed_count = 0;
        
        for key in keys {
            if let Some(value_bytes) = self.maps().lookup("client_config_map", &key)? {
                if let Ok(value) = ClientConfigValue::from_bytes(&value_bytes) {
                    if value.is_expired(now) {
                        let _ = self.maps().delete("client_config_map", &key);
                        removed_count += 1;
                    }
                }
            }
        }
        
        Ok(removed_count)
    }
}

impl Drop for BpfLoader {
    fn drop(&mut self) {
        let _ = self.detach_ingress(&self.skel.progs.handle_ingress);
        let _ = self.detach_egress(&self.skel.progs.handle_egress);
    }
}
