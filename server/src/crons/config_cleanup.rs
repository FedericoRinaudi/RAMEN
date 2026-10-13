use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Rocket, Build};
use crate::BpfState;

fn start_cleanup_task(bpf_state: Arc<BpfState>, interval_secs: u64) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            let mut loader = bpf_state.loader.lock().unwrap();
            match loader.cleanup_expired_configs() {
                Ok(count) if count > 0 => {
                    log_debug!("[CONFIG_CLEANUP] Removed {} expired configs", count);
                }
                Ok(_) => {}
                Err(e) => {
                    log_error!("[CONFIG_CLEANUP] Error during cleanup: {}", e);
                }
            }
        }
    });
}

pub struct ConfigCleanupFairing {
    pub interval_secs: u64,
}

#[rocket::async_trait]
impl Fairing for ConfigCleanupFairing {
    fn info(&self) -> Info {
        Info {
            name: "Client Config Cleanup Task Starter",
            kind: Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> rocket::fairing::Result {
        let bpf_state = rocket.state::<Arc<BpfState>>()
            .expect("BpfState not found in Rocket state");
        
        start_cleanup_task(Arc::clone(bpf_state), self.interval_secs);
        log_debug!("[CONFIG_CLEANUP] Task started with interval of {} seconds", self.interval_secs);
        
        Ok(rocket)
    }
}
