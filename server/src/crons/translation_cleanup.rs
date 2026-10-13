use std::sync::Arc;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Rocket, Build};
use user::{BpfState, start_translation_cleanup_task};

pub struct TranslationCleanupFairing {
    pub interval_secs: u64,
    pub cpu_threshold: f32,
    pub timestamp_threshold_secs: u64,
    pub force_cleanup_every: u32,
}

#[rocket::async_trait]
impl Fairing for TranslationCleanupFairing {
    fn info(&self) -> Info {
        Info {
            name: "Translation Cleanup Task Starter",
            kind: Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> rocket::fairing::Result {
        let bpf_state = rocket.state::<Arc<BpfState>>()
            .expect("BpfState not found in Rocket state");
        
        let timestamp_threshold_ns = self.timestamp_threshold_secs * 1_000_000_000;
        
        start_translation_cleanup_task(
            Arc::clone(bpf_state),
            self.interval_secs,
            self.cpu_threshold,
            timestamp_threshold_ns,
            self.force_cleanup_every,
        );
        
        Ok(rocket)
    }
}
