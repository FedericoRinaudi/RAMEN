#[macro_use] extern crate rocket;

#[macro_use]
mod log_macros;

mod config;
mod crons;
mod dtos;
mod guards;
mod models;
mod services;

use std::sync::{Arc, Mutex};
use rocket::serde::json::Json;
use rocket::http::Status;
use dtos::ClientConfig;
use guards::ClientRealAddr;
use services::ClientConfigService;
use user::{BpfLoader, BpfState};

pub struct DefaultProbabilities {
    pub padding_min: u8,
    pub padding_max: u8,
    pub dummy_min: u8,
    pub dummy_max: u8,
    pub frag_min: u8,
    pub frag_max: u8,
}

#[post("/config", format = "json", data = "<config>")]
fn set_config(
    bpf_state: &rocket::State<Arc<BpfState>>,
    default_probs: &rocket::State<DefaultProbabilities>,
    config: Json<ClientConfig>,
    client_ip: ClientRealAddr,
) -> Result<String, Status> {
    let mut config = config.into_inner();
    log_debug!("[CONFIG] Received probs: pad=[{:?},{:?}] dummy=[{:?},{:?}] frag=[{:?},{:?}]",
             config.padding_prob_min, config.padding_prob_max,
             config.dummy_prob_min,   config.dummy_prob_max,
             config.frag_prob_min,    config.frag_prob_max);

    config = config.with_default_probabilities(
        default_probs.padding_min, default_probs.padding_max,
        default_probs.dummy_min,   default_probs.dummy_max,
        default_probs.frag_min,    default_probs.frag_max,
    );
    let (pad_min, pad_max, dum_min, dum_max, fr_min, fr_max) = config.get_probabilities();
    log_debug!("[CONFIG] After defaults: pad=[{},{}] dummy=[{},{}] frag=[{},{}]",
             pad_min, pad_max, dum_min, dum_max, fr_min, fr_max);

    let (padding_key, dummy_key) = config.parse_keys()
        .map_err(|_| Status::BadRequest)?;

    let bpf_config = user::models::BpfConfig::new(
        padding_key,
        dummy_key,
        config.duration_seconds,
        client_ip.0,
        config.server_port,
        pad_min,
        pad_max,
        dum_min,
        dum_max,
        fr_min,
        fr_max,
    );
    
    let (ip, port, expiration_time) = ClientConfigService::insert_config(
        bpf_state.inner(),
        bpf_config,
    ).map_err(|e| {
        log_error!("Error inserting configuration: {}", e);
        Status::InternalServerError
    })?;
    
    Ok(format!("Configuration inserted for IP:port {}:{} (expiration: {})", ip, port, expiration_time))
}

#[launch]
fn rocket() -> _ {
    let rocket = rocket::build();
    let ifname = config::Config::get_interface(&rocket);
    
    let keys_cleanup_interval = rocket.figment()
        .extract_inner::<u64>("keys_cleanup_interval_seconds")
        .unwrap_or(60);
    
    let translation_cleanup_interval = rocket.figment()
        .extract_inner::<u64>("translation_cleanup_interval_seconds")
        .unwrap_or(5);
    
    let cpu_threshold = rocket.figment()
        .extract_inner::<f32>("cpu_threshold")
        .unwrap_or(70.0);
    
    let timestamp_threshold_seconds = rocket.figment()
        .extract_inner::<u64>("timestamp_threshold_seconds")
        .unwrap_or(3600);
    
    let force_cleanup_every = rocket.figment()
        .extract_inner::<u32>("force_cleanup_every")
        .unwrap_or(12);
    
    let default_padding_prob_min = rocket.figment()
        .extract_inner::<u8>("default_padding_prob_min")
        .unwrap_or(30);
    let default_padding_prob_max = rocket.figment()
        .extract_inner::<u8>("default_padding_prob_max")
        .unwrap_or(70);
    let default_dummy_prob_min = rocket.figment()
        .extract_inner::<u8>("default_dummy_prob_min")
        .unwrap_or(30);
    let default_dummy_prob_max = rocket.figment()
        .extract_inner::<u8>("default_dummy_prob_max")
        .unwrap_or(70);
    let default_frag_prob_min = rocket.figment()
        .extract_inner::<u8>("default_frag_prob_min")
        .unwrap_or(30);
    let default_frag_prob_max = rocket.figment()
        .extract_inner::<u8>("default_frag_prob_max")
        .unwrap_or(70);

    let bpf_loader = BpfLoader::run(&ifname).unwrap_or_else(|e| {
        panic!("Error running eBPF program: {}", e);
    });

    let bpf_state = Arc::new(BpfState {
        loader: Arc::new(Mutex::new(bpf_loader)),
    });

    let default_probabilities = DefaultProbabilities {
        padding_min: default_padding_prob_min,
        padding_max: default_padding_prob_max,
        dummy_min:   default_dummy_prob_min,
        dummy_max:   default_dummy_prob_max,
        frag_min:    default_frag_prob_min,
        frag_max:    default_frag_prob_max,
    };
    
    rocket
        .manage(bpf_state)
        .manage(default_probabilities)
        .attach(crons::ConfigCleanupFairing { 
            interval_secs: keys_cleanup_interval 
        })
        .attach(crons::TranslationCleanupFairing { 
            interval_secs: translation_cleanup_interval,
            cpu_threshold,
            timestamp_threshold_secs: timestamp_threshold_seconds,
            force_cleanup_every,
        })
        .mount("/", routes![set_config])
}