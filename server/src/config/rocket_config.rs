use rocket::Rocket;

pub struct Config;

impl Config {
    pub fn get_interface(rocket: &Rocket<rocket::Build>) -> String {
        let ifname: String = rocket
            .figment()
            .extract_inner("iface")
            .unwrap_or_else(|_| {
                log_debug!("'iface' setting not found, defaulting to 'lo'");
                "lo".to_string()
            });
        
        log_info!("Configured network interface: {}", ifname);
        ifname
    }
    
}
