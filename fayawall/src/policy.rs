use serde::Deserialize;

#[derive(Deserialize)]
pub struct BlacklistPolicy {
    pub ipv4: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct RateLimitPolicy {
    pub packet_limit: Option<String>,
    pub window_size: Option<String>,
}

#[derive(Deserialize)]
pub struct Policy {
    pub blacklist: Option<BlacklistPolicy>,
    pub rate_limit: Option<RateLimitPolicy>,
}
