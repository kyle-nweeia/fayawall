use serde::Deserialize;

#[derive(Deserialize)]
pub struct BlacklistPolicy {
    pub ipv4: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct RateLimitPolicy {
    pub packet_limit: Option<u64>,
    pub window_size: Option<u64>,
}

#[derive(Deserialize)]
pub struct Policy {
    pub blacklist: Option<BlacklistPolicy>,
    pub rate_limit: Option<RateLimitPolicy>,
}
