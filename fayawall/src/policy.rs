use std::fs::read_to_string;

use aya::Ebpf;
use clap::Parser;
use serde::Deserialize;
use toml::from_str;
use tracing::{error, info, warn};

use crate::{arg::Arg, ebpf::Init};

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

impl Policy {
    pub fn apply(ebpf: &mut Ebpf) -> anyhow::Result<()> {
        let ref policy_file = Arg::parse().policy;

        match read_to_string(policy_file) {
            Ok(ref policy) => match from_str(policy) {
                Ok(Policy {
                    blacklist,
                    rate_limit,
                }) if blacklist.is_some() || rate_limit.is_some() => {
                    info!("Applying policy");

                    ebpf.blacklist()?.apply(blacklist);
                    ebpf.rate_limit_settings()?.apply(rate_limit);

                    info!("Policy applied");
                }

                Err(e) => error!("`{policy_file}` not parsed: {e}"),

                _ => warn!("No policy found in `{policy_file}`"),
            },

            Err(e) => warn!("`{policy_file}` not found: {e}"),
        };

        Ok(())
    }
}
