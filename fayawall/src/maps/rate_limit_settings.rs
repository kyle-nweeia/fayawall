use aya::maps::{HashMap, MapData};
use common::RateLimitSetting;
use tracing::{error, info, warn};

use crate::RateLimitPolicy;

pub struct RateLimitSettings<'a>(pub HashMap<&'a mut MapData, u8, u64>);

impl<'a> RateLimitSettings<'a> {
    pub fn apply(&mut self, rate_limit_policy: Option<RateLimitPolicy>) {
        if let Some(RateLimitPolicy {
            packet_limit,
            window_size,
        }) = rate_limit_policy
        {
            if let Some(packet_limit_string) = packet_limit {
                match packet_limit_string.parse::<u64>() {
                    Ok(limit) => {
                        if let Err(e) = self.0.insert(RateLimitSetting::PacketLimit as u8, limit, 0)
                        {
                            error!("packet_limit could not be set to {limit}: {e}");
                        } else {
                            info!("packet_limit set to {limit}");
                        }
                    }
                    Err(e) => warn!(r#""{packet_limit_string}" could not be parsed as u64: {e}"#),
                }
            }
            if let Some(window_size_string) = window_size {
                match window_size_string.parse::<u64>() {
                    Ok(size) => {
                        if let Err(e) = self.0.insert(RateLimitSetting::WindowSize as u8, size, 0) {
                            error!("window_size could not be set to {size}: {e}");
                        } else {
                            info!("window_size set to {size}");
                        }
                    }
                    Err(e) => warn!(r#""{window_size_string}" could not be parsed as u64: {e}"#),
                }
            }
        };
    }
}
