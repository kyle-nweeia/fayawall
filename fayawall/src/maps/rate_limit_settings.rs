use aya::maps::{HashMap, MapData, MapError};
use common::RateLimitSetting::{PacketLimit, WindowSize};
use tracing::{error, info, warn};

use crate::policy::RateLimitPolicy;

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
                        if let Err(e) = self.set_packet_limit(limit) {
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
                        if let Err(e) = self.set_window_size(size) {
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

    pub fn get_packet_limit(&mut self) -> Result<u64, MapError> {
        self.0.get(&(PacketLimit as u8), 0)
    }

    pub fn get_window_size(&mut self) -> Result<u64, MapError> {
        self.0.get(&(WindowSize as u8), 0)
    }

    pub fn set_packet_limit(&mut self, packet_limit: u64) -> Result<(), MapError> {
        self.0.insert(PacketLimit as u8, packet_limit, 0)
    }

    pub fn set_window_size(&mut self, window_size: u64) -> Result<(), MapError> {
        self.0.insert(WindowSize as u8, window_size, 0)
    }
}

#[cfg(test)]
mod tests {
    use aya::Ebpf;
    use serial_test::serial;
    use toml::from_str;

    use crate::{Policy, ebpf::Init};

    #[serial]
    #[tokio::test]
    async fn apply_empty_policy_to_rate_limit_settings() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut rate_limit_settings = ebpf.rate_limit_settings().unwrap();
        let policy = "";
        let rate_limit_policy = from_str::<Policy>(policy).unwrap().rate_limit;

        rate_limit_settings.apply(rate_limit_policy);
        assert!(rate_limit_settings.get_packet_limit().is_err());
        assert!(rate_limit_settings.get_window_size().is_err());
    }

    #[serial]
    #[tokio::test]
    async fn apply_policy_to_rate_limit_settings() {
        let mut ebpf = Ebpf::init().unwrap();
        let mut rate_limit_settings = ebpf.rate_limit_settings().unwrap();
        let policy = "[rate_limit]\npacket_limit = \"0\"\nwindow_size = \"1\"";
        let rate_limit_policy = from_str::<Policy>(policy).unwrap().rate_limit;

        rate_limit_settings.apply(rate_limit_policy);
        assert_eq!(rate_limit_settings.get_packet_limit().unwrap(), 0);
        assert_eq!(rate_limit_settings.get_window_size().unwrap(), 1);
    }
}
