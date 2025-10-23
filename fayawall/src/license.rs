#![cfg(all(feature = "license", not(test)))]

use std::{fmt::Debug, fs::read_to_string};

use anyhow::anyhow;
use clap::Parser;
use licensegate_rs::{LicenseGate, ValidationType, licensegate_config::LicenseGateConfig};
use serde::Deserialize;
use toml::from_str;
use tracing::{error, info};

use crate::arg::Arg;

const USER_ID: &str = "a213a";

#[derive(Deserialize)]
pub struct License {
    key: String,
}

impl License {
    fn error<T: Debug>(msg: &str, e: T) -> anyhow::Result<()> {
        let msg = format!("{msg}: {e:?}");

        error!(msg);

        Err(anyhow!(msg))
    }

    pub async fn verify() -> anyhow::Result<()> {
        let license_file = &Arg::parse().license;

        info!("Verifying license key in `{license_file}`");

        match read_to_string(license_file) {
            Ok(ref license) => match from_str(license) {
                Ok(Self { key }) => {
                    match LicenseGate::new(USER_ID)
                        .verify(LicenseGateConfig::new(key))
                        .await
                    {
                        Ok(ValidationType::Valid) => {
                            info!("License key verified");
                            Ok(())
                        }

                        Ok(e) => Self::error("License key is invalid", e),

                        Err(e) => Self::error("Connection to license server failed", e),
                    }
                }

                Err(e) => Self::error("License file not parsed", e),
            },

            Err(e) => Self::error("License file not found", e),
        }
    }
}
