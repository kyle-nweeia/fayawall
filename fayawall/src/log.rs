use std::io::stdout;

use log::LevelFilter::Info;
use tracing::{Level, subscriber::set_global_default};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_log::LogTracer;
use tracing_subscriber::{Registry, filter::Targets, fmt::Layer, prelude::*};

pub struct Log;

impl Log {
    pub fn init() -> anyhow::Result<WorkerGuard> {
        let file_appender = tracing_appender::rolling::never(".", "fayawall.log");
        let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
        let file_layer = Layer::default().with_ansi(false).with_writer(file_writer);
        let stdout_layer = Layer::default()
            .with_level(false)
            .with_target(false)
            .with_writer(stdout)
            .without_time()
            .with_filter(Targets::new().with_target("fayawall::", Level::INFO));
        let subscriber = Registry::default().with(file_layer).with(stdout_layer);

        LogTracer::builder().with_max_level(Info).init()?;
        set_global_default(subscriber)?;

        Ok(guard)
    }
}
