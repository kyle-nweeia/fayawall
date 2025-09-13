use log::LevelFilter::Info;
use std::io::stdout;
use tracing::Level;
use tracing::subscriber::set_global_default;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_log::LogTracer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::Layer;
use tracing_subscriber::{Registry, prelude::*};

pub fn init() -> anyhow::Result<WorkerGuard> {
    let file_appender = tracing_appender::rolling::never(".", "firewall.log");
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = Layer::default().with_ansi(false).with_writer(file_writer);
    let stdout_layer = Layer::default()
        .with_level(false)
        .with_target(false)
        .with_writer(stdout)
        .without_time()
        .with_filter(Targets::new().with_targets(vec![
            ("firewall", Level::INFO),
            ("firewall::ipv4", Level::INFO),
        ]));
    let subscriber = Registry::default().with(file_layer).with(stdout_layer);

    LogTracer::builder().with_max_level(Info).init()?;
    set_global_default(subscriber)?;

    Ok(guard)
}
