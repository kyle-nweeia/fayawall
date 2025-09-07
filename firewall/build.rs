use anyhow::{Context, anyhow};
use aya_build::cargo_metadata::{Metadata, MetadataCommand, Package};

fn main() -> anyhow::Result<()> {
    let Metadata { packages, .. } = MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_pkg = packages
        .into_iter()
        .find(|Package { name, .. }| name == "firewall-ebpf")
        .ok_or_else(|| anyhow!("firewall-ebpf package not found"))?;

    aya_build::build_ebpf([ebpf_pkg])
}
