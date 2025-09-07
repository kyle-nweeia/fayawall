use anyhow::anyhow;
use which::which;

fn main() -> anyhow::Result<()> {
    println!(
        "cargo:rerun-if-changed={}",
        which("bpf-linker")?
            .to_str()
            .ok_or(anyhow!("`Path` is not valid UTF-8"))?
    );

    Ok(())
}
