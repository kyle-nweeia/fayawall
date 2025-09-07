use std::fs::File;

pub fn init() -> std::io::Result<()> {
    let log = File::create("firewall.log")?;
    let bx = Box::new(log);
    let tgt = env_logger::Target::Pipe(bx);

    env_logger::builder().target(tgt).init();

    Ok(())
}
