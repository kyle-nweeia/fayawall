use std::net::Ipv4Addr;

use tracing::warn;

#[derive(Debug, PartialEq)]
pub struct Addr(pub Vec<Ipv4Addr>);

impl Addr {
    pub fn parse(args: &[&str]) -> Self {
        Self(
            args.iter()
                .filter_map(|arg| match arg.parse::<Ipv4Addr>() {
                    Ok(addr) => Some(addr),
                    Err(e) => {
                        warn!(r#""{arg}" could not be parsed into Ipv4Addr: {e}"#);
                        None
                    }
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invalid_addrs() {
        let result = Addr::parse(&["-1.0.0.0", "256.0.0.0"]);
        assert_eq!(result, Addr(vec![]));
    }

    #[test]
    fn parse_no_addr() {
        let result = Addr::parse(&[]);
        assert_eq!(result, Addr(vec![]));
    }

    #[test]
    fn parse_valid_addrs() {
        let result = Addr::parse(&["0.0.0.0", "255.255.255.255"]);
        let expected = Addr(vec![
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
        ]);

        assert_eq!(result, expected);
    }

    #[test]
    fn parse_valid_addr_and_invalid_addr() {
        let result = Addr::parse(&["127.0.0.1", "invalid"]);
        assert_eq!(result, Addr(vec![Ipv4Addr::new(127, 0, 0, 1)]));
    }
}
