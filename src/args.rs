use clap::Clap;
use std::net::{Ipv4Addr, SocketAddrV4};

#[derive(Clap)]
#[clap(
    version = "v0.1.0",
    about = "Redirect traffic to SOCKS proxy with pcap."
)]
pub struct Flags {
    #[clap(long, short, about = "Print verbose information")]
    pub verbose: bool,
    #[clap(
        long = "interface",
        short,
        about = "Interface for listening",
        value_name = "INTERFACE"
    )]
    pub inter: Option<String>,
    #[clap(long, short, about = "ARP publishing address", value_name = "ADDRESS")]
    pub publish: Option<String>,
    #[clap(long = "sources", short, about = "Sources", value_name = "ADDRESS")]
    pub srcs: Vec<String>,
    #[clap(
        long = "destination",
        short,
        about = "Destination",
        value_name = "ADDRESS"
    )]
    pub dst: String,
}

pub struct Opts {
    pub verbose: bool,
    pub inter: Option<String>,
    pub publish: Option<Ipv4Addr>,
    pub srcs: Vec<Ipv4Addr>,
    pub dst: SocketAddrV4,
}

impl Opts {
    /// Creates a new empty `Opts`.
    pub fn new() -> Opts {
        Opts {
            verbose: false,
            inter: None,
            publish: None,
            srcs: vec![],
            dst: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1080),
        }
    }

    /// Validates flags and creates a new `Opts`.
    pub fn validate(flags: &Flags) -> Result<Opts, String> {
        let verbose = flags.verbose;
        let mut publish = None;
        if let Some(p) = &flags.publish {
            publish = match p.parse::<Ipv4Addr>() {
                Ok(publish) => {
                    if publish.is_unspecified() {
                        return Err(format!(
                            "validate publish {}: {}",
                            p, "unspecified IP address"
                        ));
                    }
                    Some(publish)
                }
                Err(e) => return Err(format!("validate publish {}: {}", p, e)),
            };
        }
        let srcs: Result<Vec<_>, _> = flags
            .srcs
            .iter()
            .map(|src| src.parse::<Ipv4Addr>())
            .collect();
        let srcs = match srcs {
            Ok(src) => src,
            Err(e) => return Err(format!("validate sources: {}", e)),
        };
        for src in srcs.iter() {
            if src.is_unspecified() {
                return Err(format!(
                    "validate source {}: {}",
                    src, "unspecified IP address"
                ));
            }
        }
        let dst = match flags.dst.parse::<SocketAddrV4>() {
            Ok(addr) => {
                if addr.ip().is_unspecified() {
                    return Err(format!(
                        "validate destination {}: {}",
                        flags.dst, "unspecified IP address"
                    ));
                }
                addr
            }
            Err(e) => return Err(format!("validate destination {}: {}", flags.dst, e)),
        };

        Ok(Opts {
            verbose: verbose,
            inter: flags.inter.clone(),
            publish: publish,
            srcs: srcs,
            dst: dst,
        })
    }
}
