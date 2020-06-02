use clap::Clap;
use std::net;
use std::path;

#[derive(Clap)]
#[clap(
    version = "v0.1.0",
    about = "Redirect traffic to SOCKS proxy with pcap."
)]
pub struct Flags {
    #[clap(long, short, about = "Print verbose information")]
    pub verbose: bool,
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
    pub publish: Option<net::Ipv4Addr>,
    pub srcs: Vec<net::Ipv4Addr>,
    pub dst: net::SocketAddrV4,
}

impl Opts {
    /// Creates a new empty `Opts`.
    pub fn new() -> Opts {
        Opts {
            verbose: false,
            publish: None,
            srcs: vec![],
            dst: net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), 1080),
        }
    }

    /// Validates flags and creates a new `Opts`.
    pub fn validate(flags: &Flags) -> Result<Opts, String> {
        let verbose = flags.verbose;
        let mut publish = None;
        if let Some(p) = &flags.publish {
            match p.parse::<net::Ipv4Addr>() {
                Ok(addr) => {
                    if addr.is_unspecified() {
                        return Err(format!(
                            "validate publish {}: {}",
                            p, "IP address unspecified"
                        ));
                    }
                    publish = Some(addr);
                }
                Err(e) => return Err(format!("validate publish {}: {}", p, e)),
            }
        }
        let srcs: Vec<net::Ipv4Addr>;
        let s: Result<Vec<_>, _> = flags
            .srcs
            .iter()
            .map(|src| src.parse::<net::Ipv4Addr>())
            .collect();
        match s {
            Ok(s) => srcs = s,
            Err(e) => return Err(format!("validate sources: {}", e)),
        }
        for src in srcs.iter() {
            if src.is_unspecified() {
                return Err(format!(
                    "validate source {}: {}",
                    src, "IP address unspecified"
                ));
            }
        }
        let dst;
        match flags.dst.parse::<net::SocketAddrV4>() {
            Ok(addr) => {
                if addr.ip().is_unspecified() {
                    return Err(format!(
                        "validate destination {}: {}",
                        flags.dst, "IP address unspecified"
                    ));
                }
                dst = addr;
            }
            Err(e) => return Err(format!("validate destination {}: {}", flags.dst, e)),
        }

        return Ok(Opts {
            verbose: verbose,
            publish: publish,
            srcs: srcs,
            dst: dst,
        });
    }
}
