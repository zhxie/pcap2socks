use clap::{crate_description, crate_version, Clap};
use std::net::{Ipv4Addr, SocketAddrV4};

#[derive(Clap)]
#[clap(
    version = crate_version!(),
    about = crate_description!()
)]
pub struct Flags {
    #[clap(long, short, about = "Prints verbose information")]
    pub verbose: bool,
    #[clap(long, short = "V", about = "Prints vverbose information")]
    pub vverbose: bool,
    #[clap(
        long = "interface",
        short,
        about = "Interface for listening",
        value_name = "INTERFACE"
    )]
    pub inter: Option<String>,
    #[clap(long, short, about = "ARP publishing address", value_name = "ADDRESS")]
    pub publish: Option<String>,
    #[clap(long = "source", short, about = "Source", value_name = "ADDRESS")]
    pub src: String,
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
    pub vverbose: bool,
    pub inter: Option<String>,
    pub publish: Option<Ipv4Addr>,
    pub src: Ipv4Addr,
    pub dst: SocketAddrV4,
}

impl Opts {
    /// Creates a new empty `Opts`.
    pub fn new() -> Opts {
        Opts {
            verbose: false,
            vverbose: false,
            inter: None,
            publish: None,
            src: Ipv4Addr::UNSPECIFIED,
            dst: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        }
    }

    /// Validates flags and creates a new `Opts`.
    pub fn validate(flags: &Flags) -> Result<Opts, String> {
        let verbose = flags.verbose;
        let vverbose = flags.vverbose;
        let mut publish = None;
        if let Some(p) = &flags.publish {
            publish = match p.parse::<Ipv4Addr>() {
                Ok(publish) => {
                    if publish.is_unspecified() {
                        return Err(format!("publish {} is an unspecified IP address", p));
                    }
                    Some(publish)
                }
                Err(e) => return Err(format!("parse publish {}: {}", p, e)),
            };
        }
        let src = match flags.src.parse::<Ipv4Addr>() {
            Ok(addr) => {
                if addr.is_unspecified() {
                    return Err(format!("source {} is an unspecified IP address", addr));
                }
                addr
            }
            Err(e) => return Err(format!("parse source {}: {}", flags.src, e)),
        };
        let dst = match flags.dst.parse::<SocketAddrV4>() {
            Ok(addr) => {
                if addr.ip().is_unspecified() {
                    return Err(format!(
                        "destination {} is an unspecified IP address",
                        addr.ip()
                    ));
                }
                addr
            }
            Err(e) => return Err(format!("parse destination {}: {}", flags.dst, e)),
        };

        Ok(Opts {
            verbose,
            vverbose,
            inter: flags.inter.clone(),
            publish,
            src,
            dst,
        })
    }
}
