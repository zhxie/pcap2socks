use clap::{crate_description, crate_version, Clap};
use std::clone::Clone;
use std::net::{Ipv4Addr, SocketAddrV4};

/// Represents the flags of the application.
#[derive(Clap, Clone, Debug, Eq, Hash, PartialEq)]
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
    #[clap(long, about = "MTU", value_name = "VALUE", default_value = "1400")]
    pub mtu: u16,
    #[clap(long, short, about = "ARP publishing address", value_name = "ADDRESS")]
    pub publish: Option<Ipv4Addr>,
    #[clap(long = "source", short, about = "Source", value_name = "ADDRESS")]
    pub src: Ipv4Addr,
    #[clap(
        long = "destination",
        short,
        about = "Destination",
        value_name = "ADDRESS",
        default_value = "127.0.0.1:1080"
    )]
    pub dst: SocketAddrV4,
}

/// Parses the arguments.
pub fn parse() -> Flags {
    Flags::parse()
}
