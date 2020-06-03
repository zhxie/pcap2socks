use clap::Clap;

pub mod args;

/// Parses arguments and returns a `Opts`.
pub fn parse() -> Result<args::Opts, String> {
    let flags = args::Flags::parse();

    match args::Opts::validate(&flags) {
        Ok(opts) => Ok(opts),
        Err(e) => Err(format!("parse: {}", e)),
    }
}

pub mod pcap;
pub mod socks;

/// Get a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<pcap::Interface> {
    return pcap::interfaces();
}
