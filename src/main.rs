use log::{error, info};
use pcap2socks as lib;
use std::sync::{Arc, Mutex};

fn main() {
    // Parse arguments
    let flags = lib::args::parse();

    // Log
    lib::set_logger(&flags);

    // Validate arguments
    let opts = match lib::args::Opts::validate(&flags) {
        Ok(opts) => opts,
        Err(ref e) => {
            error!("{}", e);
            return;
        }
    };

    // Interface
    let inter = match lib::interface(opts.inter) {
        Some(inter) => inter,
        None => {
            println!("Cannot determine interface. Available interfaces are listed below, use -i <INTERFACE> to designate:");
            for inter in lib::interfaces().iter() {
                println!("    {}", inter);
            }
            return;
        }
    };
    info!("Listen on {}", inter);

    // Publish
    if let Some(publish) = opts.publish {
        info!("Publish {}", publish);
    }

    // Proxy
    info!("Proxy {} to {}", opts.src, opts.dst);
    let (tx, mut rx) = match inter.open() {
        Ok((tx, rx)) => (tx, rx),
        Err(ref e) => {
            error!("{}", e);
            return;
        }
    };
    let downstreamer = lib::Downstreamer::new(tx, inter.hardware_addr, opts.src, inter.ip_addrs[0]);
    let mut upstreamer = lib::Upstreamer::new(
        Arc::new(Mutex::new(downstreamer)),
        opts.src,
        opts.publish,
        opts.dst,
    );
    if let Err(ref e) = upstreamer.open(&mut rx) {
        error!("{}", e);
    }
}
