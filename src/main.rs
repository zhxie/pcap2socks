use log::{error, info};
use std::sync::{Arc, Mutex};

use lib::args::{self, Opts};
use lib::{Forwarder, Redirector};
use pcap2socks as lib;

fn main() {
    // Parse arguments
    let flags = args::parse();

    // Log
    lib::set_logger(&flags);

    // Validate arguments
    let opts = match Opts::validate(&flags) {
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
    info!("Break packets with MTU {}", opts.mtu);

    // Publish
    if let Some(publish) = opts.publish {
        info!("Publish for {}", publish);
    }

    // Instructions
    lib::show_info(
        opts.src,
        opts.publish.unwrap_or(inter.ip_addrs[0]),
        opts.mtu,
    );

    // Proxy
    let (tx, mut rx) = match inter.open() {
        Ok((tx, rx)) => (tx, rx),
        Err(ref e) => {
            error!("{}", e);
            return;
        }
    };
    let forwarder = Forwarder::new(
        tx,
        opts.mtu,
        inter.hardware_addr,
        opts.src,
        inter.ip_addrs[0],
    );
    let mut redirector = Redirector::new(
        Arc::new(Mutex::new(forwarder)),
        opts.src,
        opts.publish,
        opts.dst,
    );
    info!("Proxy {} to {}", opts.src, opts.dst);
    if let Err(ref e) = redirector.open(&mut rx) {
        error!("{}", e);
    }
}
