use log::{error, info};
use pcap2socks as lib;

fn main() {
    // Parse arguments
    let flags = lib::parse();

    // Log
    lib::set_logger(&flags);

    // Validate arguments
    let opts = match lib::validate(&flags) {
        Ok(opts) => opts,
        Err(ref e) => {
            error!("parse: {}", e);
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
    let (mut proxy, mut rx) = match lib::Proxy::open(&inter, opts.publish, opts.src, opts.dst) {
        Ok(p) => p,
        Err(ref e) => {
            error!("proxy: {}", e);
            return;
        }
    };
    if let Err(ref e) = proxy.handle(&mut rx) {
        error!("proxy: {}", e);
    }
}
