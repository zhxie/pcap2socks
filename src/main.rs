use log::{error, info};
use pcap2socks as lib;

fn main() {
    // Parse arguments
    let flags = lib::parse();

    // Validate arguments
    let opts = match lib::validate(&flags) {
        Ok(opts) => opts,
        Err(e) => {
            error!("parse: {}", e);
            return;
        }
    };

    // Log
    lib::set_logger(&flags);

    // Interfaces
    let inter = match lib::interface(opts.inter) {
        Ok(inter) => inter,
        Err(e) => {
            lib::enumerate_interfaces();
            error!("parse: {}", e);
            return;
        }
    };
    info!("Listen on {}", inter);

    // Publish
    if let Some(publish) = opts.publish {
        info!("Publish {}", publish);
    }

    // Proxy
    match opts.srcs.len() {
        0 => info!("Proxy to {}", opts.dst),
        _ => {
            let ip_addrs = format!(
                "{}",
                opts.srcs
                    .iter()
                    .map(|src| { src.to_string() })
                    .collect::<Vec<String>>()
                    .join(", ")
            );

            info!("Proxy {} to {}", ip_addrs, opts.dst);
        }
    }

    // Start proxying
    if let Err(e) = lib::proxy(inter, opts.publish, opts.srcs, opts.dst) {
        error!("proxy: {}", e);
        return;
    }
}
