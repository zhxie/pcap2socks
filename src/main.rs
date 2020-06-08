use log::{error, info};
use pcap2socks as lib;

fn main() {
    // Parse arguments
    let flags = lib::parse();

    // Validate arguments
    let opts = match lib::validate(&flags) {
        Ok(opts) => opts,
        Err(ref e) => {
            error!("cannot parse arguements: {}", e);
            return;
        }
    };

    // Log
    lib::set_logger(&flags);

    // Interface
    let inter = match lib::interface(opts.inter) {
        Ok(inter) => inter,
        Err(ref e) => {
            error!("cannot determine interface: {}", e);
            println!();

            println!("Available interfaces are listed below, use -i <INTERFACE> to designate:");
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
    if let Err(e) = lib::proxy(&inter, opts.publish, opts.src, opts.dst) {
        error!("proxy: {}", e);
        return;
    }
}
