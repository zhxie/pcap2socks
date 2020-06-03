use pcap2socks as p;

fn main() {
    // Parse arguments
    let opts = match p::parse() {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("parse: {}", e);
            return;
        }
    };

    // Interfaces
    let inter = match p::interface(opts.inter) {
        Ok(inter) => inter,
        Err(e) => {
            println!("Available interfaces are listed below, use -i <INTERFACE> to designate:");
            for inter in p::pcap::interfaces().iter() {
                println!("  {}", inter);
            }
            eprintln!("select interface: {}", e);
            return;
        }
    };
    println!("Listen on {}", inter);

    // Publish
    if let Some(publish) = opts.publish {
        println!("Publish {}", publish);
    }

    // Proxy
    match opts.srcs.len() {
        0 => println!("Proxy to {}", opts.dst),
        _ => {
            let ip_addrs = format!(
                "{}",
                opts.srcs
                    .iter()
                    .map(|src| { src.to_string() })
                    .collect::<Vec<String>>()
                    .join(", ")
            );

            println!("Proxy {} to {}", ip_addrs, opts.dst)
        }
    }

    // Start proxying
    if let Err(e) = p::proxy(inter, opts.publish, opts.srcs, opts.dst) {
        eprintln!("proxy: {}", e);
        return;
    }
}
