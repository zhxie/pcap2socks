use pcap2socks;

fn main() {
    // Parse arguments
    let opts = match pcap2socks::parse() {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("{}", &e);
            return;
        }
    };

    // Interfaces
    let mut inters = pcap2socks::interfaces();
    if inters.len() <= 0 {
        eprintln!("No available interface.");
        return;
    }
    let inter;
    if inters.len() > 1 {
        if let None = opts.inter {
            eprintln!("Available interfaces are listed below, use -i <INTERFACE> to designate.");
            return;
        }
    }
    if let Some(inter) = opts.inter {
        inters.retain(|current_inter| current_inter.name == inter);
        if inters.len() <= 0 {
            eprintln!("Unknown interface {}.", inter);
            return;
        }
    }
    inter = inters[0].clone();
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
}
