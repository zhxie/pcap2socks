use log::{error, info};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use lib::args;
use lib::{Forwarder, Redirector};
use pcap2socks as lib;

#[tokio::main]
async fn main() {
    // Parse arguments
    let flags = args::parse();

    // Log
    lib::set_logger(&flags);

    // Interface
    let inter = match lib::interface(flags.inter) {
        Some(inter) => inter,
        None => {
            error!("Cannot determine interface. Available interfaces are listed below, use -i <INTERFACE> to designate:");
            for inter in lib::interfaces().iter() {
                info!("    {}", inter);
            }
            return;
        }
    };
    info!("Listen on {}", inter);
    info!("Break packets with MTU {}", flags.mtu);

    // Publish
    if let Some(publish) = flags.publish {
        info!("Publish for {}", publish);
    }

    // Instructions
    show_info(
        flags.src,
        flags.publish.unwrap_or(inter.ip_addrs[0]),
        flags.mtu,
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
        flags.mtu,
        inter.hardware_addr,
        flags.src,
        inter.ip_addrs[0],
    );
    let mut redirector = Redirector::new(
        Arc::new(Mutex::new(forwarder)),
        flags.src,
        flags.publish,
        flags.dst,
    );
    info!("Proxy {} to {}", flags.src, flags.dst);
    if let Err(ref e) = redirector.open(&mut rx).await {
        error!("{}", e);
    }
}

fn show_info(ip_addr: Ipv4Addr, gateway: Ipv4Addr, mtu: u16) {
    let ip_addr_octets = ip_addr.octets();
    let gateway_octets = gateway.octets();
    let mask = Ipv4Addr::new(
        !(ip_addr_octets[0] ^ gateway_octets[0]),
        !(ip_addr_octets[1] ^ gateway_octets[1]),
        !(ip_addr_octets[2] ^ gateway_octets[2]),
        0,
    );
    info!("Please set the network of your device which is going to be proxied with the following parameters:");
    info!("    ┌─{:─<10}─{:─>15}─┐", "", "");
    info!("    │ {:<10} {:>15} │", "IP Address", ip_addr);
    info!("    │ {:<10} {:>15} │", "Mask", mask);
    info!("    │ {:<10} {:>15} │", "Gateway", gateway);
    info!("    │─{:─<10}─{:─>15}─│", "", "");
    info!("    │ {:<10} {:>15} │", "MTU", mtu);
    info!("    └─{:─<10}─{:─>15}─┘", "", "");
}
