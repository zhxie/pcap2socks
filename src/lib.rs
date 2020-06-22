pub mod args;
pub mod cacher;
pub mod downstreamer;
pub mod packet;
pub mod pcap;
pub mod socks;
pub mod upstreamer;

mod datagram_worker;
mod stream_worker;

use log::info;
use pcap::Interface;
use std::io::Write;
use std::net::Ipv4Addr;

pub use downstreamer::Downstreamer;
pub use upstreamer::Upstreamer;

/// Represents the wait time after a `TimedOut` `IoError`.
const TIMEDOUT_WAIT: u64 = 20;

/// Represents the max distance of `u32` values between packets in an `u32` window.
const MAX_U32_WINDOW_SIZE: usize = 256 * 1024;

/// Represents the minimum packet size.
/// Because all traffic is in Ethernet, and the 802.3 specifies the minimum is 64 Bytes.
/// Exclude the 4 bytes used in FCS, the minimum packet size in pcap2socks is 60 Bytes.
const MINIMUM_PACKET_SIZE: usize = 60;

/// Sets the logger.
pub fn set_logger(flags: &args::Flags) {
    use env_logger::fmt::{Color, Target};
    use log::{Level, LevelFilter};

    let level = match &flags.vverbose {
        true => LevelFilter::Trace,
        false => match flags.verbose {
            true => LevelFilter::Debug,
            false => LevelFilter::Info,
        },
    };
    env_logger::builder()
        .target(Target::Stdout)
        .filter_level(level)
        .format(|buf, record| {
            let mut style = buf.style();

            let level = match &record.level() {
                Level::Error => style.set_bold(true).set_color(Color::Red).value("error: "),
                Level::Warn => style
                    .set_bold(true)
                    .set_color(Color::Yellow)
                    .value("warning: "),
                Level::Info => style.set_bold(true).set_color(Color::Green).value(""),
                _ => style.set_color(Color::Rgb(165, 165, 165)).value(""),
            };
            writeln!(buf, "{}{}", level, record.args())
        })
        .init();
}

/// Gets a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<Interface> {
    pcap::interfaces()
        .into_iter()
        .filter(|inter| !inter.is_loopback)
        .collect()
}

/// Gets a list of available network interfaces which is possibly can be used for the current machine.
fn auto_interfaces() -> Vec<Interface> {
    // With specified IP address
    let mut inters: Vec<Interface> = interfaces()
        .into_iter()
        .filter(|inter| !inter.ip_addrs[0].is_unspecified())
        .collect();
    // Is up
    if inters.len() > 1 {
        inters = inters.into_iter().filter(|inter| inter.is_up).collect();
    }

    inters
}

/// Gets an available network interface match the name.
pub fn interface(name: Option<String>) -> Option<Interface> {
    let inters = match name {
        Some(name) => {
            let mut inters = interfaces();
            inters.retain(|current_inter| current_inter.name == name);
            inters
        }
        None => auto_interfaces(),
    };

    if inters.len() != 1 {
        None
    } else {
        Some(inters[0].clone())
    }
}

/// Prints the dialog with information how to set up the proxied device.
pub fn show_info(ip_addr: Ipv4Addr, gateway: Ipv4Addr, mtu: u16) {
    let ip_addr_octets = ip_addr.octets();
    let gateway_octets = gateway.octets();
    let mask = Ipv4Addr::new(
        !(ip_addr_octets[0] ^ gateway_octets[0]),
        !(ip_addr_octets[1] ^ gateway_octets[1]),
        !(ip_addr_octets[2] ^ gateway_octets[2]),
        0,
    );
    info!("Please set the network of your device which is going to be proxied with the following parameters:");
    info!("  ┌─{:─<10}─{:─>15}─┐", "", "");
    info!("  │ {:<10} {:>15} │", "IP Address", ip_addr);
    info!("  │ {:<10} {:>15} │", "Mask", mask);
    info!("  │ {:<10} {:>15} │", "Gateway", gateway);
    info!("  │─{:─<10}─{:─>15}─│", "", "");
    info!("  │ {:<10} {:>15} │", "MTU", mtu);
    info!("  └─{:─<10}─{:─>15}─┘", "", "");
}
