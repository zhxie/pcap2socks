use clap::Clap;
use log::{info, warn};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};

pub mod args;

/// Parses arguments and returns a `Flags`.
pub fn parse() -> args::Flags {
    args::Flags::parse()
}

/// Sets the logger.
pub fn set_logger(flags: &args::Flags) {
    let level = match flags.verbose {
        true => log::LevelFilter::Debug,
        false => log::LevelFilter::Info,
    };
    env_logger::builder()
        .format_level(false)
        .format_module_path(false)
        .format_timestamp(None)
        .filter_level(level)
        .init();
}

/// Validate arguments and returns an `Opts`.
pub fn validate(flags: &args::Flags) -> Result<args::Opts, String> {
    match args::Opts::validate(flags) {
        Ok(opts) => Ok(opts),
        Err(e) => Err(format!("{}", e)),
    }
}

pub mod pcap;
use pcap::ethernet;
use pcap::interface::{self, Interface};

// Gets an available network iterface match the name.
pub fn interface(name: Option<String>) -> Result<Interface, String> {
    let mut inters = interface::interfaces();
    if inters.len() <= 0 {
        return Err(String::from("no available interface"));
    }
    if inters.len() > 1 {
        if let None = name {
            return Err(String::from("multiple available interfaces"));
        }
    }
    if let Some(inter_name) = name {
        inters.retain(|current_inter| current_inter.name == inter_name);
        if inters.len() <= 0 {
            return Err(format!("unknown interface {}", inter_name));
        }
    }
    Ok(inters[0].clone())
}

// Enumerates and prints all available network interfaces.
pub fn enumerate_interfaces() {
    let inters = interface::interfaces();
    info!("Available interfaces are listed below, use -i <INTERFACE> to designate:");
    for inter in inters.iter() {
        info!("  {}", inter);
    }
}

pub fn proxy(
    inter: Interface,
    publish: Option<Ipv4Addr>,
    srcs: Vec<Ipv4Addr>,
    dst: SocketAddrV4,
) -> Result<(), String> {
    let (tx, mut rx) = match inter.open() {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => return Err(format!("open: {}", e)),
    };
    let mutex_tx = Arc::new(Mutex::new(tx));

    // Handle received
    loop {
        match rx.next() {
            Ok(frame) => {
                let packet = EthernetPacket::new(frame).unwrap();
                match packet.get_ethertype() {
                    EtherTypes::Arp => {
                        if let Some(publish) = publish {
                            match ethernet::handle_ethernet_arp(
                                packet,
                                inter.hardware_addr,
                                &srcs,
                                &publish,
                                Arc::clone(&mutex_tx),
                            ) {
                                Ok(s) => {
                                    if !s.is_empty() {
                                        info!("{}", s);
                                    }
                                }
                                Err(e) => warn!("{}", e),
                            };
                        }
                    }
                    _ => continue,
                };
            }
            Err(e) => {
                if e.kind() != ErrorKind::TimedOut {
                    return Err(format!("receive: {}", e));
                }
            }
        }
    }
}
