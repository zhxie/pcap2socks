use clap::Clap;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};

pub mod args;

/// Parses arguments and returns a `Opts`.
pub fn parse() -> Result<args::Opts, String> {
    let flags = args::Flags::parse();

    match args::Opts::validate(&flags) {
        Ok(opts) => Ok(opts),
        Err(e) => Err(format!("{}", e)),
    }
}

pub mod pcap;

// Gets an available network iterface match the name.
pub fn interface(name: Option<String>) -> Result<pcap::Interface, String> {
    let mut inters = pcap::interfaces();
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

pub fn proxy(
    inter: pcap::Interface,
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
                            match pcap::ethernet::handle_ethernet_arp(
                                packet,
                                inter.hardware_addr,
                                &srcs,
                                &publish,
                                Arc::clone(&mutex_tx),
                            ) {
                                Ok(s) => {
                                    if !s.is_empty() {
                                        println!("{}", s);
                                    }
                                }
                                Err(e) => eprintln!("{}", e),
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
