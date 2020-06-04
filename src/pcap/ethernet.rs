use pnet::datalink::DataLinkSender;
use pnet::datalink::MacAddr;
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, Ethernet, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

pub mod arp;

/// Creates an `Ethernet` with the reverse flow of the given Ethernet packet.
pub fn reverse_ethernet(packet: &EthernetPacket) -> Ethernet {
    Ethernet {
        destination: packet.get_source(),
        source: packet.get_destination(),
        ethertype: packet.get_ethertype(),
        payload: vec![],
    }
}

/// Serialize an Ethernet layer.
pub fn serialize_ethernet(ethernet: &Ethernet, buffer: &mut [u8]) -> Result<(), String> {
    let mut ethernet_packet = match MutableEthernetPacket::new(buffer) {
        Some(packet) => packet,
        None => return Err(format!("cannot serialize Ethernet layer")),
    };

    ethernet_packet.populate(ethernet);

    Ok(())
}

/// Handles Ethernet ARP packet.
pub fn handle_ethernet_arp(
    packet: EthernetPacket,
    hardware_addr: MacAddr,
    src: &Ipv4Addr,
    dst: &Ipv4Addr,
    tx: Arc<Mutex<Box<dyn DataLinkSender>>>,
) -> Result<String, String> {
    let arp_packet = match packet.get_ethertype() {
        EtherTypes::Arp => match ArpPacket::new(packet.payload()) {
            Some(arp_packet) => arp_packet,
            None => return Err(format!("invalid ARP packet")),
        },
        t => return Err(format!("unhandled Ethernet type {}", t)),
    };

    if src != &arp_packet.get_sender_proto_addr() || dst != &arp_packet.get_target_proto_addr() {
        return Ok(String::new());
    }

    let arp = match arp_packet.get_operation() {
        ArpOperations::Request => arp::reply_arp(&arp_packet, hardware_addr),
        _ => return Ok(String::new()),
    };

    let mut ethernet = reverse_ethernet(&packet);
    ethernet.source = hardware_addr;

    let mut new_ethernet_buffer = [0u8; 42];
    if let Err(e) = serialize_ethernet(&ethernet, &mut new_ethernet_buffer[..14]) {
        return Err(format!("{}", e));
    }
    if let Err(e) = arp::serialize_arp(&arp, &mut new_ethernet_buffer[14..]) {
        return Err(format!("{}", e));
    }

    match (*tx.lock().unwrap()).send_to(&new_ethernet_buffer, None) {
        Some(result) => match result {
            Ok(_) => Ok(format!(
                "Reply ARP Request: {} <- {}",
                arp.target_proto_addr, arp.sender_proto_addr
            )),
            Err(e) => Err(format!("send: {}", e)),
        },
        None => Ok(String::new()),
    }
}
