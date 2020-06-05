use pnet::packet::arp::Arp;
use pnet::packet::ethernet::{EtherTypes, Ethernet, EthernetPacket, MutableEthernetPacket};

/// Creates an `Ethernet` according to the given Ethernet packet.
pub fn parse_ethernet(packet: &EthernetPacket) -> Ethernet {
    Ethernet {
        destination: packet.get_destination(),
        source: packet.get_source(),
        ethertype: packet.get_ethertype(),
        payload: vec![],
    }
}

/// Creates an `Ethernet` according to the given `Arp`.
pub fn create_ethernet_arp(arp: &Arp) -> Ethernet {
    Ethernet {
        destination: arp.target_hw_addr,
        source: arp.sender_hw_addr,
        ethertype: EtherTypes::Arp,
        payload: vec![],
    }
}

/// Serialize an `Ethernet`.
pub fn serialize_ethernet(ethernet: &Ethernet, buffer: &mut [u8]) -> Result<(), String> {
    let mut ethernet_packet = match MutableEthernetPacket::new(buffer) {
        Some(packet) => packet,
        None => return Err(format!("cannot serialize Ethernet layer")),
    };

    ethernet_packet.populate(ethernet);

    Ok(())
}
