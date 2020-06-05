use pnet::packet::ethernet::{Ethernet, EthernetPacket, MutableEthernetPacket};

/// Creates an `Ethernet` according to the given Ethernet packet.
pub fn parse_ethernet(packet: &EthernetPacket) -> Ethernet {
    Ethernet {
        destination: packet.get_destination(),
        source: packet.get_source(),
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
