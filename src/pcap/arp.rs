use pnet::datalink::MacAddr;
use pnet::packet::arp::{Arp, ArpOperations, ArpPacket, MutableArpPacket};

/// Creates an `Arp` according to the given ARP packet.
pub fn parse_arp(packet: &ArpPacket) -> Arp {
    Arp {
        hardware_type: packet.get_hardware_type(),
        protocol_type: packet.get_protocol_type(),
        hw_addr_len: packet.get_hw_addr_len(),
        proto_addr_len: packet.get_proto_addr_len(),
        operation: packet.get_operation(),
        sender_hw_addr: packet.get_sender_hw_addr(),
        sender_proto_addr: packet.get_sender_proto_addr(),
        target_hw_addr: packet.get_target_hw_addr(),
        target_proto_addr: packet.get_target_proto_addr(),
        payload: vec![],
    }
}

/// Creates a ARP reply according to a given `Arp`.
pub fn reply_arp(layer: &Arp, hardware_addr: MacAddr) -> Arp {
    Arp {
        hardware_type: layer.hardware_type,
        protocol_type: layer.protocol_type,
        hw_addr_len: layer.hw_addr_len,
        proto_addr_len: layer.proto_addr_len,
        operation: ArpOperations::Reply,
        sender_hw_addr: hardware_addr,
        sender_proto_addr: layer.target_proto_addr,
        target_hw_addr: layer.sender_hw_addr,
        target_proto_addr: layer.sender_proto_addr,
        payload: vec![],
    }
}

/// Serializes an `Arp`.
pub fn serialize_arp(layer: &Arp, n: usize, buffer: &mut [u8]) -> Result<usize, String> {
    let mut packet = match MutableArpPacket::new(buffer) {
        Some(packet) => packet,
        None => return Err(format!("cannot serialize ARP layer")),
    };

    packet.populate(layer);

    Ok(ArpPacket::packet_size(layer) + n)
}
