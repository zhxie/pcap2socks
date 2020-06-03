use pnet::datalink::MacAddr;
use pnet::packet::arp::{Arp, ArpHardwareTypes, ArpOperations, ArpPacket};
use pnet::packet::ethernet::EtherTypes;

pub fn handle_arp(packet: ArpPacket, hardware_addr: MacAddr) -> Arp {
    Arp {
        hardware_type: ArpHardwareTypes::Ethernet,
        protocol_type: EtherTypes::Ipv4,
        hw_addr_len: 6,
        proto_addr_len: 4,
        operation: ArpOperations::Reply,
        sender_hw_addr: hardware_addr,
        sender_proto_addr: packet.get_target_proto_addr(),
        target_hw_addr: packet.get_sender_hw_addr(),
        target_proto_addr: packet.get_sender_proto_addr(),
        payload: vec![],
    }
}
