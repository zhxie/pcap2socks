use pnet::datalink::MacAddr;
use pnet::packet::arp::{ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, Ethernet, EthernetPacket};
use pnet::packet::Packet;

pub mod arp;

pub fn handle_ethernet(packet: EthernetPacket, hardware_addr: MacAddr) -> Result<Ethernet, String> {
    match packet.get_ethertype() {
        EtherTypes::Arp => match ArpPacket::new(packet.payload()) {
            Some(arp_packet) => {
                let arp = arp::handle_arp(arp_packet, hardware_addr);
                let mut new_arp_buffer = [0u8; 28];
                let mut new_arp_packet = MutableArpPacket::new(&mut new_arp_buffer).unwrap();
                new_arp_packet.populate(&arp);

                let ethernet = Ethernet {
                    destination: packet.get_source(),
                    source: hardware_addr,
                    ethertype: EtherTypes::Arp,
                    payload: new_arp_buffer.to_vec(),
                };
                return Ok(ethernet);
            }
            None => Err(format!("invalid ARP packet")),
        },
        t => Err(format!("unhandled ethernet type: {}", t)),
    }
}
