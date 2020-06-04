use pnet::packet::udp::{self, MutableUdpPacket, Udp, UdpPacket};
use std::net::Ipv4Addr;

/// Creates an `Udp` according to the given UDP packet.
pub fn parse_udp(packet: &UdpPacket) -> Udp {
    Udp {
        source: packet.get_source(),
        destination: packet.get_destination(),
        length: packet.get_length(),
        checksum: packet.get_checksum(),
        payload: vec![],
    }
}

/// Serializes an UDP layer in IPv4.
pub fn serialize_ipv4_udp(
    udp: &Udp,
    src: &Ipv4Addr,
    dst: &Ipv4Addr,
    buffer: &mut [u8],
) -> Result<(), String> {
    let mut udp_packet = match MutableUdpPacket::new(buffer) {
        Some(packet) => packet,
        None => return Err(format!("connot serialize UDP layer")),
    };

    udp_packet.populate(udp);

    // Checksum
    let checksum = udp::ipv4_checksum(&udp_packet.to_immutable(), src, dst);
    udp_packet.set_checksum(checksum);

    Ok(())
}
