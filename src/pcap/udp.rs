use pnet::packet::ipv4::Ipv4;
use pnet::packet::udp::{self, MutableUdpPacket, Udp, UdpPacket};

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

/// Serializes an `Udp` with `Ipv4`.
pub fn serialize_ipv4_udp(
    layer: &Udp,
    ipv4_layer: &Ipv4,
    n: usize,
    buffer: &mut [u8],
) -> Result<usize, String> {
    let mut udp_packet = match MutableUdpPacket::new(buffer) {
        Some(packet) => packet,
        None => return Err(format!("connot serialize UDP layer")),
    };

    udp_packet.populate(layer);

    // Checksum
    let checksum = udp::ipv4_checksum(
        &udp_packet.to_immutable(),
        &ipv4_layer.source,
        &ipv4_layer.destination,
    );
    udp_packet.set_checksum(checksum);

    Ok(UdpPacket::packet_size(layer) + n)
}
