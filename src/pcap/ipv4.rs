use pnet::packet::ipv4::{self, Ipv4, Ipv4OptionPacket, Ipv4Packet, MutableIpv4Packet};

/// Creates an `Ipv4` according to the given IPv4 packet.
pub fn parse_ipv4(packet: &Ipv4Packet) -> Ipv4 {
    Ipv4 {
        version: packet.get_version(),
        header_length: packet.get_header_length(),
        dscp: packet.get_dscp(),
        ecn: packet.get_ecn(),
        total_length: packet.get_total_length(),
        identification: packet.get_identification(),
        flags: packet.get_flags(),
        fragment_offset: packet.get_fragment_offset(),
        ttl: packet.get_ttl(),
        next_level_protocol: packet.get_next_level_protocol(),
        checksum: packet.get_checksum(),
        source: packet.get_source(),
        destination: packet.get_destination(),
        options: packet.get_options(),
        payload: vec![],
    }
}

/// Serializes an IPv4 layer.
pub fn serialize_ipv4(layer: &Ipv4, n: usize, buffer: &mut [u8]) -> Result<usize, String> {
    let mut packet = match MutableIpv4Packet::new(buffer) {
        Some(packet) => packet,
        None => return Err(format!("connot serialize IPv4 layer")),
    };

    packet.populate(layer);
    let mut header_length = 20;
    for option in layer.options.iter() {
        header_length = header_length + Ipv4OptionPacket::packet_size(option);
    }
    packet.set_header_length((header_length / 4) as u8);
    packet.set_total_length((header_length + n) as u16);

    // Checksum
    let checksum = ipv4::checksum(&packet.to_immutable());
    packet.set_checksum(checksum);

    Ok(Ipv4Packet::packet_size(layer) + n)
}
