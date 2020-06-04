use pnet::packet::ipv4::{self, Ipv4, Ipv4Packet, MutableIpv4Packet};

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
pub fn serialize_ipv4(ipv4: &Ipv4, buffer: &mut [u8]) -> Result<(), String> {
    let mut ipv4_packet = match MutableIpv4Packet::new(buffer) {
        Some(packet) => packet,
        None => return Err(format!("connot serialize IPv4 layer")),
    };

    ipv4_packet.populate(ipv4);

    // Checksum
    let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);

    Ok(())
}
