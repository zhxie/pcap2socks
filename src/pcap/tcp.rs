use pnet::packet::tcp::{self, MutableTcpPacket, Tcp, TcpPacket};
use std::net::Ipv4Addr;

/// Creates an `Tcp` according to the given TCP packet.
pub fn parse_tcp(packet: &TcpPacket) -> Tcp {
    Tcp {
        source: packet.get_source(),
        destination: packet.get_destination(),
        sequence: packet.get_sequence(),
        acknowledgement: packet.get_acknowledgement(),
        data_offset: packet.get_data_offset(),
        reserved: packet.get_reserved(),
        flags: packet.get_flags(),
        window: packet.get_window(),
        checksum: packet.get_checksum(),
        urgent_ptr: packet.get_urgent_ptr(),
        options: packet.get_options(),
        payload: vec![],
    }
}

/// Serializes an TCP layer in IPv4.
pub fn serialize_ipv4_tcp(
    tcp: &Tcp,
    src: &Ipv4Addr,
    dst: &Ipv4Addr,
    buffer: &mut [u8],
) -> Result<(), String> {
    let mut tcp_packet = match MutableTcpPacket::new(buffer) {
        Some(packet) => packet,
        None => return Err(format!("connot serialize TCP layer")),
    };

    tcp_packet.populate(tcp);

    // Checksum
    let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), src, dst);
    tcp_packet.set_checksum(checksum);

    Ok(())
}
