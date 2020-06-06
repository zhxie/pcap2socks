pub use super::layer::{Layer, LayerType, LayerTypes};
use pnet::packet::ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};
use std::net::Ipv4Addr;

/// Represents an IPv4 layer.
#[derive(Clone, Debug)]
pub struct Ipv4 {
    layer: ipv4::Ipv4,
}

impl Ipv4 {
    /// Creates an `Ipv4`.
    pub fn new(ipv4: ipv4::Ipv4) -> Ipv4 {
        Ipv4 { layer: ipv4 }
    }

    /// Creates an `Ipv4` according to the given IPv4 packet.
    pub fn parse(packet: &Ipv4Packet) -> Ipv4 {
        Ipv4 {
            layer: ipv4::Ipv4 {
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
            },
        }
    }

    // Get the source of the layer.
    pub fn get_src(&self) -> Ipv4Addr {
        self.layer.source
    }

    // Get the destination of the layer.
    pub fn get_dst(&self) -> Ipv4Addr {
        self.layer.destination
    }
}

impl Display for Ipv4 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut fragment = String::new();
        if self.layer.flags & Ipv4Flags::MoreFragments != 0 || self.layer.fragment_offset > 0 {
            fragment = format!(", Fragment = {}", self.layer.fragment_offset);
        }

        write!(
            f,
            "{}: {} -> {}, Length = {}{}",
            LayerTypes::Ipv4,
            self.layer.source,
            self.layer.destination,
            self.layer.total_length,
            fragment
        )
    }
}

impl Layer for Ipv4 {
    fn get_type(&self) -> LayerType {
        LayerTypes::Ipv4
    }

    fn get_size(&self) -> usize {
        Ipv4Packet::packet_size(&self.layer)
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<(), String> {
        let mut packet = match MutableIpv4Packet::new(buffer) {
            Some(packet) => packet,
            None => return Err(format!("buffer is too small")),
        };

        packet.populate(&self.layer);

        // Checksum
        let checksum = ipv4::checksum(&packet.to_immutable());
        packet.set_checksum(checksum);

        Ok(())
    }

    fn serialize_n(&self, n: usize, buffer: &mut [u8]) -> Result<usize, String> {
        let mut packet = match MutableIpv4Packet::new(buffer) {
            Some(packet) => packet,
            None => return Err(format!("buffer is too small")),
        };

        packet.populate(&self.layer);

        // Recalculate size
        let mut header_length = self.get_size();
        packet.set_header_length((header_length / 4) as u8);
        packet.set_total_length((header_length + n) as u16);

        // Checksum
        let checksum = ipv4::checksum(&packet.to_immutable());
        packet.set_checksum(checksum);

        Ok(self.get_size() + n)
    }
}
