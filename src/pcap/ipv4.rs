pub use super::layer::{Layer, LayerType, LayerTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
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
    pub fn new(identification: u16, t: LayerType, src: Ipv4Addr, dst: Ipv4Addr) -> Option<Ipv4> {
        let next_level_protocol = match t {
            LayerTypes::Tcp => IpNextHeaderProtocols::Tcp,
            LayerTypes::Udp => IpNextHeaderProtocols::Udp,
            _ => return None,
        };
        Some(Ipv4 {
            layer: ipv4::Ipv4 {
                version: 4,
                header_length: 5,
                dscp: 0,
                ecn: 0,
                total_length: 0,
                identification,
                flags: 0,
                fragment_offset: 0,
                ttl: 128,
                next_level_protocol,
                checksum: 0,
                source: src,
                destination: dst,
                options: vec![],
                payload: vec![],
            },
        })
    }

    /// Creates an `Ipv4` represents an IPv4 fragment.
    pub fn new_more_fragment(
        identification: u16,
        t: LayerType,
        fragment_offset: u16,
        src: Ipv4Addr,
        dst: Ipv4Addr,
    ) -> Option<Ipv4> {
        let ipv4 = Ipv4::new(identification, t, src, dst);
        if let Some(mut ipv4) = ipv4 {
            ipv4.layer.flags = Ipv4Flags::MoreFragments;
            ipv4.layer.fragment_offset = fragment_offset;
            return Some(ipv4);
        };

        None
    }

    /// Creates an `Ipv4` represents an IPv4 last fragment.
    pub fn new_last_fragment(
        identification: u16,
        t: LayerType,
        fragment_offset: u16,
        src: Ipv4Addr,
        dst: Ipv4Addr,
    ) -> Option<Ipv4> {
        let ipv4 = Ipv4::new(identification, t, src, dst);
        if let Some(mut ipv4) = ipv4 {
            ipv4.layer.fragment_offset = fragment_offset;
            return Some(ipv4);
        };

        None
    }

    /// Creates an `Ipv4` according to the given `Ipv4`.
    pub fn from(ipv4: ipv4::Ipv4) -> Ipv4 {
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

    fn serialize_private(
        &self,
        buffer: &mut [u8],
        fix_length: bool,
        n: usize,
        compute_checksum: bool,
    ) -> Result<usize, String> {
        let mut packet = match MutableIpv4Packet::new(buffer) {
            Some(packet) => packet,
            None => return Err(format!("buffer is too small")),
        };

        packet.populate(&self.layer);

        // Fix length
        if fix_length {
            let header_length = self.get_size();
            packet.set_header_length((header_length / 4) as u8);
            packet.set_total_length((header_length + n) as u16);
        }

        // Compute checksum
        if compute_checksum {
            let checksum = ipv4::checksum(&packet.to_immutable());
            packet.set_checksum(checksum);
        }

        Ok(self.get_size())
    }

    /// Get the identification of the layer.
    pub fn get_identification(&self) -> u16 {
        self.layer.identification
    }

    /// Returns if more fragments are follows this `Ipv4`.
    pub fn is_more_fragment(&self) -> bool {
        self.layer.flags & Ipv4Flags::MoreFragments != 0
    }

    /// Get the fragment offset of the layer.
    pub fn get_fragment_offset(&self) -> u16 {
        self.layer.fragment_offset
    }

    /// Returns if the `Ipv4` is a IPv4 fragment.
    pub fn is_fragment(&self) -> bool {
        self.is_more_fragment() || self.get_fragment_offset() > 0
    }

    /// Get the source of the layer.
    pub fn get_src(&self) -> Ipv4Addr {
        self.layer.source
    }

    /// Get the destination of the layer.
    pub fn get_dst(&self) -> Ipv4Addr {
        self.layer.destination
    }
}

impl Display for Ipv4 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut fragment = String::new();
        if self.is_fragment() {
            fragment = format!(", Fragment = {}", self.get_fragment_offset() * 8);
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

    fn serialize(&self, buffer: &mut [u8]) -> Result<usize, String> {
        self.serialize_private(buffer, false, 0, true)
    }

    fn serialize_n(&self, buffer: &mut [u8], n: usize) -> Result<usize, String> {
        self.serialize_private(buffer, true, n, true)
    }
}
