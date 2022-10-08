//! Support for serializing and deserializing the IPv4 layer.

use super::{Layer, LayerKind, LayerKinds};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{self, Ipv4Flags, Ipv4OptionPacket, Ipv4Packet, MutableIpv4Packet};
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::Ipv4Addr;

/// Represents the TTL in the sent packets.
const TTL: u8 = 128;

/// Represents an IPv4 layer.
#[derive(Clone, Debug)]
pub struct Ipv4 {
    layer: ipv4::Ipv4,
}

impl Ipv4 {
    /// Creates an `Ipv4`.
    pub fn new(identification: u16, t: LayerKind, src: Ipv4Addr, dst: Ipv4Addr) -> Option<Ipv4> {
        let next_level_protocol = match t {
            LayerKinds::Icmpv4 => IpNextHeaderProtocols::Icmp,
            LayerKinds::Tcp => IpNextHeaderProtocols::Tcp,
            LayerKinds::Udp => IpNextHeaderProtocols::Udp,
            _ => return None,
        };
        let d_ipv4 = ipv4::Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 0,
            identification,
            flags: 0,
            fragment_offset: 0,
            ttl: TTL,
            next_level_protocol,
            checksum: 0,
            source: src,
            destination: dst,
            options: vec![],
            payload: vec![],
        };
        Some(Ipv4::from(d_ipv4))
    }

    /// Creates an `Ipv4` represents an IPv4 fragment.
    pub fn new_more_fragment(
        identification: u16,
        t: LayerKind,
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
        t: LayerKind,
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
        let d_ipv4 = ipv4::Ipv4 {
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
        };
        Ipv4::from(d_ipv4)
    }

    /// Returns the minimum of the layer when converted into a byte-array.
    pub fn minimum_len() -> usize {
        20
    }

    /// Returns the total length of the layer.
    pub fn total_length(&self) -> u16 {
        self.layer.total_length
    }

    /// Returns the identification of the layer.
    pub fn identification(&self) -> u16 {
        self.layer.identification
    }

    /// Returns if more fragments are follows this layer.
    pub fn is_more_fragment(&self) -> bool {
        self.layer.flags & Ipv4Flags::MoreFragments != 0
    }

    /// Returns the fragment offset of the layer.
    pub fn fragment_offset(&self) -> u16 {
        self.layer.fragment_offset
    }

    /// Returns if the layer is a IPv4 fragment.
    pub fn is_fragment(&self) -> bool {
        self.is_more_fragment() || self.fragment_offset() > 0
    }

    /// Returns the next level protocol of the layer.
    pub fn next_level_protocol(&self) -> IpNextHeaderProtocol {
        self.layer.next_level_protocol
    }

    /// Returns the next level layer kind of the layer.
    pub fn next_level_layer_kind(&self) -> Option<LayerKind> {
        match self.layer.next_level_protocol {
            IpNextHeaderProtocols::Icmp => Some(LayerKinds::Icmpv4),
            IpNextHeaderProtocols::Tcp => Some(LayerKinds::Tcp),
            IpNextHeaderProtocols::Udp => Some(LayerKinds::Udp),
            _ => None,
        }
    }

    /// Returns the source of the layer.
    pub fn src(&self) -> Ipv4Addr {
        self.layer.source
    }

    /// Returns the destination of the layer.
    pub fn dst(&self) -> Ipv4Addr {
        self.layer.destination
    }
}

impl Display for Ipv4 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut fragment = String::new();
        if self.is_fragment() {
            fragment = format!(", Fragment = {}", self.fragment_offset() * 8);
        }

        write!(
            f,
            "{}: {} -> {}, Length = {}{}",
            LayerKinds::Ipv4,
            self.layer.source,
            self.layer.destination,
            self.layer.total_length,
            fragment
        )
    }
}

impl Layer for Ipv4 {
    fn kind(&self) -> LayerKind {
        LayerKinds::Ipv4
    }

    fn len(&self) -> usize {
        let mut ipv4_size = Ipv4Packet::packet_size(&self.layer);
        let mut ipv4_options_size = 0;
        for option in &self.layer.options {
            ipv4_size -= 1;
            ipv4_options_size += Ipv4OptionPacket::packet_size(option);
        }

        ipv4_size + ipv4_options_size
    }

    fn serialize(&self, buffer: &mut [u8], n: usize) -> io::Result<usize> {
        let mut packet = MutableIpv4Packet::new(buffer)
            .ok_or_else(|| io::Error::new(io::ErrorKind::WriteZero, "buffer too small"))?;

        packet.populate(&self.layer);

        // Fix length
        let header_length = self.len();
        if header_length / 4 > u8::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::Other, "IPv4 too big"));
        }
        packet.set_header_length((header_length / 4) as u8);
        if n > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "length too big",
            ));
        }
        packet.set_total_length(n as u16);

        // Compute checksum
        let checksum = ipv4::checksum(&packet.to_immutable());
        packet.set_checksum(checksum);

        Ok(header_length)
    }

    fn serialize_with_payload(
        &self,
        buffer: &mut [u8],
        payload: &[u8],
        n: usize,
    ) -> io::Result<usize> {
        let mut packet = MutableIpv4Packet::new(buffer)
            .ok_or_else(|| io::Error::new(io::ErrorKind::WriteZero, "buffer too small"))?;

        packet.populate(&self.layer);

        // Fix length
        let header_length = self.len();
        if header_length / 4 > u8::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::Other, "IPv4 too big"));
        }
        packet.set_header_length((header_length / 4) as u8);
        if n > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "length too big",
            ));
        }
        packet.set_total_length(n as u16);

        // Copy payload
        packet.set_payload(payload);

        // Compute checksum
        let checksum = ipv4::checksum(&packet.to_immutable());
        packet.set_checksum(checksum);

        Ok(header_length)
    }
}
