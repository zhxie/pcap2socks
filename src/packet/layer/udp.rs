//! Support for serializing and deserializing the UDP layer.

use super::ipv4::Ipv4;
use super::{Layer, LayerKind, LayerKinds};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::Ipv4Addr;

/// Represents an UDP packet.
#[derive(Clone, Debug)]
pub struct Udp {
    layer: udp::Udp,
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

impl Udp {
    /// Creates an `Udp`.
    pub fn new(src: u16, dst: u16) -> Udp {
        let d_udp = udp::Udp {
            source: src,
            destination: dst,
            length: 0,
            checksum: 0,
            payload: vec![],
        };
        Udp::from(d_udp)
    }

    /// Creates an `Udp` according to the given `Udp`.
    pub fn from(udp: udp::Udp) -> Udp {
        Udp {
            layer: udp,
            src: Ipv4Addr::UNSPECIFIED,
            dst: Ipv4Addr::UNSPECIFIED,
        }
    }

    /// Creates an `Udp` according to the given UDP packet and the `Ipv4`
    pub fn parse(packet: &UdpPacket, ipv4: &Ipv4) -> Udp {
        let d_udp = udp::Udp {
            source: packet.get_source(),
            destination: packet.get_destination(),
            length: packet.get_length(),
            checksum: packet.get_checksum(),
            payload: vec![],
        };
        let mut udp = Udp::from(d_udp);
        udp.set_ipv4_layer(ipv4);

        udp
    }

    /// Returns the minimum of the layer when converted into a byte-array.
    pub fn minimum_len() -> usize {
        8
    }

    /// Sets the source and destination IP address for the layer with the given `Ipv4`.
    pub fn set_ipv4_layer(&mut self, ipv4: &Ipv4) {
        self.src = ipv4.src();
        self.dst = ipv4.dst();
    }

    /// Returns the source IP address of the layer.
    pub fn src_ip_addr(&self) -> Ipv4Addr {
        self.src
    }

    /// Returns the destination IP address of the layer.
    pub fn dst_ip_addr(&self) -> Ipv4Addr {
        self.dst
    }

    /// Returns the source of the layer.
    pub fn src(&self) -> u16 {
        self.layer.source
    }

    /// Returns the destination of the layer.
    pub fn dst(&self) -> u16 {
        self.layer.destination
    }

    /// Returns the length of the layer.
    pub fn length(&self) -> u16 {
        self.layer.length
    }
}

impl Display for Udp {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}: {} -> {}, Length = {}",
            LayerKinds::Udp,
            self.layer.source,
            self.layer.destination,
            self.layer.length
        )
    }
}

impl Layer for Udp {
    fn kind(&self) -> LayerKind {
        LayerKinds::Udp
    }

    fn len(&self) -> usize {
        UdpPacket::packet_size(&self.layer)
    }

    fn serialize(&self, buffer: &mut [u8], n: usize) -> io::Result<usize> {
        let mut packet = MutableUdpPacket::new(buffer)
            .ok_or_else(|| io::Error::new(io::ErrorKind::WriteZero, "buffer too small"))?;

        packet.populate(&self.layer);

        // Fix length
        if n > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "length too big",
            ));
        }
        packet.set_length(n as u16);

        // Compute checksum
        let checksum = udp::ipv4_checksum(
            &packet.to_immutable(),
            &self.src_ip_addr(),
            &self.dst_ip_addr(),
        );
        packet.set_checksum(checksum);

        Ok(self.len())
    }

    fn serialize_with_payload(
        &self,
        buffer: &mut [u8],
        payload: &[u8],
        n: usize,
    ) -> io::Result<usize> {
        let mut packet = MutableUdpPacket::new(buffer)
            .ok_or_else(|| io::Error::new(io::ErrorKind::WriteZero, "buffer too small"))?;

        packet.populate(&self.layer);

        // Copy payload
        packet.set_payload(payload);

        // Fix length
        if n > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "length too big",
            ));
        }
        packet.set_length(n as u16);

        // Compute checksum
        let checksum = udp::ipv4_checksum(
            &packet.to_immutable(),
            &self.src_ip_addr(),
            &self.dst_ip_addr(),
        );
        packet.set_checksum(checksum);

        Ok(self.len() + n)
    }
}
