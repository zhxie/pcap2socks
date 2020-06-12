pub use super::{Layer, LayerType, LayerTypes};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::Ipv4Addr;

/// Represents an UDP packet.
#[derive(Clone, Debug)]
pub struct Udp {
    pub layer: udp::Udp,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl Udp {
    /// Creates an `Udp`.
    pub fn new(src_ip_addr: Ipv4Addr, dst_ip_addr: Ipv4Addr, src: u16, dst: u16) -> Udp {
        Udp {
            layer: udp::Udp {
                source: src,
                destination: dst,
                length: 0,
                checksum: 0,
                payload: vec![],
            },
            src: src_ip_addr,
            dst: dst_ip_addr,
        }
    }

    /// Creates an `Udp` according to the given `Udp`.
    pub fn from(udp: udp::Udp, src: Ipv4Addr, dst: Ipv4Addr) -> Udp {
        Udp {
            layer: udp,
            src,
            dst,
        }
    }

    /// Creates an `Udp` according to the given UDP packet, source and destination.
    pub fn parse(packet: &UdpPacket, src: Ipv4Addr, dst: Ipv4Addr) -> Udp {
        Udp {
            layer: udp::Udp {
                source: packet.get_source(),
                destination: packet.get_destination(),
                length: packet.get_length(),
                checksum: packet.get_checksum(),
                payload: vec![],
            },
            src,
            dst,
        }
    }

    fn serialize_internal(
        &self,
        buffer: &mut [u8],
        fix_length: bool,
        n: usize,
        compute_checksum: bool,
    ) -> io::Result<usize> {
        let mut packet = MutableUdpPacket::new(buffer)
            .ok_or(io::Error::new(io::ErrorKind::WriteZero, "buffer too small"))?;

        packet.populate(&self.layer);

        // Fix length
        if fix_length {
            packet.set_length(n as u16);
        }

        // Compute checksum
        if compute_checksum {
            let checksum = udp::ipv4_checksum(
                &packet.to_immutable(),
                &self.get_src_ip_addr(),
                &self.get_dst_ip_addr(),
            );
            packet.set_checksum(checksum);
        }

        Ok(self.get_size() + n)
    }

    /// Get the source IP address of the layer.
    pub fn get_src_ip_addr(&self) -> Ipv4Addr {
        self.src
    }

    /// Get the destination IP address of the layer.
    pub fn get_dst_ip_addr(&self) -> Ipv4Addr {
        self.dst
    }

    /// Get the source of the layer.
    pub fn get_src(&self) -> u16 {
        self.layer.source
    }

    /// Get the destination of the layer.
    pub fn get_dst(&self) -> u16 {
        self.layer.destination
    }
}

impl Display for Udp {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}: {} -> {}, Length = {}",
            LayerTypes::Udp,
            self.layer.source,
            self.layer.destination,
            self.layer.length
        )
    }
}

impl Layer for Udp {
    fn get_type(&self) -> LayerType {
        LayerTypes::Udp
    }

    fn get_size(&self) -> usize {
        UdpPacket::packet_size(&self.layer)
    }

    fn serialize(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.serialize_internal(buffer, false, 0, true)
    }

    fn serialize_n(&self, buffer: &mut [u8], n: usize) -> io::Result<usize> {
        self.serialize_internal(buffer, true, n, true)
    }
}
