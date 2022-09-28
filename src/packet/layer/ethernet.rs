//! Support for serializing and deserializing the Ethernet layer.

use super::{Layer, LayerKind, LayerKinds};
use pnet::packet::ethernet::{self, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};
use std::io;

/// Represents an Ethernet layer.
#[derive(Clone, Debug)]
pub struct Ethernet {
    pub layer: ethernet::Ethernet,
}

impl Ethernet {
    /// Creates an `Ethernet`.
    pub fn new(t: LayerKind, src: MacAddr, dst: MacAddr) -> Option<Ethernet> {
        let ethertype = match t {
            LayerKinds::Arp => EtherTypes::Arp,
            LayerKinds::Ipv4 => EtherTypes::Ipv4,
            _ => return None,
        };
        let ethernet = ethernet::Ethernet {
            destination: dst,
            source: src,
            ethertype,
            payload: vec![],
        };
        Some(Ethernet::from(ethernet))
    }

    /// Creates an `Ethernet` according to the given `Ethernet`.
    pub fn from(ethernet: ethernet::Ethernet) -> Ethernet {
        Ethernet { layer: ethernet }
    }

    /// Creates an `Ethernet` according to the given Ethernet packet.
    pub fn parse(packet: &EthernetPacket) -> Ethernet {
        let ethernet = ethernet::Ethernet {
            destination: packet.get_destination(),
            source: packet.get_source(),
            ethertype: packet.get_ethertype(),
            payload: vec![],
        };
        Ethernet::from(ethernet)
    }

    /// Returns the source of the layer.
    pub fn src(&self) -> MacAddr {
        self.layer.source
    }

    /// Returns the destination of the layer.
    pub fn dst(&self) -> MacAddr {
        self.layer.destination
    }
}

impl Display for Ethernet {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}: {} -> {}",
            LayerKinds::Ethernet,
            self.layer.source,
            self.layer.destination
        )
    }
}

impl Layer for Ethernet {
    fn kind(&self) -> LayerKind {
        LayerKinds::Ethernet
    }

    fn len(&self) -> usize {
        EthernetPacket::packet_size(&self.layer)
    }

    fn serialize(&self, buffer: &mut [u8], _: usize) -> io::Result<usize> {
        let mut packet = MutableEthernetPacket::new(buffer)
            .ok_or_else(|| io::Error::new(io::ErrorKind::WriteZero, "buffer too small"))?;

        packet.populate(&self.layer);

        Ok(self.len())
    }

    fn serialize_with_payload(&self, buffer: &mut [u8], _: &[u8], n: usize) -> io::Result<usize> {
        self.serialize(buffer, n)
    }
}
