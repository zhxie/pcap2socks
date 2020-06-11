pub use super::{Layer, LayerType, LayerTypes};
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
    pub fn new(t: LayerType, src: MacAddr, dst: MacAddr) -> Option<Ethernet> {
        match t {
            LayerTypes::Arp => Some(Ethernet {
                layer: ethernet::Ethernet {
                    destination: dst,
                    source: src,
                    ethertype: EtherTypes::Arp,
                    payload: vec![],
                },
            }),
            LayerTypes::Ipv4 => Some(Ethernet {
                layer: ethernet::Ethernet {
                    destination: dst,
                    source: src,
                    ethertype: EtherTypes::Ipv4,
                    payload: vec![],
                },
            }),
            _ => None,
        }
    }

    /// Creates an `Ethernet` according to the given `Ethernet`.
    pub fn from(ethernet: ethernet::Ethernet) -> Ethernet {
        Ethernet { layer: ethernet }
    }

    /// Creates an `Ethernet` according to the given Ethernet packet.
    pub fn parse(packet: &EthernetPacket) -> Ethernet {
        Ethernet {
            layer: ethernet::Ethernet {
                destination: packet.get_destination(),
                source: packet.get_source(),
                ethertype: packet.get_ethertype(),
                payload: vec![],
            },
        }
    }

    /// Get the source of the layer.
    pub fn get_src(&self) -> MacAddr {
        self.layer.source
    }

    /// Get the destination of the layer.
    pub fn get_dst(&self) -> MacAddr {
        self.layer.destination
    }
}

impl Display for Ethernet {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}: {} -> {}",
            LayerTypes::Ethernet,
            self.layer.source,
            self.layer.destination
        )
    }
}

impl Layer for Ethernet {
    fn get_type(&self) -> LayerType {
        LayerTypes::Ethernet
    }

    fn get_size(&self) -> usize {
        EthernetPacket::packet_size(&self.layer)
    }

    fn serialize(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut packet = MutableEthernetPacket::new(buffer)
            .ok_or(io::Error::new(io::ErrorKind::WriteZero, "buffer too small"))?;

        packet.populate(&self.layer);

        Ok(self.get_size())
    }

    fn serialize_n(&self, buffer: &mut [u8], _: usize) -> io::Result<usize> {
        self.serialize(buffer)
    }
}
