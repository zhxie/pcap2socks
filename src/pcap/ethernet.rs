pub use super::layer::{Layer, LayerType, LayerTypes};
use pnet::packet::ethernet::{self, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};

/// Represents an Ethernet layer.
#[derive(Clone, Debug)]
pub struct Ethernet {
    pub layer: ethernet::Ethernet,
}

impl Ethernet {
    /// Creates an `Ethernet`.
    pub fn new(ethernet: ethernet::Ethernet) -> Ethernet {
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

    /// Creates an `Ethernet` according to the given layer type.
    pub fn from(t: LayerType, src: MacAddr, dst: MacAddr) -> Option<Ethernet> {
        match t {
            LayerTypes::Arp => Some(Ethernet {
                layer: ethernet::Ethernet {
                    destination: dst,
                    source: src,
                    ethertype: EtherTypes::Arp,
                    payload: vec![],
                },
            }),
            LayerTypes::Ipv4 => None,
            _ => None,
        }
    }

    /// Get the source of the layer.
    pub fn get_src(&self) -> MacAddr {
        return self.layer.source;
    }

    /// Get the destination of the layer.
    pub fn get_dst(&self) -> MacAddr {
        return self.layer.destination;
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

    fn serialize(&self, buffer: &mut [u8]) -> Result<usize, String> {
        let mut packet = match MutableEthernetPacket::new(buffer) {
            Some(packet) => packet,
            None => return Err(format!("buffer is too small")),
        };

        packet.populate(&self.layer);

        Ok(self.get_size())
    }

    fn serialize_n(&self, buffer: &mut [u8], n: usize) -> Result<usize, String> {
        self.serialize(buffer)
    }
}
