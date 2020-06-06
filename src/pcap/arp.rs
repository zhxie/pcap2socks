pub use super::layer::{Layer, LayerType, LayerTypes};
use pnet::datalink::MacAddr;
use pnet::packet::arp::{self, ArpOperations, ArpPacket, MutableArpPacket};
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};

/// Represents an ARP layer.
#[derive(Clone, Debug)]
pub struct Arp {
    pub layer: arp::Arp,
}

impl Arp {
    /// Creates an `Arp`.
    pub fn new(arp: arp::Arp) -> Arp {
        Arp { layer: arp }
    }

    /// Creates an `Arp` according to the given ARP packet.
    pub fn parse(packet: &ArpPacket) -> Arp {
        Arp {
            layer: arp::Arp {
                hardware_type: packet.get_hardware_type(),
                protocol_type: packet.get_protocol_type(),
                hw_addr_len: packet.get_hw_addr_len(),
                proto_addr_len: packet.get_proto_addr_len(),
                operation: packet.get_operation(),
                sender_hw_addr: packet.get_sender_hw_addr(),
                sender_proto_addr: packet.get_sender_proto_addr(),
                target_hw_addr: packet.get_target_hw_addr(),
                target_proto_addr: packet.get_target_proto_addr(),
                payload: vec![],
            },
        }
    }

    /// Creates an ARP reply according to a given `Arp`.
    pub fn reply(layer: &Arp, hardware_addr: MacAddr) -> Arp {
        Arp {
            layer: arp::Arp {
                hardware_type: layer.layer.hardware_type,
                protocol_type: layer.layer.protocol_type,
                hw_addr_len: layer.layer.hw_addr_len,
                proto_addr_len: layer.layer.proto_addr_len,
                operation: ArpOperations::Reply,
                sender_hw_addr: hardware_addr,
                sender_proto_addr: layer.layer.target_proto_addr,
                target_hw_addr: layer.layer.sender_hw_addr,
                target_proto_addr: layer.layer.sender_proto_addr,
                payload: vec![],
            },
        }
    }
}

impl Display for Arp {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}: {} -> {}, Operation = {}",
            self.get_type(),
            self.layer.sender_proto_addr,
            self.layer.target_proto_addr,
            match self.layer.operation {
                ArpOperations::Request => "Request",
                ArpOperations::Reply => "Reply",
                _ => "unknown",
            }
        )
    }
}

impl Layer for Arp {
    fn get_type(&self) -> LayerType {
        LayerTypes::Arp
    }

    fn get_size(&self) -> usize {
        ArpPacket::packet_size(&self.layer)
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<(), String> {
        let mut packet = match MutableArpPacket::new(buffer) {
            Some(packet) => packet,
            None => return Err(format!("buffer is too small")),
        };

        packet.populate(&self.layer);

        Ok(())
    }

    fn serialize_n(&self, n: usize, buffer: &mut [u8]) -> Result<usize, String> {
        match self.serialize(buffer) {
            Ok(_) => Ok(self.get_size() + n),
            Err(e) => Err(e),
        }
    }
}
