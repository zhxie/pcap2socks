pub use super::layer::{Layer, LayerType, LayerTypes, SerializeError, SerializeResult};
use pnet::datalink::MacAddr;
use pnet::packet::arp::{self, ArpOperations, ArpPacket, MutableArpPacket};
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};
use std::net::Ipv4Addr;

/// Represents an ARP layer.
#[derive(Clone, Debug)]
pub struct Arp {
    pub layer: arp::Arp,
}

impl Arp {
    /// Creates an `Arp` according to the given `Arp`.
    pub fn from(arp: arp::Arp) -> Arp {
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

    /// Returns if the `Arp` is an ARP request.
    pub fn is_request(&self) -> bool {
        self.layer.operation == ArpOperations::Request
    }

    /// Returns if the `Arp` is an ARP reply.
    pub fn is_reply(&self) -> bool {
        self.layer.operation == ArpOperations::Reply
    }

    /// Returns if the `Arp` is an ARP request of the given source and destination.
    pub fn is_request_of(&self, src: Ipv4Addr, dst: Ipv4Addr) -> bool {
        match self.layer.operation {
            ArpOperations::Request => {
                self.layer.sender_proto_addr == src && self.layer.target_proto_addr == dst
            }
            _ => false,
        }
    }

    /// Get the source hardware address of the layer.
    pub fn get_src_hardware_addr(&self) -> MacAddr {
        self.layer.sender_hw_addr
    }

    /// Get the destination hardware address of the layer.
    pub fn get_dst_hardware_addr(&self) -> MacAddr {
        self.layer.target_hw_addr
    }

    /// Get the source of the layer.
    pub fn get_src(&self) -> Ipv4Addr {
        self.layer.sender_proto_addr
    }

    /// Get the destination of the layer.
    pub fn get_dst(&self) -> Ipv4Addr {
        self.layer.target_proto_addr
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

    fn serialize(&self, buffer: &mut [u8]) -> SerializeResult {
        let mut packet =
            MutableArpPacket::new(buffer).ok_or(SerializeError::BufferTooSmallError)?;

        packet.populate(&self.layer);

        Ok(self.get_size())
    }

    fn serialize_n(&self, buffer: &mut [u8], _: usize) -> SerializeResult {
        self.serialize(buffer)
    }
}
