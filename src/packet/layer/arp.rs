//! Support for serializing and deserializing the ARP layer.

use super::{Layer, LayerKind, LayerKinds};
use pnet::datalink::MacAddr;
use pnet::packet::arp::{self, ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::Ipv4Addr;

/// Represents an ARP layer.
#[derive(Clone, Debug)]
pub struct Arp {
    pub layer: arp::Arp,
}

impl Arp {
    /// Creates a `Arp` represents an ARP reply.
    pub fn new_reply(
        src_hardware_addr: MacAddr,
        src_ip_addr: Ipv4Addr,
        dst_hardware_addr: MacAddr,
        dst_ip_addr: Ipv4Addr,
    ) -> Arp {
        let arp = arp::Arp {
            hardware_type: ArpHardwareTypes::Ethernet,
            protocol_type: EtherTypes::Ipv4,
            hw_addr_len: 6,
            proto_addr_len: 4,
            operation: ArpOperations::Reply,
            sender_hw_addr: src_hardware_addr,
            sender_proto_addr: src_ip_addr,
            target_hw_addr: dst_hardware_addr,
            target_proto_addr: dst_ip_addr,
            payload: vec![],
        };
        Arp::from(arp)
    }

    /// Creates a `Arp` represents an gratuitous ARP.
    pub fn gratuitous_arp(hardware_addr: MacAddr, ip_addr: Ipv4Addr) -> Arp {
        let arp = arp::Arp {
            hardware_type: ArpHardwareTypes::Ethernet,
            protocol_type: EtherTypes::Ipv4,
            hw_addr_len: 6,
            proto_addr_len: 4,
            operation: ArpOperations::Request,
            sender_hw_addr: hardware_addr,
            sender_proto_addr: ip_addr,
            target_hw_addr: MacAddr::zero(),
            target_proto_addr: ip_addr,
            payload: vec![],
        };
        Arp::from(arp)
    }

    /// Creates an `Arp` according to the given `Arp`.
    pub fn from(arp: arp::Arp) -> Arp {
        Arp { layer: arp }
    }

    /// Creates an `Arp` according to the given ARP packet.
    pub fn parse(packet: &ArpPacket) -> Arp {
        let arp = arp::Arp {
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
        };
        Arp::from(arp)
    }

    /// Creates an ARP reply according to a given `Arp`.
    pub fn reply(layer: &Arp, hardware_addr: MacAddr) -> Arp {
        let arp = arp::Arp {
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
        };
        Arp::from(arp)
    }

    /// Returns if the layer is an ARP request.
    pub fn is_request(&self) -> bool {
        self.layer.operation == ArpOperations::Request
    }

    /// Returns if the layer is an ARP reply.
    pub fn is_reply(&self) -> bool {
        self.layer.operation == ArpOperations::Reply
    }

    /// Returns if the layer is an ARP request of the given source and destination.
    pub fn is_request_of(&self, src: Ipv4Addr, dst: Ipv4Addr) -> bool {
        match self.layer.operation {
            ArpOperations::Request => {
                self.layer.sender_proto_addr == src && self.layer.target_proto_addr == dst
            }
            _ => false,
        }
    }

    /// Returns the source hardware address of the layer.
    pub fn src_hardware_addr(&self) -> MacAddr {
        self.layer.sender_hw_addr
    }

    /// Returns the destination hardware address of the layer.
    pub fn dst_hardware_addr(&self) -> MacAddr {
        self.layer.target_hw_addr
    }

    /// Returns the source of the layer.
    pub fn src(&self) -> Ipv4Addr {
        self.layer.sender_proto_addr
    }

    /// Returns the destination of the layer.
    pub fn dst(&self) -> Ipv4Addr {
        self.layer.target_proto_addr
    }
}

impl Display for Arp {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}: {} -> {}, Operation = {}",
            self.kind(),
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
    fn kind(&self) -> LayerKind {
        LayerKinds::Arp
    }

    fn len(&self) -> usize {
        ArpPacket::packet_size(&self.layer)
    }

    fn serialize(&self, buffer: &mut [u8], _: usize) -> io::Result<usize> {
        let mut packet = MutableArpPacket::new(buffer)
            .ok_or_else(|| io::Error::new(io::ErrorKind::WriteZero, "buffer too small"))?;

        packet.populate(&self.layer);

        Ok(self.len())
    }

    fn serialize_with_payload(&self, buffer: &mut [u8], _: &[u8], n: usize) -> io::Result<usize> {
        self.serialize(buffer, n)
    }
}
