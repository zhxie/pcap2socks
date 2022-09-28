//! Support for serializing and deserializing the ICMPv4 layer.

use super::{Layer, LayerKind, LayerKinds};
use pnet::packet::icmp::destination_unreachable;
use pnet::packet::icmp::echo_reply;
use pnet::packet::icmp::echo_request;
use pnet::packet::icmp::{self, Icmp, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{FromPacket, Packet};
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

use super::ipv4::Ipv4;
use super::tcp::Tcp;
use super::udp::Udp;
use super::Layers;

/// Represents an ICMPv4 layer.
#[derive(Clone, Debug)]
pub struct Icmpv4 {
    layer: Icmp,
}

impl Icmpv4 {
    /// Creates a `Icmpv4` represents an ICMPv4 echo reply.
    pub fn new_echo_reply(identifier: u16, sequence_number: u16) -> Icmpv4 {
        let mut payload = vec![0u8; 4];
        payload[..2].copy_from_slice(&identifier.to_ne_bytes());
        payload[2..].copy_from_slice(&sequence_number.to_ne_bytes());
        let icmp = Icmp {
            icmp_type: IcmpTypes::EchoReply,
            icmp_code: echo_reply::IcmpCodes::NoCode,
            checksum: 0,
            payload,
        };
        Icmpv4::from(icmp)
    }

    /// Creates a `Icmpv4` represents an ICMPv4 destination host unreachable.
    pub fn new_destination_host_unreachable(payload: &[u8]) -> Icmpv4 {
        let mut next_payload = vec![0u8; 4 + payload.len()];
        next_payload[4..].copy_from_slice(payload);
        let icmp = Icmp {
            icmp_type: IcmpTypes::DestinationUnreachable,
            icmp_code: destination_unreachable::IcmpCodes::DestinationHostUnreachable,
            checksum: 0,
            payload: next_payload,
        };
        Icmpv4::from(icmp)
    }

    /// Creates a `Icmpv4` represents an ICMPv4 destination port unreachable.
    pub fn new_destination_port_unreachable(payload: &[u8]) -> Icmpv4 {
        let mut next_payload = vec![0u8; 4 + payload.len()];
        next_payload[4..].copy_from_slice(payload);
        let icmp = Icmp {
            icmp_type: IcmpTypes::DestinationUnreachable,
            icmp_code: destination_unreachable::IcmpCodes::DestinationPortUnreachable,
            checksum: 0,
            payload: next_payload,
        };
        Icmpv4::from(icmp)
    }

    /// Creates an `Icmpv4` according to the given `Icmp`.
    pub fn from(icmp: Icmp) -> Icmpv4 {
        Icmpv4 { layer: icmp }
    }

    /// Creates an `Icmpv4` according to the given ICMPv4 packet.
    pub fn parse(packet: &IcmpPacket) -> Icmpv4 {
        let icmp = packet.from_packet();

        Icmpv4::from(icmp)
    }

    /// Returns the string represents the description of the layer.
    pub fn description(&self) -> String {
        if self.is_echo_reply() {
            String::from("Echo reply")
        } else if self.is_destination_host_unreachable() {
            String::from("Destination host unreachable")
        } else if self.is_destination_port_unreachable() {
            String::from("Destination port unreachable")
        } else if self.is_fragmentation_required_and_df_flag_set() {
            String::from("Fragmentation required, and DF flag set")
        } else if self.is_echo_request() {
            String::from("Echo request")
        } else {
            format!(
                "Type = {}, Code = {}",
                self.layer.icmp_type.0, self.layer.icmp_code.0
            )
        }
    }

    /// Returns the identifier (NE) of the layer.
    pub fn identifier(&self) -> Option<u16> {
        if self.is_echo_reply() || self.is_echo_request() {
            let buffer = [self.layer.payload[0], self.layer.payload[1]];
            Some(u16::from_ne_bytes(buffer))
        } else {
            None
        }
    }

    /// Returns the sequence number (NE) of the layer.
    pub fn sequence_number(&self) -> Option<u16> {
        if self.is_echo_reply() || self.is_echo_request() {
            let buffer = [self.layer.payload[2], self.layer.payload[3]];
            Some(u16::from_ne_bytes(buffer))
        } else {
            None
        }
    }

    /// Returns the next-hop MTU of the layer.
    pub fn next_hop_mtu(&self) -> Option<u16> {
        if self.is_fragmentation_required_and_df_flag_set() {
            let buffer = [self.layer.payload[2], self.layer.payload[3]];
            Some(u16::from_be_bytes(buffer))
        } else {
            None
        }
    }

    /// Returns the source IP address in the payload of the layer.
    pub fn src_ip_addr(&self) -> Option<Ipv4Addr> {
        if self.is_destination_port_unreachable()
            || self.is_fragmentation_required_and_df_flag_set()
        {
            let (ipv4, _) = self.parse_payload().unwrap();
            Some(ipv4.src())
        } else {
            None
        }
    }

    /// Returns the destination IP address in the payload of the layer.
    pub fn dst_ip_addr(&self) -> Option<Ipv4Addr> {
        if self.is_destination_port_unreachable()
            || self.is_fragmentation_required_and_df_flag_set()
        {
            let (ipv4, _) = self.parse_payload().unwrap();
            Some(ipv4.dst())
        } else {
            None
        }
    }

    /// Returns the next level protocol in the payload of the layer.
    pub fn next_level_protocol(&self) -> Option<IpNextHeaderProtocol> {
        if self.is_destination_port_unreachable()
            || self.is_fragmentation_required_and_df_flag_set()
        {
            let (ipv4, _) = self.parse_payload().unwrap();
            Some(ipv4.next_level_protocol())
        } else {
            None
        }
    }

    /// Returns the next level layer kind in the payload of the layer.
    pub fn next_level_layer_kind(&self) -> Option<LayerKind> {
        if self.is_destination_port_unreachable()
            || self.is_fragmentation_required_and_df_flag_set()
        {
            let (ipv4, _) = self.parse_payload().unwrap();
            ipv4.next_level_layer_kind()
        } else {
            None
        }
    }

    /// Returns the source in the payload of the layer.
    pub fn src(&self) -> Option<SocketAddrV4> {
        if self.is_destination_port_unreachable()
            || self.is_fragmentation_required_and_df_flag_set()
        {
            let (_, transport) = self.parse_payload().unwrap();
            match transport {
                Some(transport) => match transport {
                    Layers::Tcp(ref tcp) => Some(SocketAddrV4::new(tcp.src_ip_addr(), tcp.src())),
                    Layers::Udp(ref udp) => Some(SocketAddrV4::new(udp.src_ip_addr(), udp.src())),
                    _ => None,
                },
                None => None,
            }
        } else {
            None
        }
    }

    /// Returns the destination in the payload of the layer.
    pub fn dst(&self) -> Option<SocketAddrV4> {
        if self.is_destination_port_unreachable()
            || self.is_fragmentation_required_and_df_flag_set()
        {
            let (_, transport) = self.parse_payload().unwrap();
            match transport {
                Some(transport) => match transport {
                    Layers::Tcp(ref tcp) => Some(SocketAddrV4::new(tcp.dst_ip_addr(), tcp.dst())),
                    Layers::Udp(ref udp) => Some(SocketAddrV4::new(udp.dst_ip_addr(), udp.dst())),
                    _ => None,
                },
                None => None,
            }
        } else {
            None
        }
    }

    fn parse_payload(&self) -> Option<(Ipv4, Option<Layers>)> {
        if self.layer.payload.len() < 4 {
            return None;
        }
        let payload = &self.layer.payload[4..];
        match Ipv4Packet::new(payload) {
            Some(ref ipv4_packet) => {
                let ipv4 = Ipv4::parse(ipv4_packet);
                // Fragment
                if !ipv4.is_fragment() {
                    let transport = match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Icmp => {
                            IcmpPacket::new(ipv4_packet.payload())
                                .map(|icmp_packet| Layers::Icmpv4(Icmpv4::parse(&icmp_packet)))
                        }
                        IpNextHeaderProtocols::Tcp => {
                            TcpPacket::new(ipv4_packet.payload())
                                .map(|tcp_packet| Layers::Tcp(Tcp::parse(&tcp_packet, &ipv4)))
                        },
                        IpNextHeaderProtocols::Udp => {
                            UdpPacket::new(ipv4_packet.payload())
                                .map(|udp_packet| Layers::Udp(Udp::parse(&udp_packet, &ipv4)))
                        },
                        _ => None,
                    };

                    Some((ipv4, transport))
                } else {
                    Some((ipv4, None))
                }
            }
            None => None,
        }
    }

    /// Returns if the layer an ICMPv4 echo reply.
    pub fn is_echo_reply(&self) -> bool {
        self.layer.icmp_type == IcmpTypes::EchoReply
            && self.layer.icmp_code == echo_reply::IcmpCodes::NoCode
    }

    /// Returns if the layer is an ICMPv4 destination host unreachable.
    pub fn is_destination_host_unreachable(&self) -> bool {
        self.layer.icmp_type == IcmpTypes::DestinationUnreachable
            && self.layer.icmp_code
                == destination_unreachable::IcmpCodes::DestinationHostUnreachable
    }

    /// Returns if the layer is an ICMPv4 destination port unreachable.
    pub fn is_destination_port_unreachable(&self) -> bool {
        self.layer.icmp_type == IcmpTypes::DestinationUnreachable
            && self.layer.icmp_code
                == destination_unreachable::IcmpCodes::DestinationPortUnreachable
    }

    /// Returns if the layer is an ICMPv4 fragmentation required, and DF flag set.
    pub fn is_fragmentation_required_and_df_flag_set(&self) -> bool {
        self.layer.icmp_type == IcmpTypes::DestinationUnreachable
            && self.layer.icmp_code
                == destination_unreachable::IcmpCodes::FragmentationRequiredAndDFFlagSet
    }

    /// Returns if the layer is an ICMPv4 echo request.
    pub fn is_echo_request(&self) -> bool {
        self.layer.icmp_type == IcmpTypes::EchoRequest
            && self.layer.icmp_code == echo_request::IcmpCodes::NoCode
    }
}

impl Display for Icmpv4 {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}: {}", LayerKinds::Icmpv4, self.description())
    }
}

impl Layer for Icmpv4 {
    fn kind(&self) -> LayerKind {
        LayerKinds::Icmpv4
    }

    fn len(&self) -> usize {
        IcmpPacket::packet_size(&self.layer)
    }

    fn serialize(&self, buffer: &mut [u8], _: usize) -> io::Result<usize> {
        let mut packet = MutableIcmpPacket::new(buffer)
            .ok_or_else(|| io::Error::new(io::ErrorKind::WriteZero, "buffer too small"))?;

        packet.populate(&self.layer);

        // Compute checksum
        let checksum = icmp::checksum(&packet.to_immutable());
        packet.set_checksum(checksum);

        Ok(self.len())
    }

    fn serialize_with_payload(&self, buffer: &mut [u8], _: &[u8], n: usize) -> io::Result<usize> {
        self.serialize(buffer, n)
    }
}
