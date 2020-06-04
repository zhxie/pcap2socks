use pnet::packet::arp::{Arp, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, Ethernet, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4, Ipv4Packet};
use pnet::packet::tcp::{Tcp, TcpPacket};
use pnet::packet::udp::{Udp, UdpPacket};
use pnet::packet::Packet;
use std::clone::Clone;

pub mod interface;

mod arp;
mod ethernet;
mod ipv4;
mod tcp;
mod udp;

#[derive(Clone)]
pub enum Network {
    Arp(Arp),
    Ipv4(Ipv4),
}

#[derive(Clone)]
pub enum Transport {
    Tcp(Tcp),
    Udp(Udp),
}

/// Represents a packet indicator.
pub struct Indicator<'a> {
    packet: Option<EthernetPacket<'a>>,
    ethernet: Ethernet,
    network: Option<Network>,
    transport: Option<Transport>,
}

impl<'a> Indicator<'a> {
    /// Creates a `Indicator`.
    pub fn new(packet: EthernetPacket<'a>) -> Indicator<'a> {
        let ethernet = ethernet::parse_ethernet(&packet);
        let transport = None;
        let network = match packet.get_ethertype() {
            EtherTypes::Arp => match ArpPacket::new(packet.payload()) {
                Some(arp_packet) => Some(Network::Arp(arp::parse_arp(&arp_packet))),
                None => None,
            },
            EtherTypes::Ipv4 => match Ipv4Packet::new(packet.payload()) {
                Some(ipv4_packet) => {
                    // Transport
                    transport = match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => match TcpPacket::new(ipv4_packet.payload()) {
                            Some(tcp_packet) => Some(Transport::Tcp(tcp::parse_tcp(&tcp_packet))),
                            None => None,
                        },
                        IpNextHeaderProtocols::Udp => match UdpPacket::new(ipv4_packet.payload()) {
                            Some(udp_packet) => Some(Transport::Udp(udp::parse_udp(&udp_packet))),
                            None => None,
                        },
                        _ => None,
                    };

                    Some(Network::Ipv4(ipv4::parse_ipv4(&ipv4_packet)))
                }
                None => None,
            },
            _ => None,
        };
        Indicator {
            packet: Some(packet),
            ethernet,
            network,
            transport,
        }
    }

    /// Maps from a `Indicator` to `ImmutableIndicator`.
    pub fn to_mutable(self) -> MutableIndicator {
        MutableIndicator {
            ethernet: self.ethernet.clone(),
            network: self.network.clone(),
            transport: self.transport.clone(),
        }
    }

    /// Get the Ethernet layer (copies contents).
    pub fn get_ethernet(&self) -> Ethernet {
        self.ethernet.clone()
    }
}

/// Represents a packet indicator which is mutable.
pub struct MutableIndicator {
    pub ethernet: Ethernet,
    pub network: Option<Network>,
    pub transport: Option<Transport>,
}

impl MutableIndicator {
    /// Creates a `MutableIndicator`.
    pub fn new(ethernet: Ethernet) -> MutableIndicator {
        MutableIndicator {
            ethernet,
            network: None,
            transport: None,
        }
    }
}
