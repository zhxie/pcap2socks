use pnet::packet::arp::{Arp, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, Ethernet, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4, Ipv4Flags, Ipv4Packet};
use pnet::packet::tcp::{Tcp, TcpPacket};
use pnet::packet::udp::{Udp, UdpPacket};
use pnet::packet::Packet;
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};

pub mod interface;
pub mod layer;

mod arp;
mod ethernet;
mod ipv4;
mod tcp;
mod udp;

/// Represents a packet indicator.
#[derive(Clone)]
pub struct Indicator {
    pub link: layer::Layer,
    pub network: Option<layer::Layer>,
    pub transport: Option<layer::Layer>,
}

impl Indicator {
    /// Creates a `Indicator`.
    pub fn new(ethernet: Ethernet) -> Indicator {
        Indicator {
            link: layer::Layer::Ethernet(ethernet),
            network: None,
            transport: None,
        }
    }

    /// Creates a `Indicator` by the given Ethernet packet.
    pub fn parse(packet: &EthernetPacket) -> Indicator {
        let mut transport = None;

        let link = layer::Layer::Ethernet(ethernet::parse_ethernet(packet));
        let network = match packet.get_ethertype() {
            EtherTypes::Arp => match ArpPacket::new(packet.payload()) {
                Some(arp_packet) => Some(layer::Layer::Arp(arp::parse_arp(&arp_packet))),
                None => None,
            },
            EtherTypes::Ipv4 => match Ipv4Packet::new(packet.payload()) {
                Some(ipv4_packet) => {
                    let this_ipv4 = Some(layer::Layer::Ipv4(ipv4::parse_ipv4(&ipv4_packet)));
                    // Fragment
                    if ipv4_packet.get_flags() & Ipv4Flags::MoreFragments == 0
                        && ipv4_packet.get_fragment_offset() <= 0
                    {
                        transport = match ipv4_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                match TcpPacket::new(ipv4_packet.payload()) {
                                    Some(tcp_packet) => {
                                        Some(layer::Layer::Tcp(tcp::parse_tcp(&tcp_packet)))
                                    }
                                    None => None,
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                match UdpPacket::new(ipv4_packet.payload()) {
                                    Some(udp_packet) => {
                                        Some(layer::Layer::Udp(udp::parse_udp(&udp_packet)))
                                    }
                                    None => None,
                                }
                            }
                            _ => None,
                        };
                    }

                    this_ipv4
                }
                None => None,
            },
            _ => None,
        };

        Indicator {
            link,
            network,
            transport,
        }
    }

    /// Get the link layer.
    pub fn get_link(&self) -> &layer::Layer {
        &self.link
    }

    /// Get the `Ethernet`.
    pub fn get_ethernet(&self) -> &Ethernet {
        if let layer::Layer::Ethernet(layer) = &self.link {
            return layer;
        }

        panic!("unexpected link layer")
    }

    /// Get the network layer.
    pub fn get_network(&self) -> Option<&layer::Layer> {
        match &self.network {
            Some(layer) => Some(layer),
            None => None,
        }
    }

    /// Get the network layer type.
    pub fn get_network_type(&self) -> Option<layer::LayerType> {
        match self.get_network() {
            Some(layer) => match layer {
                layer::Layer::Arp(_) => Some(layer::LayerTypes::Arp),
                layer::Layer::Ipv4(_) => Some(layer::LayerTypes::Ipv4),
                _ => None,
            },
            None => None,
        }
    }

    /// Get the ARP.
    pub fn get_arp(&self) -> Option<&Arp> {
        match self.get_network() {
            Some(layer) => match layer {
                layer::Layer::Arp(arp) => Some(arp),
                _ => None,
            },
            None => None,
        }
    }

    /// Get the IPv4.
    pub fn get_ipv4(&self) -> Option<&Ipv4> {
        match self.get_network() {
            Some(layer) => match layer {
                layer::Layer::Ipv4(ipv4) => Some(ipv4),
                _ => None,
            },
            None => None,
        }
    }

    /// Get the transport layer.
    pub fn get_transport(&self) -> Option<&layer::Layer> {
        match &self.transport {
            Some(layer) => Some(layer),
            None => None,
        }
    }

    /// Get the transport layer type.
    pub fn get_transport_type(&self) -> Option<layer::LayerType> {
        match self.get_transport() {
            Some(layer) => match layer {
                layer::Layer::Tcp(_) => Some(layer::LayerTypes::Tcp),
                layer::Layer::Udp(_) => Some(layer::LayerTypes::Udp),
                _ => None,
            },
            None => None,
        }
    }

    /// Get the TCP.
    pub fn get_tcp(&self) -> Option<&Tcp> {
        match self.get_transport() {
            Some(layer) => match layer {
                layer::Layer::Tcp(tcp) => Some(tcp),
                _ => None,
            },
            None => None,
        }
    }

    /// Get the UDP.
    pub fn get_udp(&self) -> Option<&Udp> {
        match self.get_transport() {
            Some(layer) => match layer {
                layer::Layer::Udp(udp) => Some(udp),
                _ => None,
            },
            None => None,
        }
    }
}

impl Display for Indicator {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut network_string = String::new();
        if let Some(network) = self.get_network() {
            network_string = format!("\n- {}", network);
        }
        let mut transport_string = String::new();
        if let Some(transport) = self.get_transport() {
            transport_string = format!("\n- {}", transport);
        }

        write!(
            f,
            "Indicator\n- {}{}{}",
            self.get_link(),
            network_string,
            transport_string
        )
    }
}

// Get The size of a `Layer` when converted into a byte-array.
pub fn layer_size(layer: &layer::Layer) -> usize {
    match layer {
        layer::Layer::Ethernet(layer) => EthernetPacket::packet_size(layer),
        layer::Layer::Arp(layer) => ArpPacket::packet_size(layer),
        layer::Layer::Ipv4(layer) => Ipv4Packet::packet_size(layer),
        layer::Layer::Tcp(layer) => TcpPacket::packet_size(layer),
        layer::Layer::Udp(layer) => UdpPacket::packet_size(layer),
    }
}
