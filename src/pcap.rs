use ipnetwork::IpNetwork;
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, MacAddr};
use pnet::packet::arp::{Arp, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, Ethernet, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4, Ipv4Flags, Ipv4Packet};
use pnet::packet::tcp::{Tcp, TcpPacket};
use pnet::packet::udp::{Udp, UdpPacket};
use pnet::packet::Packet;
use std::clone::Clone;
use std::cmp::{Eq, PartialEq};
use std::fmt::{self, Display, Formatter};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr};

/// Represents a network interface and its associated addresses.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Interface {
    pub name: String,
    pub alias: Option<String>,
    pub hardware_addr: MacAddr,
    pub ip_addrs: Vec<Ipv4Addr>,
    pub is_loopback: bool,
}

impl Interface {
    /// Construct a new empty `Interface`.
    pub fn new() -> Interface {
        Interface {
            name: String::new(),
            alias: None,
            hardware_addr: MacAddr::zero(),
            ip_addrs: vec![],
            is_loopback: false,
        }
    }

    // Opens the network interface for sending and receiving data.
    pub fn open(&self) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>), String> {
        let inters = datalink::interfaces();
        let inter = match inters
            .into_iter()
            .filter(|current_inter| current_inter.name == self.name)
            .next()
        {
            Some(int) => int,
            _ => return Err(format!("unknown interface {}", self.name)),
        };
        let (tx, rx) = match datalink::channel(&inter, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(format!("unhandled link type")),
            Err(e) => return Err(format!("{}", e)),
        };
        Ok((tx, rx))
    }
}

impl Display for Interface {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let name;
        if let Some(alias) = &self.alias {
            name = format!("{} ({})", self.name, alias);
        } else {
            name = self.name.clone();
        }

        let hardware_addr = format!(" [{}]", self.hardware_addr);

        let ip_addrs = format!(
            "{}",
            self.ip_addrs
                .iter()
                .map(|ip_addr| { ip_addr.to_string() })
                .collect::<Vec<String>>()
                .join(", ")
        );

        let mut flags = String::new();
        if self.is_loopback {
            flags = String::from(" (Loopback)");
        }

        write!(f, "{}{}{}: {}", name, hardware_addr, flags, ip_addrs)
    }
}

/// Gets a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<Interface> {
    let inters = datalink::interfaces();

    let ifs: Vec<Interface> = inters
        .iter()
        .map(|inter| {
            /*if !inter.is_up() {
                return Err(());
            }*/

            let mut i = Interface::new();
            i.name = inter.name.clone();
            i.hardware_addr = match inter.mac {
                Some(mac) => mac,
                None => return Err(()),
            };
            i.ip_addrs = inter
                .ips
                .iter()
                .map(|ip| match ip {
                    IpNetwork::V4(ipv4) => {
                        let ip = ipv4.ip();
                        if ip.is_unspecified() {
                            return Err(());
                        }
                        Ok(ip)
                    }
                    _ => Err(()),
                })
                .filter_map(Result::ok)
                .collect();
            if i.ip_addrs.len() <= 0 {
                return Err(());
            }
            i.is_loopback = inter.is_loopback();

            Ok(i)
        })
        .filter_map(Result::ok)
        .collect();

    ifs
}

pub mod arp;
pub mod ethernet;
mod ipv4;
pub mod layer;
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
                    let this_ipv4 = ipv4::parse_ipv4(&ipv4_packet);
                    let src = this_ipv4.source;
                    let dst = this_ipv4.destination;
                    let this_ipv4 = Some(layer::Layer::Ipv4(this_ipv4));
                    // Fragment
                    if ipv4_packet.get_flags() & Ipv4Flags::MoreFragments == 0
                        && ipv4_packet.get_fragment_offset() <= 0
                    {
                        transport = match ipv4_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                match TcpPacket::new(ipv4_packet.payload()) {
                                    Some(tcp_packet) => Some(layer::Layer::Tcp(
                                        tcp::parse_tcp(&tcp_packet),
                                        IpAddr::V4(src),
                                        IpAddr::V4(dst),
                                    )),
                                    None => None,
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                match UdpPacket::new(ipv4_packet.payload()) {
                                    Some(udp_packet) => Some(layer::Layer::Udp(
                                        udp::parse_udp(&udp_packet),
                                        IpAddr::V4(src),
                                        IpAddr::V4(dst),
                                    )),
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
                layer::Layer::Tcp(_, _, _) => Some(layer::LayerTypes::Tcp),
                layer::Layer::Udp(_, _, _) => Some(layer::LayerTypes::Udp),
                _ => None,
            },
            None => None,
        }
    }

    /// Get the TCP.
    pub fn get_tcp(&self) -> Option<&Tcp> {
        match self.get_transport() {
            Some(layer) => match layer {
                layer::Layer::Tcp(tcp, _, _) => Some(tcp),
                _ => None,
            },
            None => None,
        }
    }

    /// Get the UDP.
    pub fn get_udp(&self) -> Option<&Udp> {
        match self.get_transport() {
            Some(layer) => match layer {
                layer::Layer::Udp(udp, _, _) => Some(udp),
                _ => None,
            },
            None => None,
        }
    }
}

impl Display for Indicator {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let link_string = format!(
            "\n- {} ({} Bytes)",
            self.get_link(),
            layer_size(self.get_link())
        );
        let mut network_string = String::new();
        if let Some(network) = self.get_network() {
            network_string = format!("\n- {} ({} Bytes)", network, layer_size(network));
        }
        let mut transport_string = String::new();
        if let Some(transport) = self.get_transport() {
            transport_string = format!("\n- {} ({} Bytes)", transport, layer_size(transport));
        }

        write!(
            f,
            "Indicator{}{}{}",
            link_string, network_string, transport_string
        )
    }
}

// Get The size of a `Layer` when converted into a byte-array.
pub fn layer_size(layer: &layer::Layer) -> usize {
    match layer {
        layer::Layer::Ethernet(layer) => EthernetPacket::packet_size(layer),
        layer::Layer::Arp(layer) => ArpPacket::packet_size(layer),
        layer::Layer::Ipv4(layer) => Ipv4Packet::packet_size(layer),
        layer::Layer::Tcp(layer, _, _) => TcpPacket::packet_size(layer),
        layer::Layer::Udp(layer, _, _) => UdpPacket::packet_size(layer),
    }
}
