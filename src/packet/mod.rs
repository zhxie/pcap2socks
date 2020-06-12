use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::fmt::{self, Display, Formatter};
use std::io;

pub mod layer;
use layer::arp::Arp;
use layer::ethernet::Ethernet;
use layer::ipv4::Ipv4;
use layer::tcp::Tcp;
use layer::udp::Udp;
use layer::{Layer, LayerType, LayerTypes, Layers};

/// Represents a packet indicator.
#[derive(Debug)]
pub struct Indicator {
    pub link: Layers,
    pub network: Option<Layers>,
    pub transport: Option<Layers>,
}

impl Indicator {
    /// Creates a `Indicator`.
    pub fn new(link: Layers, network: Option<Layers>, transport: Option<Layers>) -> Indicator {
        Indicator {
            link,
            network,
            transport,
        }
    }

    /// Creates a `Indicator` by the given Ethernet packet.
    pub fn parse(packet: &EthernetPacket) -> Indicator {
        let mut transport = None;

        let link = Layers::Ethernet(Ethernet::parse(packet));
        let network = match packet.get_ethertype() {
            EtherTypes::Arp => match ArpPacket::new(packet.payload()) {
                Some(ref arp_packet) => Some(Layers::Arp(Arp::parse(arp_packet))),
                None => None,
            },
            EtherTypes::Ipv4 => match Ipv4Packet::new(packet.payload()) {
                Some(ref ipv4_packet) => {
                    let this_ipv4 = Ipv4::parse(ipv4_packet);
                    let src = this_ipv4.get_src();
                    let dst = this_ipv4.get_dst();
                    let this_ipv4 = Some(Layers::Ipv4(this_ipv4));
                    // Fragment
                    if ipv4_packet.get_flags() & Ipv4Flags::MoreFragments == 0
                        && ipv4_packet.get_fragment_offset() <= 0
                    {
                        transport = match ipv4_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                match TcpPacket::new(ipv4_packet.payload()) {
                                    Some(ref tcp_packet) => {
                                        Some(Layers::Tcp(Tcp::parse(tcp_packet, src, dst)))
                                    }
                                    None => None,
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                match UdpPacket::new(ipv4_packet.payload()) {
                                    Some(ref udp_packet) => {
                                        Some(Layers::Udp(Udp::parse(udp_packet, src, dst)))
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

    /// Creates a `Indicator` by the given frame.
    pub fn from(frame: &[u8]) -> Option<Indicator> {
        match EthernetPacket::new(frame) {
            Some(ref packet) => Some(Indicator::parse(packet)),
            None => None,
        }
    }

    /// Get the brief of the `Indicator`.
    pub fn brief(&self) -> String {
        match self.get_network_type() {
            Some(t) => match t {
                LayerTypes::Arp => {
                    let layer = self.get_arp().unwrap();
                    format!(
                        "{}: {} -> {}",
                        layer.get_type(),
                        layer.get_src(),
                        layer.get_dst()
                    )
                }
                LayerTypes::Ipv4 => match self.get_transport_type() {
                    Some(t) => match t {
                        LayerTypes::Tcp => {
                            let layer = self.get_tcp().unwrap();
                            format!(
                                "{}: {}:{} -> {}:{}",
                                layer.get_type(),
                                layer.get_src_ip_addr(),
                                layer.get_src(),
                                layer.get_dst_ip_addr(),
                                layer.get_dst()
                            )
                        }
                        LayerTypes::Udp => {
                            let layer = self.get_udp().unwrap();
                            format!(
                                "{}: {}:{} -> {}:{}",
                                layer.get_type(),
                                layer.get_src_ip_addr(),
                                layer.get_src(),
                                layer.get_dst_ip_addr(),
                                layer.get_dst()
                            )
                        }
                        _ => unreachable!(),
                    },
                    None => {
                        let layer = self.get_ipv4().unwrap();
                        format!(
                            "{}: {} -> {}",
                            layer.get_type(),
                            layer.get_src(),
                            layer.get_dst()
                        )
                    }
                },
                _ => unreachable!(),
            },
            None => match self.get_link_type() {
                LayerTypes::Ethernet => {
                    let layer = self.get_ethernet().unwrap();
                    format!(
                        "{}: {} -> {}",
                        layer.get_type(),
                        layer.get_src(),
                        layer.get_dst()
                    )
                }
                _ => unreachable!(),
            },
        }
    }

    /// Get The size of the `Indicator` when converted into a byte-array.
    pub fn get_size(&self) -> usize {
        let mut size = 0;

        // Link
        size = size + self.get_link().get_size();
        // Network
        if let Some(network) = self.get_network() {
            size = size + network.get_size();
        }
        // Transport
        if let Some(transport) = self.get_transport() {
            size = size + transport.get_size();
        }

        size
    }

    /// Serialize the `Indicator` into a byte-array.
    pub fn serialize(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut begin = 0;

        // Link
        begin = begin + self.get_link().serialize(&mut buffer[begin..])?;
        // Network
        if let Some(network) = self.get_network() {
            begin = begin + network.serialize(&mut buffer[begin..])?;
        }
        // Transport
        if let Some(transport) = self.get_transport() {
            begin = begin + transport.serialize(&mut buffer[begin..])?;
        }

        Ok(begin)
    }

    /// Serialize the `Indicator` into a byte-array with payload.
    pub fn serialize_with_payload(&self, buffer: &mut [u8], payload: &[u8]) -> io::Result<usize> {
        let mut begin = 0;
        let mut total = self.get_size() + payload.len();

        // Link
        let m = self
            .get_link()
            .serialize_with_payload(&mut buffer[begin..], payload, total)?;
        begin = begin + m;
        total = total - m;
        // Network
        if let Some(network) = self.get_network() {
            let m = network.serialize_with_payload(&mut buffer[begin..], payload, total)?;
            begin = begin + m;
            total = total - m;
        };
        // Transport
        if let Some(transport) = self.get_transport() {
            let m = transport.serialize_with_payload(&mut buffer[begin..], payload, total)?;
            begin = begin + m;
        };

        Ok(begin)
    }

    /// Get the link layer.
    pub fn get_link(&self) -> &Layers {
        &self.link
    }

    /// Get the link layer type.
    pub fn get_link_type(&self) -> LayerType {
        self.get_link().get_type()
    }

    /// Get the `Ethernet`.
    pub fn get_ethernet(&self) -> Option<&Ethernet> {
        if let Layers::Ethernet(layer) = &self.get_link() {
            return Some(layer);
        }

        None
    }

    /// Get the network layer.
    pub fn get_network(&self) -> Option<&Layers> {
        if let Some(layer) = &self.network {
            return Some(layer);
        }

        None
    }

    /// Get the network layer type.
    pub fn get_network_type(&self) -> Option<LayerType> {
        if let Some(layer) = self.get_network() {
            return Some(layer.get_type());
        }

        None
    }

    /// Get the ARP.
    pub fn get_arp(&self) -> Option<&Arp> {
        if let Some(layer) = self.get_network() {
            if let Layers::Arp(layer) = layer {
                return Some(layer);
            }
        }

        None
    }

    /// Get the IPv4.
    pub fn get_ipv4(&self) -> Option<&Ipv4> {
        if let Some(layer) = self.get_network() {
            if let Layers::Ipv4(layer) = layer {
                return Some(layer);
            }
        }

        None
    }

    /// Get the transport layer.
    pub fn get_transport(&self) -> Option<&Layers> {
        if let Some(layer) = &self.transport {
            return Some(layer);
        }

        None
    }

    /// Get the transport layer type.
    pub fn get_transport_type(&self) -> Option<LayerType> {
        if let Some(layer) = self.get_transport() {
            return Some(layer.get_type());
        }

        None
    }

    /// Get the TCP.
    pub fn get_tcp(&self) -> Option<&Tcp> {
        if let Some(layer) = self.get_transport() {
            if let Layers::Tcp(layer) = layer {
                return Some(layer);
            }
        }

        None
    }

    /// Get the UDP.
    pub fn get_udp(&self) -> Option<&Udp> {
        if let Some(layer) = self.get_transport() {
            if let Layers::Udp(layer) = layer {
                return Some(layer);
            }
        }

        None
    }
}

impl Display for Indicator {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let link_string = format!("\n- {} ({} Bytes)", self.link, self.link.get_size());
        let mut network_string = String::new();
        if let Some(network) = &self.network {
            network_string = format!("\n- {} ({} Bytes)", network, network.get_size());
        }
        let mut transport_string = String::new();
        if let Some(transport) = &self.transport {
            transport_string = format!("\n- {} ({} Bytes)", transport, transport.get_size());
        }

        write!(
            f,
            "Indicator{}{}{}",
            link_string, network_string, transport_string
        )
    }
}
