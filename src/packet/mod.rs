//! Support for serializing and deserializing packets.

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::Ipv4Addr;
use std::time::Instant;

pub mod layer;
use layer::arp::Arp;
use layer::ethernet::Ethernet;
use layer::ipv4::Ipv4;
use layer::tcp::Tcp;
use layer::udp::Udp;
use layer::{Layer, LayerKind, Layers};

/// Represents a packet indicator.
#[derive(Clone, Debug)]
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
                    let ipv4 = Ipv4::parse(ipv4_packet);
                    // Fragment
                    if ipv4_packet.get_flags() & Ipv4Flags::MoreFragments == 0
                        && ipv4_packet.get_fragment_offset() <= 0
                    {
                        transport = match ipv4_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                match TcpPacket::new(ipv4_packet.payload()) {
                                    Some(ref tcp_packet) => {
                                        Some(Layers::Tcp(Tcp::parse(tcp_packet, &ipv4)))
                                    }
                                    None => None,
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                match UdpPacket::new(ipv4_packet.payload()) {
                                    Some(ref udp_packet) => {
                                        Some(Layers::Udp(Udp::parse(udp_packet, &ipv4)))
                                    }
                                    None => None,
                                }
                            }
                            _ => None,
                        };
                    }

                    Some(Layers::Ipv4(ipv4))
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

    /// Get the brief of the indicator.
    pub fn brief(&self) -> String {
        match self.network() {
            Some(network) => match network {
                Layers::Arp(arp) => format!("{}", arp),
                Layers::Ipv4(ipv4) => match self.transport() {
                    Some(transport) => match transport {
                        Layers::Tcp(tcp) => format!(
                            "{}: {}:{} -> {}:{} {}",
                            tcp.kind(),
                            tcp.src_ip_addr(),
                            tcp.src(),
                            tcp.dst_ip_addr(),
                            tcp.dst(),
                            tcp.flag_string(),
                        ),
                        Layers::Udp(udp) => format!(
                            "{}: {}:{} -> {}:{}, Length = {}",
                            udp.kind(),
                            udp.src_ip_addr(),
                            udp.src(),
                            udp.dst_ip_addr(),
                            udp.dst(),
                            udp.length(),
                        ),
                        _ => unreachable!(),
                    },
                    None => format!("{}", ipv4),
                },
                _ => unreachable!(),
            },
            None => match self.link() {
                Layers::Ethernet(ethernet) => format!("{}", ethernet),
                _ => unreachable!(),
            },
        }
    }

    /// Get The length of the indicator when converted into a byte-array.
    pub fn len(&self) -> usize {
        let mut size = 0;

        // Link
        size = size + self.link().len();
        // Network
        if let Some(network) = self.network() {
            size = size + network.len();
        }
        // Transport
        if let Some(transport) = self.transport() {
            size = size + transport.len();
        }

        size
    }

    /// Get the content length of the indicator when converted into a byte-array.
    pub fn content_len(&self) -> usize {
        match self.link() {
            Layers::Ethernet(ethernet) => match self.network() {
                Some(network) => match network {
                    Layers::Arp(arp) => ethernet.len() + arp.len(),
                    Layers::Ipv4(ipv4) => ethernet.len() + ipv4.total_length() as usize,
                    _ => unreachable!(),
                },
                None => ethernet.len(),
            },
            _ => unreachable!(),
        }
    }

    /// Serialize the indicator into a byte-array.
    pub fn serialize(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut begin = 0;
        let mut total = self.len();

        // Link
        let m = self.link().serialize(&mut buffer[begin..], total)?;
        begin = begin + m;
        total = total - m;
        // Network
        if let Some(network) = self.network() {
            let m = network.serialize(&mut buffer[begin..], total)?;
            begin = begin + m;
            total = total - m;
        };
        // Transport
        if let Some(transport) = self.transport() {
            let m = transport.serialize(&mut buffer[begin..], total)?;
            begin = begin + m;
        };

        Ok(begin)
    }

    /// Serialize the indicator into a byte-array with payload.
    pub fn serialize_with_payload(&self, buffer: &mut [u8], payload: &[u8]) -> io::Result<usize> {
        let mut begin = 0;
        let mut total = self.len() + payload.len();

        // Link
        let m = self
            .link()
            .serialize_with_payload(&mut buffer[begin..], payload, total)?;
        begin = begin + m;
        total = total - m;
        // Network
        if let Some(network) = self.network() {
            let m = network.serialize_with_payload(&mut buffer[begin..], payload, total)?;
            begin = begin + m;
            total = total - m;
        };
        // Transport
        if let Some(transport) = self.transport() {
            let m = transport.serialize_with_payload(&mut buffer[begin..], payload, total)?;
            begin = begin + m;
        };

        Ok(begin)
    }

    /// Get the link layer.
    pub fn link(&self) -> &Layers {
        &self.link
    }

    /// Get the link layer kind.
    pub fn link_kind(&self) -> LayerKind {
        self.link().kind()
    }

    /// Get the Ethernet layer.
    pub fn ethernet(&self) -> Option<&Ethernet> {
        if let Layers::Ethernet(layer) = &self.link() {
            return Some(layer);
        }

        None
    }

    /// Get the network layer.
    pub fn network(&self) -> Option<&Layers> {
        if let Some(layer) = &self.network {
            return Some(layer);
        }

        None
    }

    /// Get the network layer kind.
    pub fn network_kind(&self) -> Option<LayerKind> {
        if let Some(layer) = self.network() {
            return Some(layer.kind());
        }

        None
    }

    /// Get the ARP layer.
    pub fn arp(&self) -> Option<&Arp> {
        if let Some(layer) = self.network() {
            if let Layers::Arp(layer) = layer {
                return Some(layer);
            }
        }

        None
    }

    /// Get the IPv4 layer.
    pub fn ipv4(&self) -> Option<&Ipv4> {
        if let Some(layer) = self.network() {
            if let Layers::Ipv4(layer) = layer {
                return Some(layer);
            }
        }

        None
    }

    /// Get the transport layer.
    pub fn transport(&self) -> Option<&Layers> {
        if let Some(layer) = &self.transport {
            return Some(layer);
        }

        None
    }

    /// Get the transport layer kind.
    pub fn transport_kind(&self) -> Option<LayerKind> {
        if let Some(layer) = self.transport() {
            return Some(layer.kind());
        }

        None
    }

    /// Get the TCP layer.
    pub fn tcp(&self) -> Option<&Tcp> {
        if let Some(layer) = self.transport() {
            if let Layers::Tcp(layer) = layer {
                return Some(layer);
            }
        }

        None
    }

    /// Get the UDP layer.
    pub fn udp(&self) -> Option<&Udp> {
        if let Some(layer) = self.transport() {
            if let Layers::Udp(layer) = layer {
                return Some(layer);
            }
        }

        None
    }
}

impl Display for Indicator {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let link_string = format!("\n- {} ({} Bytes)", self.link, self.link.len());
        let mut network_string = String::new();
        if let Some(network) = &self.network {
            network_string = format!("\n- {} ({} Bytes)", network, network.len());
        }
        let mut transport_string = String::new();
        if let Some(transport) = &self.transport {
            transport_string = format!("\n- {} ({} Bytes)", transport, transport.len());
        }

        write!(
            f,
            "Indicator{}{}{}",
            link_string, network_string, transport_string
        )
    }
}

const EXPIRE_TIME: u128 = 10000;

/// Represents a fragmentation.
#[derive(Debug)]
pub struct Fragmentation {
    ethernet: Ethernet,
    ipv4: Ipv4,
    transport: Option<Layers>,
    buffer: Vec<u8>,
    last_seen: Instant,
    length: usize,
}

impl Fragmentation {
    /// Creates a `Fragmentation`.
    pub fn new(indicator: &Indicator) -> Option<Fragmentation> {
        let new_ipv4 = match indicator.ipv4() {
            Some(ref ipv4) => Ipv4::defrag(ipv4),
            None => return None,
        };
        let ethernet = match indicator.ethernet() {
            Some(ethernet) => ethernet,
            None => return None,
        };

        let mut frag = Fragmentation {
            ethernet: ethernet.clone(),
            ipv4: new_ipv4.clone(),
            transport: None,
            buffer: vec![0; u16::MAX as usize],
            last_seen: Instant::now(),
            length: 0,
        };

        // Indicator
        let new_indicator = Indicator::new(
            Layers::Ethernet(ethernet.clone()),
            Some(Layers::Ipv4(new_ipv4)),
            None,
        );

        // Serialize
        if let Err(_) = new_indicator.serialize(&mut frag.buffer[0..]) {
            return None;
        }

        Some(frag)
    }

    /// Adds a fragmentation.
    pub fn add(&mut self, indicator: &Indicator, payload: &[u8]) {
        // Transport
        if let None = self.transport {
            if let Some(transport) = indicator.transport() {
                self.transport = Some(transport.clone());
            }
        }

        // Payload
        let ipv4 = match indicator.ipv4() {
            Some(ipv4) => ipv4,
            None => return,
        };
        let offset = (ipv4.fragment_offset() as usize) * 8;
        let header_size = self.ethernet.len() + self.ipv4.len();

        self.buffer[header_size + offset..header_size + offset + payload.len()]
            .copy_from_slice(payload);
        self.length += payload.len();
    }

    /// Concatenates fragmentations and returns an indicator of the frame and the frame itself.
    pub fn concatenate(&self) -> (Indicator, &[u8]) {
        let new_indicator = Indicator::new(
            Layers::Ethernet(self.ethernet.clone()),
            Some(Layers::Ipv4(self.ipv4.clone())),
            self.transport.clone(),
        );

        let header_size = self.ethernet.len() + self.ipv4.len();

        (new_indicator, &self.buffer[0..header_size + self.length])
    }

    /// Returns if the fragmentation is completed.
    pub fn is_completed(&self) -> bool {
        self.length == self.ipv4.total_length() as usize - self.ipv4.len()
    }

    /// Returns if the fragmentation is expired.
    pub fn is_expired(&self) -> bool {
        self.last_seen.elapsed().as_millis() > EXPIRE_TIME
    }
}

/// Represents a defragmentation machine.
#[derive(Debug)]
pub struct Defraggler {
    frags: HashMap<(Ipv4Addr, Ipv4Addr, u16), Fragmentation>,
}

impl Defraggler {
    /// Creates a new empty `Defraggler`.
    pub fn new() -> Defraggler {
        Defraggler {
            frags: HashMap::new(),
        }
    }

    /// Adds a fragmentation and returns the fragmentation if it is completed.
    pub fn add(&mut self, indicator: &Indicator, frame: &[u8]) -> Option<Fragmentation> {
        let ipv4 = match indicator.ipv4() {
            Some(ipv4) => ipv4,
            None => return None,
        };

        let key = (ipv4.src(), ipv4.dst(), ipv4.identification());

        let is_create = match self.frags.get(&key) {
            Some(frag) => frag.is_expired(),
            None => true,
        };

        if is_create {
            let frag = match Fragmentation::new(indicator) {
                Some(frag) => frag,
                None => return None,
            };

            self.frags.insert(key, frag);
        }

        let frag = self.frags.get_mut(&key).unwrap();

        // Add fragmentation
        let header_size = indicator.ethernet().unwrap().len() + ipv4.len();
        frag.add(indicator, &frame[header_size..]);
        if frag.is_completed() {
            self.frags.remove(&key)
        } else {
            None
        }
    }
}
