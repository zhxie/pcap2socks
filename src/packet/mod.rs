//! Support for serializing and deserializing packets.

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
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
use layer::icmpv4::Icmpv4;
use layer::ipv4::Ipv4;
use layer::tcp::Tcp;
use layer::udp::Udp;
use layer::{Layer, LayerKind, Layers};

/// Represents a packet indicator.
#[derive(Clone, Debug)]
pub struct Indicator {
    link: Layers,
    network: Option<Layers>,
    transport: Option<Layers>,
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
            EtherTypes::Arp => ArpPacket::new(packet.payload()).map(|arp_packet| Layers::Arp(Arp::parse(&arp_packet))),
            EtherTypes::Ipv4 => match Ipv4Packet::new(packet.payload()) {
                Some(ref ipv4_packet) => {
                    let ipv4 = Ipv4::parse(ipv4_packet);
                    // Fragment
                    if !ipv4.is_fragment() {
                        transport = match ipv4_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Icmp => {
                                IcmpPacket::new(ipv4_packet.payload())
                                    .map(|icmp_packet| Layers::Icmpv4(Icmpv4::parse(&icmp_packet)))
                            }
                            IpNextHeaderProtocols::Tcp => {
                                TcpPacket::new(ipv4_packet.payload())
                                    .map(|tcp_packet| Layers::Tcp(Tcp::parse(&tcp_packet, &ipv4)))
                            }
                            IpNextHeaderProtocols::Udp => {
                                UdpPacket::new(ipv4_packet.payload())
                                    .map(|udp_packet| Layers::Udp(Udp::parse(&udp_packet, &ipv4)))
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
        EthernetPacket::new(frame).map(|packet| Indicator::parse(&packet))
    }

    /// Returns the brief of the indicator.
    pub fn brief(&self) -> String {
        match self.network() {
            Some(network) => match network {
                Layers::Arp(arp) => format!("{}", arp),
                Layers::Ipv4(ipv4) => match self.transport() {
                    Some(transport) => match transport {
                        Layers::Icmpv4(icmpv4) => format!(
                            "{}: {} -> {}, {}",
                            icmpv4.kind(),
                            ipv4.src(),
                            ipv4.dst(),
                            icmpv4.description()
                        ),
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

    /// Returns The length of the indicator when converted into a byte-array.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        let mut size = 0;

        // Link
        size += self.link().len();
        // Network
        if let Some(network) = self.network() {
            size += network.len();
        }
        // Transport
        if let Some(transport) = self.transport() {
            size += transport.len();
        }

        size
    }

    /// Returns the content length of the indicator when converted into a byte-array.
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
        begin += m;
        total -= m;
        // Network
        if let Some(network) = self.network() {
            let m = network.serialize(&mut buffer[begin..], total)?;
            begin += m;
            total -= m;
        };
        // Transport
        if let Some(transport) = self.transport() {
            let m = transport.serialize(&mut buffer[begin..], total)?;
            begin += m;
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
        begin += m;
        total -= m;
        // Network
        if let Some(network) = self.network() {
            let m = network.serialize_with_payload(&mut buffer[begin..], payload, total)?;
            begin += m;
            total -= m;
        };
        // Transport
        if let Some(transport) = self.transport() {
            let m = transport.serialize_with_payload(&mut buffer[begin..], payload, total)?;
            begin += m;
        };

        Ok(begin)
    }

    /// Returns the link layer.
    pub fn link(&self) -> &Layers {
        &self.link
    }

    /// Returns the link layer kind.
    pub fn link_kind(&self) -> LayerKind {
        self.link().kind()
    }

    /// Returns the Ethernet layer.
    pub fn ethernet(&self) -> Option<&Ethernet> {
        if let Layers::Ethernet(layer) = &self.link() {
            return Some(layer);
        }

        None
    }

    /// Returns the network layer.
    pub fn network(&self) -> Option<&Layers> {
        if let Some(layer) = &self.network {
            return Some(layer);
        }

        None
    }

    /// Returns the network layer kind.
    pub fn network_kind(&self) -> Option<LayerKind> {
        if let Some(layer) = self.network() {
            return Some(layer.kind());
        }

        None
    }

    /// Returns the ARP layer.
    pub fn arp(&self) -> Option<&Arp> {
        #[allow(clippy::collapsible_match)]
        if let Some(layer) = self.network() {
            if let Layers::Arp(layer) = layer {
                return Some(layer);
            }
        }

        None
    }

    /// Returns the IPv4 layer.
    pub fn ipv4(&self) -> Option<&Ipv4> {
        #[allow(clippy::collapsible_match)]
        if let Some(layer) = self.network() {
            if let Layers::Ipv4(layer) = layer {
                return Some(layer);
            }
        }

        None
    }

    /// Returns the transport layer.
    pub fn transport(&self) -> Option<&Layers> {
        if let Some(layer) = &self.transport {
            return Some(layer);
        }

        None
    }

    /// Returns the transport layer kind.
    pub fn transport_kind(&self) -> Option<LayerKind> {
        if let Some(layer) = self.transport() {
            return Some(layer.kind());
        }

        None
    }

    /// Returns the ICMPv4 layer.
    pub fn icmpv4(&self) -> Option<&Icmpv4> {
        #[allow(clippy::collapsible_match)]
        if let Some(layer) = self.transport() {
            if let Layers::Icmpv4(layer) = layer {
                return Some(layer);
            }
        }

        None
    }

    /// Returns the TCP layer.
    pub fn tcp(&self) -> Option<&Tcp> {
        #[allow(clippy::collapsible_match)]
        if let Some(layer) = self.transport() {
            if let Layers::Tcp(layer) = layer {
                return Some(layer);
            }
        }

        None
    }

    /// Returns the UDP layer.
    pub fn udp(&self) -> Option<&Udp> {
        #[allow(clippy::collapsible_match)]
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

/// Represents the expire time of each group of fragments.
const EXPIRE_TIME: u128 = 10000;

/// Represents a fragmentation.
#[allow(dead_code)]
#[derive(Debug)]
pub struct Fragmentation {
    ethernet: Ethernet,
    ipv4: Ipv4,
    buffer: Vec<u8>,
    length: usize,
    total_length: Option<usize>,
    last_seen: Instant,
}

impl Fragmentation {
    /// Creates a `Fragmentation`.
    pub fn new(indicator: &Indicator) -> Option<Fragmentation> {
        let ethernet = match indicator.ethernet() {
            Some(ethernet) => ethernet,
            None => return None,
        };
        let ipv4 = match indicator.ipv4() {
            Some(ipv4) => ipv4,
            None => return None,
        };

        let frag = Fragmentation {
            ethernet: ethernet.clone(),
            ipv4: ipv4.clone(),
            buffer: vec![0; u16::MAX as usize],
            length: 0,
            total_length: None,
            last_seen: Instant::now(),
        };

        Some(frag)
    }

    /// Adds a fragmentation.
    pub fn add(&mut self, indicator: &Indicator, payload: &[u8]) {
        // Payload
        let ipv4 = match indicator.ipv4() {
            Some(ipv4) => ipv4,
            None => return,
        };
        let offset = (ipv4.fragment_offset() as usize) * 8;
        if !ipv4.is_more_fragment() {
            self.total_length = Some(offset + payload.len());
        }

        self.buffer[offset..offset + payload.len()].copy_from_slice(payload);
        self.length += payload.len();
    }

    /// Concatenates fragmentations and returns the transport layer and the payload.
    pub fn concatenate(&self) -> (Option<Layers>, &[u8]) {
        let transport = match self.ipv4.next_level_protocol() {
            IpNextHeaderProtocols::Icmp => {
                IcmpPacket::new(&self.buffer[..self.length])
                    .map(|icmp_packet| Layers::Icmpv4(Icmpv4::parse(&icmp_packet)))
            },
            IpNextHeaderProtocols::Tcp => {
                TcpPacket::new(&self.buffer[..self.length])
                    .map(|tcp_packet| Layers::Tcp(Tcp::parse(&tcp_packet, &self.ipv4)))
            },
            IpNextHeaderProtocols::Udp => {
                UdpPacket::new(&self.buffer[..self.length])
                    .map(|udp_packet| Layers::Udp(Udp::parse(&udp_packet, &self.ipv4)))
            },
            _ => None,
        };

        let header_size = match &transport {
            Some(transport) => transport.len(),
            None => 0,
        };
        (transport, &self.buffer[header_size..self.length])
    }

    /// Returns if the fragmentation is completed.
    pub fn is_completed(&self) -> bool {
        match self.total_length {
            Some(total_length) => self.length == total_length,
            None => false,
        }
    }

    /// Returns if the fragmentation is expired.
    pub fn is_expired(&self) -> bool {
        self.last_seen.elapsed().as_millis() > EXPIRE_TIME
    }
}

/// Represents a defragmentation machine.
#[derive(Debug, Default)]
pub struct Defraggler {
    frags: HashMap<(Ipv4Addr, Ipv4Addr, LayerKind, u16), Fragmentation>,
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

        let key = (ipv4.src(), ipv4.dst(), ipv4.kind(), ipv4.identification());

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

        // Add fragmentation
        let frag = self.frags.get_mut(&key).unwrap();
        let header_size = indicator.ethernet().unwrap().len() + ipv4.len();
        frag.add(indicator, &frame[header_size..]);
        if frag.is_completed() {
            self.frags.remove(&key)
        } else {
            None
        }
    }
}

#[test]
fn defraggler_add() {
    use layer::LayerKinds;

    let mut d = Defraggler::new();
    let ethernet = Ethernet::new(
        LayerKinds::Ipv4,
        "11:11:11:11:11:11".parse().unwrap(),
        "22:22:22:22:22:22".parse().unwrap(),
    )
    .unwrap();
    let mut b = vec![0u8; ethernet.len() + Ipv4::minimum_len() + Udp::minimum_len() + 8];

    let ipv4 = Ipv4::new_more_fragment(
        0,
        LayerKinds::Udp,
        0,
        "1.1.1.1".parse().unwrap(),
        "2.2.2.2".parse().unwrap(),
    )
    .unwrap();
    let udp = Udp::new(1, 2);
    let i = Indicator::new(
        Layers::Ethernet(ethernet.clone()),
        Some(Layers::Ipv4(ipv4)),
        Some(Layers::Udp(udp)),
    );
    let v = (0..8).into_iter().collect::<Vec<_>>();
    i.serialize_with_payload(b.as_mut_slice(), v.as_slice())
        .unwrap();

    let i = Indicator::from(b.as_slice()).unwrap();
    let r = d.add(&i, &b[..i.content_len()]);
    assert!(r.is_none());

    let ipv4 = Ipv4::new_last_fragment(
        0,
        LayerKinds::Udp,
        2,
        "1.1.1.1".parse().unwrap(),
        "2.2.2.2".parse().unwrap(),
    )
    .unwrap();
    let i = Indicator::new(Layers::Ethernet(ethernet), Some(Layers::Ipv4(ipv4)), None);
    let v = (8..16).into_iter().collect::<Vec<_>>();
    i.serialize_with_payload(b.as_mut_slice(), v.as_slice())
        .unwrap();

    let i = Indicator::from(b.as_slice()).unwrap();
    let f = d.add(&i, &b[..i.content_len()]).unwrap();
    let (_, p) = f.concatenate();

    assert_eq!(p, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
}
