use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, MacAddr};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::clone::Clone;
use std::cmp::{Eq, PartialEq};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::hash::Hash;
use std::io;
use std::net::Ipv4Addr;
use std::result;

pub mod arp;
pub mod ethernet;
pub mod ipv4;
pub mod layer;
pub mod tcp;
pub mod udp;
use layer::{Layer, LayerType, LayerTypes, Layers, SerializeResult};

/// Represents an error when handle pcap interfaces.
#[derive(Debug)]
pub enum PcapError {
    OpenInterfaceError(io::Error),
    SendError(io::Error),
    ReceiveError(io::Error),
    ReceiveTimeOutError(io::Error),
}

impl Display for PcapError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match &self {
            PcapError::OpenInterfaceError(ref e) => write!(f, "open interface: {}", e),
            PcapError::SendError(ref e) => write!(f, "send: {}", e),
            PcapError::ReceiveError(ref e) => write!(f, "receive: {}", e),
            PcapError::ReceiveTimeOutError(ref e) => write!(f, "receive: {}", e),
        }
    }
}

impl Error for PcapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            PcapError::OpenInterfaceError(ref e) => Some(e),
            PcapError::SendError(ref e) => Some(e),
            PcapError::ReceiveError(ref e) => Some(e),
            PcapError::ReceiveTimeOutError(ref e) => Some(e),
        }
    }
}

type Result<T> = result::Result<T, PcapError>;

/// Represents the channel sending packets to the pcap.
pub struct Sender {
    tx: Box<dyn DataLinkSender>,
}

impl Sender {
    /// Creates a new `Sender`.
    pub fn new(tx: Box<dyn DataLinkSender>) -> Sender {
        Sender { tx }
    }

    /// Send a packet.
    pub fn send_to(&mut self, packet: &[u8]) -> Result<()> {
        match self.tx.send_to(packet, None) {
            Some(r) => match r {
                Ok(_) => Ok(()),
                Err(e) => Err(PcapError::SendError(e)),
            },
            None => Ok(()),
        }
    }
}

/// Represents the channel receiving packets from the pcap.
pub struct Receiver {
    rx: Box<dyn DataLinkReceiver>,
}

impl Receiver {
    /// Creates a new `Receiver`.
    pub fn new(rx: Box<dyn DataLinkReceiver>) -> Receiver {
        Receiver { rx }
    }

    /// Get the next frame in the channel.
    pub fn next(&mut self) -> Result<&[u8]> {
        match self.rx.next() {
            Ok(frame) => Ok(frame),
            Err(e) => {
                if e.kind() == io::ErrorKind::TimedOut {
                    Err(PcapError::ReceiveTimeOutError(e))
                } else {
                    Err(PcapError::ReceiveError(e))
                }
            }
        }
    }
}

/// Represents a network interface and its associated addresses.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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
    pub fn open(&self) -> Result<(Sender, Receiver)> {
        let inters = datalink::interfaces();
        let inter = inters
            .into_iter()
            .filter(|current_inter| current_inter.name == self.name)
            .next()
            .ok_or(PcapError::OpenInterfaceError(io::Error::from(
                io::ErrorKind::NotFound,
            )))?;

        match datalink::channel(&inter, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => Ok((Sender::new(tx), Receiver::new(rx))),
            Ok(_) => Err(PcapError::OpenInterfaceError(io::Error::from(
                io::ErrorKind::InvalidInput,
            ))),
            Err(e) => Err(PcapError::OpenInterfaceError(e)),
        }
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
                    ipnetwork::IpNetwork::V4(ref ipv4) => Ok(ipv4.ip()),
                    _ => Err(()),
                })
                .filter_map(result::Result::ok)
                .collect();
            if i.ip_addrs.len() <= 0 {
                return Err(());
            }
            i.is_loopback = inter.is_loopback();

            Ok(i)
        })
        .filter_map(result::Result::ok)
        .collect();

    ifs
}

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

        let link = Layers::Ethernet(ethernet::Ethernet::parse(packet));
        let network = match packet.get_ethertype() {
            EtherTypes::Arp => match ArpPacket::new(packet.payload()) {
                Some(ref arp_packet) => Some(Layers::Arp(arp::Arp::parse(arp_packet))),
                None => None,
            },
            EtherTypes::Ipv4 => match Ipv4Packet::new(packet.payload()) {
                Some(ref ipv4_packet) => {
                    let this_ipv4 = ipv4::Ipv4::parse(ipv4_packet);
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
                                        Some(Layers::Tcp(tcp::Tcp::parse(tcp_packet, src, dst)))
                                    }
                                    None => None,
                                }
                            }
                            IpNextHeaderProtocols::Udp => {
                                match UdpPacket::new(ipv4_packet.payload()) {
                                    Some(ref udp_packet) => {
                                        Some(Layers::Udp(udp::Udp::parse(udp_packet, src, dst)))
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
    pub fn serialize(&self, buffer: &mut [u8]) -> SerializeResult {
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

    /// Recalculate the length and serialize the `Indicator` into a byte-array.
    pub fn serialize_n(&self, buffer: &mut [u8], n: usize) -> SerializeResult {
        let mut begin = 0;
        let mut total = n;

        // Link
        let m = self.get_link().serialize_n(&mut buffer[begin..], total)?;
        begin = begin + m;
        total = total - m;
        // Network
        if let Some(network) = self.get_network() {
            let m = network.serialize_n(&mut buffer[begin..], total)?;
            begin = begin + m;
            total = total - m;
        };
        // Transport
        if let Some(transport) = self.get_transport() {
            let m = transport.serialize_n(&mut buffer[begin..], total)?;
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
    pub fn get_ethernet(&self) -> Option<&ethernet::Ethernet> {
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
    pub fn get_arp(&self) -> Option<&arp::Arp> {
        if let Some(layer) = self.get_network() {
            if let Layers::Arp(layer) = layer {
                return Some(layer);
            }
        }

        None
    }

    /// Get the IPv4.
    pub fn get_ipv4(&self) -> Option<&ipv4::Ipv4> {
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
    pub fn get_tcp(&self) -> Option<&tcp::Tcp> {
        if let Some(layer) = self.get_transport() {
            if let Layers::Tcp(layer) = layer {
                return Some(layer);
            }
        }

        None
    }

    /// Get the UDP.
    pub fn get_udp(&self) -> Option<&udp::Udp> {
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
