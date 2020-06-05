use pnet::packet::arp::{Arp, ArpOperations};
use pnet::packet::ethernet::Ethernet;
use pnet::packet::ipv4::{Ipv4, Ipv4Flags};
use pnet::packet::tcp::{Tcp, TcpFlags};
use pnet::packet::udp::Udp;
use std::clone::Clone;
use std::cmp::{Eq, PartialEq};
use std::fmt::{self, Display, Formatter};

/// Represents the type of the layer.
#[derive(Clone, Eq, PartialEq)]
pub struct LayerType(u8);

impl Display for LayerType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                &LayerTypes::Ethernet => "Ethernet",
                &LayerTypes::Arp => "ARP",
                &LayerTypes::Ipv4 => "IPv4",
                &LayerTypes::Tcp => "TCP",
                &LayerTypes::Udp => "UDP",
                _ => "unknown",
            }
        )
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod LayerTypes {
    use super::LayerType;

    // Ethernet
    pub const Ethernet: LayerType = LayerType(0);
    // ARP
    pub const Arp: LayerType = LayerType(1);
    // IPv4
    pub const Ipv4: LayerType = LayerType(2);
    // TCP
    pub const Tcp: LayerType = LayerType(3);
    // UDP
    pub const Udp: LayerType = LayerType(4);
}

/// Represents a layer.
#[derive(Clone)]
pub enum Layer {
    Ethernet(Ethernet),
    Arp(Arp),
    Ipv4(Ipv4),
    Tcp(Tcp),
    Udp(Udp),
}

impl Display for Layer {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Layer::Ethernet(layer) => format!(
                    "{}: {} -> {}",
                    LayerTypes::Ethernet,
                    layer.source,
                    layer.destination
                ),
                Layer::Arp(layer) => format!(
                    "{}: {} -> {}, Operation = {}",
                    LayerTypes::Arp,
                    layer.sender_proto_addr,
                    layer.target_proto_addr,
                    match layer.operation {
                        ArpOperations::Request => "Request",
                        ArpOperations::Reply => "Reply",
                        _ => "unknown",
                    }
                ),
                Layer::Ipv4(layer) => {
                    let mut fragment = String::new();
                    if layer.flags & Ipv4Flags::MoreFragments != 0 || layer.fragment_offset > 0 {
                        fragment = format!(", Fragment = {}", layer.fragment_offset);
                    }

                    format!(
                        "{}: {} -> {}, Length = {}{}",
                        LayerTypes::Ipv4,
                        layer.source,
                        layer.destination,
                        layer.total_length,
                        fragment
                    )
                }
                Layer::Tcp(layer) => {
                    let mut flags = String::new();
                    if layer.flags & TcpFlags::ACK != 0 {
                        flags = flags + "A";
                    }
                    if layer.flags & TcpFlags::RST != 0 {
                        flags = flags + "R";
                    }
                    if layer.flags & TcpFlags::SYN != 0 {
                        flags = flags + "S";
                    }
                    if layer.flags & TcpFlags::FIN != 0 {
                        flags = flags + "F";
                    }
                    if !flags.is_empty() {
                        flags = String::from(" [") + &flags + "]";
                    }

                    format!(
                        "{}: {} -> {}{}",
                        LayerTypes::Tcp,
                        layer.source,
                        layer.destination,
                        flags
                    )
                }
                Layer::Udp(layer) => format!(
                    "{}: {} -> {}, Length = {}",
                    LayerTypes::Udp,
                    layer.source,
                    layer.destination,
                    layer.length
                ),
            }
        )
    }
}
