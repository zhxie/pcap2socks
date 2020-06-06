use std::clone::Clone;
use std::cmp::{Eq, PartialEq};
use std::fmt::{self, Display, Formatter};
use std::hash::Hash;

/// Represents the type of the layer.
#[derive(Clone, Eq, Hash, PartialEq)]
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
pub trait Layer: Display {
    // Get the type of the `Layer`.
    fn get_type(&self) -> LayerType;

    // Get The size of the `Layer` when converted into a byte-array.
    fn get_size(&self) -> usize;

    // Serialize the `Layer` into a byte-array.
    fn serialize(&self, buffer: &mut [u8]) -> Result<(), String>;

    // Recalculate the length and serialize the `Layer` into a byte-array.
    fn serialize_n(&self, n: usize, buffer: &mut [u8]) -> Result<usize, String>;
}

use super::arp;
use super::ethernet;
use super::ipv4;
use super::tcp;
use super::udp;

#[derive(Debug, Clone)]
pub enum Layers {
    Ethernet(ethernet::Ethernet),
    Arp(arp::Arp),
    Ipv4(ipv4::Ipv4),
    Tcp(tcp::Tcp),
    Udp(udp::Udp),
}

impl Display for Layers {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        return match &self {
            Layers::Ethernet(layer) => layer.fmt(f),
            Layers::Arp(layer) => layer.fmt(f),
            Layers::Ipv4(layer) => layer.fmt(f),
            Layers::Tcp(layer) => layer.fmt(f),
            Layers::Udp(layer) => layer.fmt(f),
        };
    }
}

impl Layer for Layers {
    fn get_type(&self) -> LayerType {
        return match &self {
            Layers::Ethernet(layer) => layer.get_type(),
            Layers::Arp(layer) => layer.get_type(),
            Layers::Ipv4(layer) => layer.get_type(),
            Layers::Tcp(layer) => layer.get_type(),
            Layers::Udp(layer) => layer.get_type(),
        };
    }

    fn get_size(&self) -> usize {
        return match &self {
            Layers::Ethernet(layer) => layer.get_size(),
            Layers::Arp(layer) => layer.get_size(),
            Layers::Ipv4(layer) => layer.get_size(),
            Layers::Tcp(layer) => layer.get_size(),
            Layers::Udp(layer) => layer.get_size(),
        };
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<(), String> {
        return match &self {
            Layers::Ethernet(layer) => layer.serialize(buffer),
            Layers::Arp(layer) => layer.serialize(buffer),
            Layers::Ipv4(layer) => layer.serialize(buffer),
            Layers::Tcp(layer) => layer.serialize(buffer),
            Layers::Udp(layer) => layer.serialize(buffer),
        };
    }

    fn serialize_n(&self, n: usize, buffer: &mut [u8]) -> Result<usize, String> {
        return match &self {
            Layers::Ethernet(layer) => layer.serialize_n(n, buffer),
            Layers::Arp(layer) => layer.serialize_n(n, buffer),
            Layers::Ipv4(layer) => layer.serialize_n(n, buffer),
            Layers::Tcp(layer) => layer.serialize_n(n, buffer),
            Layers::Udp(layer) => layer.serialize_n(n, buffer),
        };
    }
}
