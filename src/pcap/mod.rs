//! Support for handling pcap interfaces.

use pnet::datalink::{self, Channel, Config, DataLinkReceiver, DataLinkSender, MacAddr};
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::Ipv4Addr;

/// Represents the hardware address MAC in an Ethernet network.
pub type HardwareAddr = pnet::datalink::MacAddr;

/// Represents an unspecified hardware address `00:00:00:00:00:00` in an Ethernet network.
pub const HARDWARE_ADDR_UNSPECIFIED: HardwareAddr = pnet::datalink::MacAddr(0, 0, 0, 0, 0, 0);

/// Represents the send half of a pcap device.
pub type Sender = Box<dyn DataLinkSender>;
/// Represents the receive half of a pcap device.
pub type Receiver = Box<dyn DataLinkReceiver>;

/// Represents the buffer size of pcap channels.
const BUFFER_SIZE: usize = 256 * 1024;

/// Represents a network interface and its associated addresses.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Interface {
    pub name: String,
    pub alias: Option<String>,
    pub hardware_addr: MacAddr,
    pub ip_addrs: Vec<Ipv4Addr>,
    pub is_up: bool,
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
            is_up: false,
            is_loopback: false,
        }
    }

    // Opens the network interface for sending and receiving data.
    pub fn open(&self) -> io::Result<(Sender, Receiver)> {
        let inters = datalink::interfaces();
        let inter = inters
            .into_iter()
            .filter(|current_inter| current_inter.name == self.name)
            .next()
            .ok_or(io::Error::new(
                io::ErrorKind::NotFound,
                "interface not found",
            ))?;

        let mut config = Config::default();
        config.write_buffer_size = BUFFER_SIZE;
        config.read_buffer_size = BUFFER_SIZE;
        let channel = datalink::channel(&inter, config)?;
        let channel = match channel {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => return Err(io::Error::new(io::ErrorKind::Other, "unknown link type")),
        };

        Ok(channel)
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
            /* Cannot get flags using WinPcap in Windows
            if !inter.is_up() {
                return Err(());
            }
            */

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
                .filter_map(Result::ok)
                .collect();

            // Exclude interface without any IPv4 address
            if i.ip_addrs.len() <= 0 {
                return Err(());
            }

            i.is_up = inter.is_up();
            i.is_loopback = inter.is_loopback();

            Ok(i)
        })
        .filter_map(Result::ok)
        .collect();

    ifs
}
