use ipnetwork::IpNetwork;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkReceiver, DataLinkSender, MacAddr};
use std::clone::Clone;
use std::cmp::{Eq, PartialEq};
use std::fmt::{self, Display, Formatter};
use std::hash::Hash;
use std::net::Ipv4Addr;

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
            Ok(Ethernet(tx, rx)) => (tx, rx),
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
