use ipnetwork::IpNetwork;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkReceiver, DataLinkSender, MacAddr};
use std::clone::Clone;
use std::cmp::{Eq, PartialEq};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::net::Ipv4Addr;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Interface {
    pub name: String,
    pub alias: Option<String>,
    pub hardware_addr: Option<MacAddr>,
    pub ip_addrs: Vec<Ipv4Addr>,
    pub loopback: bool,
}

impl Interface {
    pub fn new() -> Interface {
        Interface {
            name: String::new(),
            alias: None,
            hardware_addr: None,
            ip_addrs: vec![],
            loopback: false,
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

        let mut hardware_addr = String::new();
        if let Some(addr) = &self.hardware_addr {
            hardware_addr = format!(" [{}]", addr);
        }

        let ip_addrs = format!(
            "{}",
            self.ip_addrs
                .iter()
                .map(|ip_addr| { ip_addr.to_string() })
                .collect::<Vec<String>>()
                .join(", ")
        );

        let mut flags = String::new();
        if self.loopback {
            flags = String::from(" (Loopback)");
        }

        write!(f, "{}{}{}: {}", name, hardware_addr, flags, ip_addrs)
    }
}

pub fn interfaces() -> Vec<Interface> {
    let inters = datalink::interfaces();

    let ifs: Vec<Interface> = inters
        .iter()
        .map(|inter| {
            if inter.is_loopback() {
                return Err(());
            }
            /*if !inter.is_up() {
                return Err(());
            }*/

            let mut i = Interface::new();
            i.name = inter.name.clone();
            i.hardware_addr = inter.mac;
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
            i.loopback = inter.is_loopback();

            Ok(i)
        })
        .filter_map(Result::ok)
        .collect();

    ifs
}

pub fn open(
    interface: &Interface,
) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>), String> {
    let inters = datalink::interfaces();
    let inter = match inters
        .into_iter()
        .filter(|current_inter| current_inter.name == interface.name)
        .next()
    {
        Some(int) => int,
        _ => return Err(format!("unknown interface {}", interface.name)),
    };

    let (tx, rx) = match datalink::channel(&inter, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(format!("channel: {}", "unhandled link type")),
        Err(e) => return Err(format!("channel: {}", e)),
    };

    Ok((tx, rx))
}

mod ethernet;
