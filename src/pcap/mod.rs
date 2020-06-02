use ipnetwork;
use pnet::datalink;
use std::fmt;
use std::net;

pub struct MacAddr(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddr {
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddr {
        return MacAddr(a, b, c, d, e, f);
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0, self.1, self.2, self.3, self.4, self.5
        );
    }
}

pub struct Interface {
    pub name: String,
    pub alias: Option<String>,
    pub hardware_addr: Option<MacAddr>,
    pub ip_addrs: Vec<net::Ipv4Addr>,
    pub loopback: bool,
}

impl Interface {
    pub fn new() -> Interface {
        return Interface {
            name: String::new(),
            alias: None,
            hardware_addr: None,
            ip_addrs: vec![],
            loopback: false,
        };
    }
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

        return write!(f, "{}{}{}: {}", name, hardware_addr, flags, ip_addrs);
    }
}

pub fn interfaces() -> Vec<Interface> {
    let inters = datalink::interfaces();

    let ifs: Vec<Interface> = inters
        .iter()
        .map(|inter| {
            // if !inter.is_up() {
            //     return Err(());
            // }

            let mut i = Interface::new();
            i.name = inter.name.clone();
            if let Some(addr) = inter.mac {
                i.hardware_addr = Some(MacAddr::new(addr.0, addr.1, addr.2, addr.3, addr.4, addr.5))
            }
            i.ip_addrs = inter
                .ips
                .iter()
                .map(|ip| match ip {
                    ipnetwork::IpNetwork::V4(ipv4) => {
                        let ip = ipv4.network();
                        if ip.is_unspecified() {
                            return Err(());
                        }
                        return Ok(ip);
                    }
                    _ => return Err(()),
                })
                .filter_map(Result::ok)
                .collect();
            if i.ip_addrs.len() <= 0 {
                return Err(());
            }
            i.loopback = inter.is_loopback();

            return Ok(i);
        })
        .filter_map(Result::ok)
        .collect();

    return ifs;
}
