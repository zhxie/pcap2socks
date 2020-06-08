use std::cell::RefCell;
use std::io::{ErrorKind, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

pub mod args;
use log::{debug, trace, warn, Level, LevelFilter};

/// Parses arguments and returns a `Flags`.
pub fn parse() -> args::Flags {
    args::parse()
}

/// Sets the logger.
pub fn set_logger(flags: &args::Flags) {
    use env_logger::fmt::Color;

    let level = match &flags.vverbose {
        true => LevelFilter::Trace,
        false => match flags.verbose {
            true => LevelFilter::Debug,
            false => LevelFilter::Info,
        },
    };
    env_logger::builder()
        .filter_level(level)
        .format(|buf, record| {
            let mut style = buf.style();

            let level = match &record.level() {
                Level::Error => style.set_bold(true).set_color(Color::Red).value("error: "),
                Level::Warn => style
                    .set_bold(true)
                    .set_color(Color::Yellow)
                    .value("warning: "),
                Level::Info => style.set_bold(true).set_color(Color::Green).value(""),
                _ => style.set_color(Color::Rgb(165, 165, 165)).value(""),
            };
            writeln!(buf, "{}{}", level, record.args())
        })
        .init();
}

/// Validate arguments and returns an `Opts`.
pub fn validate(flags: &args::Flags) -> Result<args::Opts, String> {
    args::Opts::validate(flags)
}

pub mod pcap;
pub mod socks;
use crate::socks::Socks5Datagram;
use pcap::layer::{self, Layer, Layers};
use pcap::{arp, ethernet, Indicator, Interface, Receiver, Sender};

/// Gets a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<Interface> {
    pcap::interfaces()
        .into_iter()
        .filter(|inter| !inter.is_loopback)
        .collect()
}

/// Gets an available network iterface match the name.
pub fn interface(name: Option<String>) -> Result<Interface, String> {
    let mut inters = interfaces();
    if inters.len() <= 0 {
        return Err(String::from("no available interface"));
    }
    if inters.len() > 1 {
        if let None = name {
            return Err(String::from("multiple available interfaces"));
        }
    }
    if let Some(inter_name) = name {
        inters.retain(|current_inter| current_inter.name == inter_name);
        if inters.len() <= 0 {
            return Err(format!("unknown interface {}", inter_name));
        }
    }
    Ok(inters[0].clone())
}

const INITIAL_PORT: u16 = 32768;

/// Represents the proxy redirects pcap traffic to SOCKS.
pub struct Proxy {
    hardware_addr: pnet::datalink::MacAddr,
    publish: Option<Ipv4Addr>,
    src: Ipv4Addr,
    dst: SocketAddrV4,
    tx: Arc<Mutex<Sender>>,
    rx: Receiver,
    ipv4_identification: u16,
    tcp_sequence: u32,
    tcp_acknowledgement: u32,
    next_udp_port: u16,
    datagrams: Vec<Option<Socks5Datagram>>,
    datagram_remote_to_local_map: Vec<u16>,
    datagram_local_to_remote_map: Vec<u16>,
}

impl Proxy {
    /// Opens an `Interface` for proxy.
    pub fn open(
        inter: &Interface,
        publish: Option<Ipv4Addr>,
        src: Ipv4Addr,
        dst: SocketAddrV4,
    ) -> Result<Proxy, String> {
        let (tx, rx) = match inter.open() {
            Ok((tx, rx)) => (tx, rx),
            Err(ref e) => return Err(format!("open pcap: {}", e)),
        };

        Ok(Proxy {
            hardware_addr: inter.hardware_addr,
            publish,
            src,
            dst,
            tx: Arc::new(Mutex::new(tx)),
            rx,
            ipv4_identification: 0,
            tcp_sequence: 0,
            tcp_acknowledgement: 0,
            next_udp_port: INITIAL_PORT,
            datagrams: (0..u16::MAX).map(|_| None).collect(),
            datagram_local_to_remote_map: vec![u16::MAX; 0],
            datagram_remote_to_local_map: vec![u16::MAX; 0],
        })
    }

    /// Get the sender of the `Proxy`.
    fn get_tx(&self) -> Arc<Mutex<Sender>> {
        self.tx.clone()
    }

    // Handles the proxy.
    pub fn handle(&mut self) -> Result<(), String> {
        loop {
            let frame = match self.rx.next() {
                Ok(frame) => frame,
                Err(ref e) => {
                    if e.kind() != ErrorKind::TimedOut {
                        return Err(format!("handle pcap: {}", e));
                    }
                    continue;
                }
            };

            if let Some(ref indicator) = Indicator::from(frame) {
                trace!("receive from pcap: {}", indicator);

                if let Some(t) = indicator.get_network_type() {
                    match t {
                        layer::LayerTypes::Arp => {
                            if let Err(ref e) = self.handle_arp(indicator) {
                                warn!("handle {}: {}", t, e);
                            };
                        }
                        layer::LayerTypes::Ipv4 => {
                            if let Err(ref e) = self.handle_ipv4(indicator, frame) {
                                warn!("handle {}: {}", t, e);
                            };
                        }
                        _ => {}
                    };
                };
            };
        }
    }

    fn handle_arp(&self, indicator: &Indicator) -> Result<(), String> {
        if let Some(publish) = self.publish {
            if let Some(arp) = indicator.get_arp() {
                if arp.is_request_of(self.src, publish) {
                    let new_arp = arp::Arp::reply(&arp, self.hardware_addr);
                    let new_ethernet = ethernet::Ethernet::new(
                        new_arp.get_type(),
                        new_arp.get_src_hardware_addr(),
                        new_arp.get_dst_hardware_addr(),
                    )
                    .unwrap();
                    let new_indicator = Indicator::new(
                        Layers::Ethernet(new_ethernet),
                        Some(Layers::Arp(new_arp)),
                        None,
                    );
                    trace!("send to pcap {}", new_indicator);
                    // Serialize
                    let size = new_indicator.get_size();
                    let mut buffer = vec![0u8; size];
                    if let Err(e) = new_indicator.serialize(&mut buffer) {
                        return Err(format!("serialize: {}", e));
                    };
                    // Send
                    if let Some(result) = self.get_tx().lock().unwrap().send_to(&buffer, None) {
                        match result {
                            Ok(_) => {
                                debug!("send to pcap: {} ({} Bytes)", new_indicator.brief(), size);
                                return Ok(());
                            }
                            Err(ref e) => return Err(format!("send to pcap: {}", e)),
                        };
                    };
                }
            };
        };

        Ok(())
    }

    fn handle_ipv4(&mut self, indicator: &Indicator, buffer: &[u8]) -> Result<(), String> {
        if let Some(ref ipv4) = indicator.get_ipv4() {
            if ipv4.get_src() == self.src {
                if ipv4.is_fragment() {
                    // Fragment
                } else {
                    if let Some(t) = indicator.get_transport_type() {
                        match t {
                            layer::LayerTypes::Tcp => {}
                            layer::LayerTypes::Udp => {
                                if let Some(r) = self.handle_udp(indicator, ipv4.get_src()) {
                                    match r {
                                        Ok((local_port, dst_port)) => {
                                            if let Some(datagram) = &self.datagrams
                                                [(local_port - INITIAL_PORT) as usize]
                                            {
                                                if let Err(ref e) = datagram.send_to(
                                                    &buffer[indicator.get_size()..],
                                                    SocketAddrV4::new(ipv4.get_dst(), dst_port),
                                                ) {
                                                    return Err(format!("handle {}: {}", t, e));
                                                }
                                            }
                                        }
                                        Err(e) => return Err(format!("handle {}: {}", t, e)),
                                    };
                                }
                            }
                            _ => return Err(format!("unhandled transport layer type")),
                        };
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_udp(
        &mut self,
        indicator: &Indicator,
        src: Ipv4Addr,
    ) -> Option<Result<(u16, u16), String>> {
        if let Some(ref udp) = indicator.get_udp() {
            let port = self.get_local_udp_port(udp.get_src());

            self.datagrams[port as usize] = match socks::Socks5Datagram::bind(
                SocketAddrV4::new(self.src, udp.get_src()),
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
                self.dst,
            ) {
                Ok(datagram) => Some(datagram),
                Err(ref e) => {
                    return Some(Err(format!("bind datagram: {}", e)));
                }
            };

            return Some(Ok((port, udp.get_dst())));
        }

        None
    }

    /// Get the remote UDP port according to the given local UDP port.
    fn get_remote_udp_port(&self, local_port: u16) -> Option<u16> {
        let port = self.datagram_local_to_remote_map[local_port as usize];
        if port == 0 {
            return None;
        }

        Some(port)
    }

    /// Get the local UDP port distributed according to the given remove UDP port or distribute a new one.
    fn get_local_udp_port(&mut self, remote_port: u16) -> u16 {
        if self.datagram_remote_to_local_map[remote_port as usize] == 0 {
            self.datagram_local_to_remote_map[self.next_udp_port as usize] = remote_port;
            self.datagram_remote_to_local_map[remote_port as usize] = self.next_udp_port;

            self.next_udp_port = self.next_udp_port + 1;
            if self.next_udp_port > u16::MAX {
                self.next_udp_port = INITIAL_PORT;
            }
        }

        self.datagram_remote_to_local_map[remote_port as usize]
    }
}
