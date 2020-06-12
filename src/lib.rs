use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

pub mod args;
pub mod packet;
pub mod pcap;
pub mod socks;
use crate::socks::SocksDatagram;
use log::{debug, trace, warn, Level, LevelFilter};
use packet::layer::arp::Arp;
use packet::layer::ethernet::Ethernet;
use packet::layer::ipv4::Ipv4;
use packet::layer::tcp::Tcp;
use packet::layer::udp::Udp;
use packet::layer::{Layer, LayerType, LayerTypes, Layers};
use packet::Indicator;
use pcap::{HardwareAddr, Interface, Receiver, Sender};

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

/// Gets a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<Interface> {
    pcap::interfaces()
        .into_iter()
        .filter(|inter| !inter.is_loopback)
        .collect()
}

/// Gets an available network iterface match the name.
pub fn interface(name: Option<String>) -> Option<Interface> {
    let mut inters = interfaces();
    if inters.len() > 1 {
        if let None = name {
            return None;
        }
    }
    if let Some(inter_name) = name {
        inters.retain(|current_inter| current_inter.name == inter_name);
    }
    if inters.len() <= 0 {
        return None;
    }

    Some(inters[0].clone())
}

const INITIAL_PORT: u16 = 32768;
const PORT_COUNT: usize = 32;

/// Represents the channel downstream traffic to the source in pcap.
pub struct Downstreamer {
    tx: Sender,
    src_hardware_addr: HardwareAddr,
    local_hardware_addr: HardwareAddr,
    src_ip_addr: Ipv4Addr,
    local_ip_addr: Ipv4Addr,
    ipv4_identification_map: HashMap<Ipv4Addr, u16>,
    tcp_sequence_map: HashMap<SocketAddrV4, u32>,
    tcp_acknowledgement_map: HashMap<SocketAddrV4, u32>,
}

impl Downstreamer {
    /// Construct a new `Downstreamer`.
    pub fn new(
        tx: Sender,
        local_hardware_addr: HardwareAddr,
        src_ip_addr: Ipv4Addr,
        local_ip_addr: Ipv4Addr,
    ) -> Downstreamer {
        Downstreamer {
            tx,
            src_hardware_addr: pcap::HARDWARE_ADDR_UNSPECIFIED,
            local_hardware_addr,
            src_ip_addr,
            local_ip_addr,
            ipv4_identification_map: HashMap::new(),
            tcp_sequence_map: HashMap::new(),
            tcp_acknowledgement_map: HashMap::new(),
        }
    }

    /// Sets the source hardware address.
    pub fn set_src_hardware_addr(&mut self, hardware_addr: HardwareAddr) {
        trace!("set source hardware address to {}", hardware_addr);
        self.src_hardware_addr = hardware_addr;
    }

    /// Sets the local IP address.
    pub fn set_local_ip_addr(&mut self, ip_addr: Ipv4Addr) {
        trace!("set local IP address to {}", ip_addr);
        self.local_ip_addr = ip_addr;
    }

    /// Sends an ARP reply packet.
    pub fn send_arp_reply(&mut self) -> io::Result<()> {
        // ARP
        let arp = Arp::new_reply(
            self.local_hardware_addr,
            self.local_ip_addr,
            self.src_hardware_addr,
            self.src_ip_addr,
        );

        // Ethernet
        let ethernet = Ethernet::new(
            arp.get_type(),
            arp.get_src_hardware_addr(),
            arp.get_dst_hardware_addr(),
        )
        .unwrap();

        // Indicator
        let indicator = Indicator::new(Layers::Ethernet(ethernet), Some(Layers::Arp(arp)), None);
        trace!("send to pcap {}", indicator);

        // Send
        self.send(&indicator)
    }

    /// Sends an UDP packet.
    pub fn send_udp(&mut self, dst: SocketAddrV4, src_port: u16, payload: &[u8]) -> io::Result<()> {
        // UDP
        let udp = Udp::new(dst.ip().clone(), self.src_ip_addr, dst.port(), src_port);

        // IPv4 identification
        if !self.ipv4_identification_map.contains_key(dst.ip()) {
            self.ipv4_identification_map.insert(dst.ip().clone(), 0);
        }

        // IPv4
        let ipv4 = Ipv4::new(0, udp.get_type(), dst.ip().clone(), self.src_ip_addr).unwrap();

        // Ethernet
        let ethernet = Ethernet::new(
            ipv4.get_type(),
            self.local_hardware_addr,
            self.src_hardware_addr,
        )
        .unwrap();

        // Indicator
        let indicator = Indicator::new(
            Layers::Ethernet(ethernet),
            Some(Layers::Ipv4(ipv4)),
            Some(Layers::Udp(udp)),
        );

        // Send
        match self.send_with_payload(&indicator, payload) {
            Ok(()) => {
                // Update IPv4 identification
                let ipv4_identification_entry = self
                    .ipv4_identification_map
                    .entry(dst.ip().clone())
                    .or_insert(0);
                *ipv4_identification_entry += 1;

                return Ok(());
            }
            Err(e) => Err(e),
        }
    }

    fn send(&mut self, indicator: &Indicator) -> io::Result<()> {
        // Serialize
        let size = indicator.get_size();
        let mut buffer = vec![0u8; size];
        indicator.serialize(&mut buffer)?;

        // Send
        self.tx.send_to(&buffer, None).unwrap_or(Ok(()))?;
        debug!("send to pcap: {} ({} Bytes)", indicator.brief(), size);

        Ok(())
    }

    fn send_with_payload(&mut self, indicator: &Indicator, payload: &[u8]) -> io::Result<()> {
        // Serialize
        let size = indicator.get_size();
        let mut buffer = vec![0u8; size + payload.len()];
        indicator.serialize_with_payload(&mut buffer, payload)?;

        // Send
        self.tx.send_to(&buffer, None).unwrap_or(Ok(()))?;
        debug!("send to pcap: {} ({} Bytes)", indicator.brief(), size);

        Ok(())
    }
}

/// Represents the channel upstream traffic to the proxy of SOCKS or loopback to the source in pcap.
pub struct Upstreamer {
    tx: Arc<Mutex<Downstreamer>>,
    is_tx_src_hardware_addr_set: bool,
    src_ip_addr: Ipv4Addr,
    local_ip_addr: Option<Ipv4Addr>,
    remote: SocketAddrV4,
    next_udp_port: u16,
    datagrams: Vec<Option<DatagramWorker>>,
    datagram_map: Vec<u16>,
    datagram_reverse_map: Vec<u16>,
}

impl Upstreamer {
    /// Construct a new `Upstreamer`.
    pub fn new(
        tx: Arc<Mutex<Downstreamer>>,
        src_ip_addr: Ipv4Addr,
        local_ip_addr: Option<Ipv4Addr>,
        remote: SocketAddrV4,
    ) -> Upstreamer {
        let upstreamer = Upstreamer {
            tx,
            is_tx_src_hardware_addr_set: false,
            src_ip_addr,
            local_ip_addr,
            remote,
            next_udp_port: INITIAL_PORT,
            datagrams: (0..PORT_COUNT).map(|_| None).collect(),
            datagram_map: vec![0u16; u16::MAX as usize],
            datagram_reverse_map: vec![0u16; PORT_COUNT],
        };
        if let Some(local_ip_addr) = local_ip_addr {
            upstreamer
                .tx
                .lock()
                .unwrap()
                .set_local_ip_addr(local_ip_addr);
        }

        upstreamer
    }

    /// Opens an `Interface` for upstream.
    pub fn open(&mut self, rx: &mut Receiver) -> io::Result<()> {
        loop {
            match rx.next() {
                Ok(frame) => {
                    if let Some(ref indicator) = Indicator::from(frame) {
                        trace!("receive from pcap: {}", indicator);

                        if let Some(t) = indicator.get_network_type() {
                            match t {
                                LayerTypes::Arp => {
                                    if let Err(ref e) = self.handle_arp(indicator) {
                                        warn!("handle {}: {}", t, e);
                                    }
                                }
                                LayerTypes::Ipv4 => {
                                    if let Err(ref e) = self.handle_ipv4(indicator, frame) {
                                        warn!("handle {}: {}", t, e);
                                    }
                                }
                                _ => unreachable!(),
                            }
                        }
                    };
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::TimedOut {
                        continue;
                    }
                    return Err(e);
                }
            };
        }
    }

    fn handle_arp(&self, indicator: &Indicator) -> io::Result<()> {
        if let Some(local_ip_addr) = self.local_ip_addr {
            if let Some(arp) = indicator.get_arp() {
                if arp.is_request_of(self.src_ip_addr, local_ip_addr) {
                    debug!(
                        "receive from pcap: {} ({} Bytes)",
                        indicator.brief(),
                        indicator.get_size()
                    );

                    // Set downstreamer's hardware address
                    if !self.is_tx_src_hardware_addr_set {
                        self.tx
                            .lock()
                            .unwrap()
                            .set_src_hardware_addr(arp.get_src_hardware_addr());
                    }

                    // Send
                    self.tx.lock().unwrap().send_arp_reply()?
                }
            }
        }

        Ok(())
    }

    fn handle_ipv4(&mut self, indicator: &Indicator, buffer: &[u8]) -> io::Result<()> {
        if let Some(ref ipv4) = indicator.get_ipv4() {
            if ipv4.get_src() == self.src_ip_addr {
                debug!(
                    "receive from pcap: {} ({} Bytes)",
                    indicator.brief(),
                    indicator.get_size()
                );
                // Set downstreamer's hardware address
                if !self.is_tx_src_hardware_addr_set {
                    self.tx
                        .lock()
                        .unwrap()
                        .set_src_hardware_addr(indicator.get_ethernet().unwrap().get_src());
                }

                if ipv4.is_fragment() {
                    // Fragment
                } else {
                    if let Some(t) = indicator.get_transport_type() {
                        match t {
                            LayerTypes::Tcp => {}
                            LayerTypes::Udp => self.handle_udp(indicator, buffer)?,
                            _ => unreachable!(),
                        };
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_udp(&mut self, indicator: &Indicator, buffer: &[u8]) -> io::Result<()> {
        if let Some(ref udp) = indicator.get_udp() {
            let port = self.get_local_udp_port(udp.get_src());
            let index = (port - INITIAL_PORT) as usize;

            // Bind
            let create_new = match self.datagrams[index] {
                Some(ref worker) => worker.get_src_port() != udp.get_src(),
                None => true,
            };
            if create_new {
                self.datagrams[index] = Some(DatagramWorker::new_and_open(
                    self.get_tx(),
                    udp.get_src(),
                    port,
                    self.remote,
                )?);
            }

            // Send
            self.datagrams[index].as_mut().unwrap().send_to(
                &buffer[indicator.get_size()..],
                SocketAddrV4::new(udp.get_dst_ip_addr(), udp.get_dst()),
            )?;
        }

        Ok(())
    }

    fn get_tx(&self) -> Arc<Mutex<Downstreamer>> {
        Arc::clone(&self.tx)
    }

    fn get_local_udp_port(&mut self, src_port: u16) -> u16 {
        if self.datagram_map[src_port as usize] == 0 {
            if self.datagram_reverse_map[(self.next_udp_port - INITIAL_PORT) as usize] != 0 {
                self.datagram_map[self.datagram_reverse_map
                    [(self.next_udp_port - INITIAL_PORT) as usize]
                    as usize] = 0;
            }
            self.datagram_map[src_port as usize] = self.next_udp_port;
            self.datagram_reverse_map[(self.next_udp_port - INITIAL_PORT) as usize] = src_port;

            // To next port
            self.next_udp_port = self.next_udp_port + 1;
            if self.next_udp_port >= INITIAL_PORT + PORT_COUNT as u16 {
                self.next_udp_port = INITIAL_PORT;
            }
        }

        self.datagram_map[src_port as usize]
    }
}

pub struct DatagramWorker {
    tx: Arc<Mutex<Downstreamer>>,
    src_port: u16,
    local_port: u16,
    datagram: Arc<SocksDatagram>,
    thread: JoinHandle<()>,
}

impl DatagramWorker {
    /// Construct a new `DatagramWorker` and open it.
    pub fn new_and_open(
        tx: Arc<Mutex<Downstreamer>>,
        src_port: u16,
        local_port: u16,
        remote: SocketAddrV4,
    ) -> io::Result<DatagramWorker> {
        let datagram =
            SocksDatagram::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local_port), remote)?;

        let a_datagram = Arc::new(datagram);
        let a_datagram_cloned = Arc::clone(&a_datagram);
        let tx_cloned = Arc::clone(&tx);
        let thread = thread::spawn(move || {
            let mut buffer = [0u8; u16::MAX as usize];
            loop {
                match a_datagram_cloned.recv_from(&mut buffer) {
                    Ok((size, addr)) => {
                        debug!(
                            "receive from socks: {}: {} -> {} ({} Bytes)",
                            "UDP", addr, local_port, size
                        );
                        if let Err(ref e) =
                            tx_cloned
                                .lock()
                                .unwrap()
                                .send_udp(addr, src_port, &buffer[..size])
                        {
                            warn!("handle {}: {}", "UDP", e);
                        }
                    }
                    Err(ref e) => {
                        if e.kind() == io::ErrorKind::TimedOut {
                            continue;
                        }
                        warn!("socks: {}", e);
                        return;
                    }
                }
            }
        });

        Ok(DatagramWorker {
            tx,
            src_port,
            local_port,
            datagram: a_datagram,
            thread: thread,
        })
    }

    /// Sends data on the SOCKS to the destination.
    pub fn send_to(&mut self, buffer: &[u8], dst: SocketAddrV4) -> io::Result<usize> {
        debug!(
            "send to socks {}: {} -> {} ({} Bytes)",
            "UDP",
            self.local_port,
            dst,
            buffer.len()
        );

        // Send
        self.datagram.send_to(buffer, dst)
    }

    /// Get the source port of the SOCKS.
    pub fn get_src_port(&self) -> u16 {
        self.src_port
    }
}

/// Represents the proxy redirects pcap traffic to SOCKS.
pub struct Proxy {
    hardware_addr: HardwareAddr,
    publish: Option<Ipv4Addr>,
    src: Ipv4Addr,
    dst: SocketAddrV4,
    tx: Arc<Mutex<Sender>>,
    ipv4_identification: u16,
    tcp_sequence: u32,
    tcp_acknowledgement: u32,
    next_udp_port: u16,
    datagrams: Vec<Option<SocksDatagram>>,
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
    ) -> io::Result<(Proxy, Receiver)> {
        let (tx, rx) = inter.open()?;

        Ok((
            Proxy {
                hardware_addr: inter.hardware_addr,
                publish,
                src,
                dst,
                tx: Arc::new(Mutex::new(tx)),
                ipv4_identification: 0,
                tcp_sequence: 0,
                tcp_acknowledgement: 0,
                next_udp_port: INITIAL_PORT,
                datagrams: (0..u16::MAX).map(|_| None).collect(),
                datagram_local_to_remote_map: vec![0; u16::MAX as usize],
                datagram_remote_to_local_map: vec![0; u16::MAX as usize],
            },
            rx,
        ))
    }

    /// Get the sender of the `Proxy`.
    fn get_tx(&self) -> Arc<Mutex<Sender>> {
        self.tx.clone()
    }

    // Handles the proxy.
    pub fn handle(&mut self, rx: &mut Receiver) -> io::Result<()> {
        loop {
            let frame = match rx.next() {
                Ok(frame) => frame,
                Err(e) => {
                    if e.kind() == io::ErrorKind::TimedOut {
                        continue;
                    }
                    return Err(e);
                }
            };

            if let Some(ref indicator) = Indicator::from(frame) {
                trace!("receive from pcap: {}", indicator);

                if let Some(t) = indicator.get_network_type() {
                    match t {
                        LayerTypes::Arp => {
                            if let Err(ref e) = self.handle_arp(indicator) {
                                warn!("handle {}: {}", t, e);
                            };
                        }
                        LayerTypes::Ipv4 => {
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

    fn handle_arp(&self, indicator: &Indicator) -> io::Result<()> {
        if let Some(publish) = self.publish {
            if let Some(arp) = indicator.get_arp() {
                if arp.is_request_of(self.src, publish) {
                    debug!(
                        "receive from pcap: {} ({} Bytes)",
                        indicator.brief(),
                        indicator.get_size()
                    );

                    // Reply
                    let new_arp = Arp::reply(&arp, self.hardware_addr);
                    let new_ethernet = Ethernet::new(
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
                    new_indicator.serialize(&mut buffer)?;

                    // Send
                    self.get_tx()
                        .lock()
                        .unwrap()
                        .send_to(&buffer, None)
                        .unwrap_or(Ok(()))?;
                    debug!("send to pcap: {} ({} Bytes)", new_indicator.brief(), size);
                }
            };
        };

        Ok(())
    }

    fn handle_ipv4(&mut self, indicator: &Indicator, buffer: &[u8]) -> io::Result<()> {
        if let Some(ref ipv4) = indicator.get_ipv4() {
            if ipv4.get_src() == self.src {
                debug!(
                    "receive from pcap: {} ({} Bytes)",
                    indicator.brief(),
                    buffer.len()
                );

                if ipv4.is_fragment() {
                    // Fragment
                } else {
                    if let Some(t) = indicator.get_transport_type() {
                        match t {
                            LayerTypes::Tcp => {}
                            LayerTypes::Udp => self.handle_udp(indicator, buffer)?,
                            _ => {}
                        };
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_udp(&mut self, indicator: &Indicator, buffer: &[u8]) -> io::Result<()> {
        if let Some(ref udp) = indicator.get_udp() {
            let port = self.get_local_udp_port(udp.get_src());

            // Bind
            if let None = self.datagrams[port as usize] {
                self.datagrams[port as usize] = match SocksDatagram::bind(
                    SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
                    self.dst,
                ) {
                    Ok(datagram) => Some(datagram),
                    Err(e) => return Err(e),
                };
            };

            // Send
            self.datagrams[port as usize].as_ref().unwrap().send_to(
                &buffer[indicator.get_size()..],
                SocketAddrV4::new(udp.get_dst_ip_addr(), udp.get_dst()),
            )?;
            debug!(
                "send to SOCKS: {}: {} -> {} ({} Bytes)",
                udp.get_type(),
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
                self.dst,
                buffer.len() - indicator.get_size()
            );
        }

        Ok(())
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

            // To next port
            self.next_udp_port = self.next_udp_port + 1;
            if self.next_udp_port > u16::MAX {
                self.next_udp_port = INITIAL_PORT;
            }
        }

        self.datagram_remote_to_local_map[remote_port as usize]
    }
}
