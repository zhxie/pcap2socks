use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
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
const PORT_COUNT: usize = 64;

/// Represents the channel downstream traffic to the source in pcap.
pub struct Downstreamer {
    tx: Sender,
    src_hardware_addr: HardwareAddr,
    local_hardware_addr: HardwareAddr,
    src_ip_addr: Ipv4Addr,
    local_ip_addr: Ipv4Addr,
    ipv4_identification_map: HashMap<Ipv4Addr, u16>,
    tcp_sequence_map: HashMap<(u16, SocketAddrV4), u32>,
    tcp_acknowledgement_map: HashMap<(u16, SocketAddrV4), u32>,
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

    /// Adds TCP acknowledgement to an TCP connection.
    pub fn add_tcp_acknowledgement(&mut self, dst: SocketAddrV4, src_port: u16, n: u32) {
        let entry = self
            .tcp_acknowledgement_map
            .entry((src_port, dst))
            .or_insert(0);
        *entry += n;
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
        let ipv4_identification = self.ipv4_identification_map.get(dst.ip()).unwrap();

        // IPv4
        let ipv4 = Ipv4::new(
            *ipv4_identification,
            udp.get_type(),
            dst.ip().clone(),
            self.src_ip_addr,
        )
        .unwrap();

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

    /// Sends an TCP ACK packet.
    pub fn send_tcp_ack(
        &mut self,
        dst: SocketAddrV4,
        src_port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        let key = (src_port, dst);

        // TCP
        let tcp = Tcp::new_ack(
            dst.ip().clone(),
            self.src_ip_addr,
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).or(Some(&0)).unwrap(),
            *self.tcp_acknowledgement_map.get(&key).unwrap(),
        );

        // IPv4 identification
        if !self.ipv4_identification_map.contains_key(dst.ip()) {
            self.ipv4_identification_map.insert(dst.ip().clone(), 0);
        }
        let ipv4_identification = self.ipv4_identification_map.get(dst.ip()).unwrap();

        // IPv4
        let ipv4 = Ipv4::new(
            *ipv4_identification,
            tcp.get_type(),
            dst.ip().clone(),
            self.src_ip_addr,
        )
        .unwrap();

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
            Some(Layers::Tcp(tcp)),
        );

        // Send
        match self.send_with_payload(&indicator, payload) {
            Ok(()) => {
                // Update TCP sequence
                let tcp_sequence_entry = self.tcp_sequence_map.entry(key).or_insert(0);
                *tcp_sequence_entry += payload.len() as u32;

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

    /// Sends an TCP ACK packet without payload.
    pub fn send_tcp_ack_0(&mut self, dst: SocketAddrV4, src_port: u16) -> io::Result<()> {
        let key = (src_port, dst);

        // TCP
        let tcp = Tcp::new_ack(
            dst.ip().clone(),
            self.src_ip_addr,
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).or(Some(&0)).unwrap(),
            *self.tcp_acknowledgement_map.get(&key).unwrap(),
        );

        // IPv4 identification
        if !self.ipv4_identification_map.contains_key(dst.ip()) {
            self.ipv4_identification_map.insert(dst.ip().clone(), 0);
        }
        let ipv4_identification = self.ipv4_identification_map.get(dst.ip()).unwrap();

        // IPv4
        let ipv4 = Ipv4::new(
            *ipv4_identification,
            tcp.get_type(),
            dst.ip().clone(),
            self.src_ip_addr,
        )
        .unwrap();

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
            Some(Layers::Tcp(tcp)),
        );

        // Send
        match self.send(&indicator) {
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

    /// Sends an TCP ACK/SYN packet.
    pub fn send_tcp_ack_syn(
        &mut self,
        dst: SocketAddrV4,
        src_port: u16,
        sequence: u32,
    ) -> io::Result<()> {
        // TCP sequence & acknowledgement
        let key = (src_port, dst);
        self.tcp_acknowledgement_map.insert(key, sequence);

        // TCP
        let tcp = Tcp::new_ack_syn(
            dst.ip().clone(),
            self.src_ip_addr,
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).or(Some(&0)).unwrap(),
            *self.tcp_acknowledgement_map.get(&key).unwrap(),
        );

        // IPv4 identification
        if !self.ipv4_identification_map.contains_key(dst.ip()) {
            self.ipv4_identification_map.insert(dst.ip().clone(), 0);
        }
        let ipv4_identification = self.ipv4_identification_map.get(dst.ip()).unwrap();

        // IPv4
        let ipv4 = Ipv4::new(
            *ipv4_identification,
            tcp.get_type(),
            dst.ip().clone(),
            self.src_ip_addr,
        )
        .unwrap();

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
            Some(Layers::Tcp(tcp)),
        );

        // Send
        match self.send(&indicator) {
            Ok(()) => {
                // Update TCP sequence
                let tcp_sequence_entry = self.tcp_sequence_map.entry(key).or_insert(0);
                *tcp_sequence_entry += 1;

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

    /// Sends an TCP RST packet.
    pub fn send_tcp_rst(
        &mut self,
        dst: SocketAddrV4,
        src_port: u16,
        sequence: u32,
    ) -> io::Result<()> {
        // TCP sequence & acknowledgement
        let key = (src_port, dst);
        self.tcp_acknowledgement_map.insert(key, sequence);

        // TCP
        let tcp = Tcp::new_rst(
            dst.ip().clone(),
            self.src_ip_addr,
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).or(Some(&0)).unwrap(),
            *self.tcp_acknowledgement_map.get(&key).unwrap(),
        );

        // IPv4 identification
        if !self.ipv4_identification_map.contains_key(dst.ip()) {
            self.ipv4_identification_map.insert(dst.ip().clone(), 0);
        }
        let ipv4_identification = self.ipv4_identification_map.get(dst.ip()).unwrap();

        // IPv4
        let ipv4 = Ipv4::new(
            *ipv4_identification,
            tcp.get_type(),
            dst.ip().clone(),
            self.src_ip_addr,
        )
        .unwrap();

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
            Some(Layers::Tcp(tcp)),
        );

        // Send
        match self.send(&indicator) {
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
        debug!(
            "send to pcap: {} ({} Bytes)",
            indicator.brief(),
            size + payload.len()
        );

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
    next_tcp_port: u16,
    streams: Vec<Option<StreamWorker>>,
    stream_map: HashMap<(u16, SocketAddrV4), u16>,
    stream_reverse_map: Vec<Option<(u16, SocketAddrV4)>>,
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
            next_tcp_port: INITIAL_PORT,
            streams: (0..PORT_COUNT).map(|_| None).collect(),
            stream_map: HashMap::new(),
            stream_reverse_map: (0..PORT_COUNT).map(|_| None).collect(),
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
                    indicator.get_size() + buffer.len()
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
                            LayerTypes::Tcp => self.handle_tcp(indicator, buffer)?,
                            LayerTypes::Udp => self.handle_udp(indicator, buffer)?,
                            _ => unreachable!(),
                        };
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_tcp(&mut self, indicator: &Indicator, buffer: &[u8]) -> io::Result<()> {
        if let Some(ref tcp) = indicator.get_tcp() {
            let dst = SocketAddrV4::new(tcp.get_dst_ip_addr(), tcp.get_dst());
            let port = self.get_local_tcp_port(tcp.get_src(), dst);
            let index = (port - INITIAL_PORT) as usize;

            if tcp.is_ack() {
                let is_ok = match self.streams[index] {
                    Some(ref stream) => {
                        stream.get_src_port_and_dst() == (tcp.get_src(), dst) && !stream.is_closed()
                    }
                    None => false,
                };

                if is_ok {
                    if buffer.len() > indicator.get_size() {
                        // Send
                        match self.streams[index]
                            .as_mut()
                            .unwrap()
                            .send(&buffer[indicator.get_size()..])
                        {
                            Ok(_) => {
                                // Update TCP acknowledgement
                                self.tx.lock().unwrap().add_tcp_acknowledgement(
                                    dst,
                                    tcp.get_src(),
                                    (buffer.len() - indicator.get_size()) as u32,
                                );

                                // Send ACK0
                                self.tx.lock().unwrap().send_tcp_ack_0(dst, tcp.get_src())?;
                            }
                            Err(e) => {
                                // Send RST
                                self.tx.lock().unwrap().send_tcp_rst(
                                    dst,
                                    tcp.get_src(),
                                    tcp.get_sequence(),
                                )?;

                                return Err(e);
                            }
                        }
                    }
                } else {
                    // Send RST
                    self.tx
                        .lock()
                        .unwrap()
                        .send_tcp_rst(dst, tcp.get_src(), tcp.get_sequence())?;
                }
            } else if tcp.is_syn() {
                // Connect
                if let Some(ref mut stream) = self.streams[index] {
                    stream.close()
                }
                self.streams[index] = match StreamWorker::new_and_open(
                    self.get_tx(),
                    tcp.get_src(),
                    port,
                    dst,
                    self.remote,
                ) {
                    Ok(stream) => {
                        // Send ACK/SYN
                        self.tx.lock().unwrap().send_tcp_ack_syn(
                            dst,
                            tcp.get_src(),
                            tcp.get_sequence() + 1,
                        )?;

                        Some(stream)
                    }
                    Err(e) => {
                        // Send RST
                        self.tx.lock().unwrap().send_tcp_rst(
                            dst,
                            tcp.get_src(),
                            tcp.get_sequence() + 1,
                        )?;

                        return Err(e);
                    }
                }
            } else if tcp.is_rst_or_fin() {
                let is_ok = match self.streams[index] {
                    Some(ref stream) => {
                        stream.get_src_port_and_dst() == (tcp.get_src(), dst) && !stream.is_closed()
                    }
                    None => false,
                };

                if is_ok {
                    self.streams[index].as_mut().unwrap().close();
                }
                // Send RST
                self.tx
                    .lock()
                    .unwrap()
                    .send_tcp_rst(dst, tcp.get_src(), tcp.get_sequence())?;
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
                Some(ref worker) => worker.get_src_port() != udp.get_src() || worker.is_closed(),
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

    fn get_local_tcp_port(&mut self, src_port: u16, dst: SocketAddrV4) -> u16 {
        let key = (src_port, dst);

        if !self.stream_map.contains_key(&key) {
            let index = (self.next_tcp_port - INITIAL_PORT) as usize;

            if let Some(ref prev) = self.stream_reverse_map[index] {
                self.stream_map.remove(prev);
            }
            self.stream_map.insert(key, self.next_tcp_port);
            self.stream_reverse_map[index] = Some(key);

            // To next port
            self.next_tcp_port = self.next_tcp_port + 1;
            if self.next_tcp_port >= INITIAL_PORT + PORT_COUNT as u16 {
                self.next_tcp_port = INITIAL_PORT;
            }
        }

        *self.stream_map.get(&key).unwrap()
    }

    fn get_local_udp_port(&mut self, src_port: u16) -> u16 {
        if self.datagram_map[src_port as usize] == 0 {
            let index = (self.next_udp_port - INITIAL_PORT) as usize;

            if self.datagram_reverse_map[index] != 0 {
                self.datagram_map[self.datagram_reverse_map[index] as usize] = 0;
            }
            self.datagram_map[src_port as usize] = self.next_udp_port;
            self.datagram_reverse_map[index] = src_port;

            // To next port
            self.next_udp_port = self.next_udp_port + 1;
            if self.next_udp_port >= INITIAL_PORT + PORT_COUNT as u16 {
                self.next_udp_port = INITIAL_PORT;
            }
        }

        self.datagram_map[src_port as usize]
    }
}

/// Represents a worker of a SOCKS5 TCP client.
pub struct StreamWorker {
    src_port: u16,
    local_port: u16,
    dst: SocketAddrV4,
    writer: BufWriter<TcpStream>,
    thread: JoinHandle<()>,
    is_closed: Arc<AtomicBool>,
}

impl StreamWorker {
    /// Construct a new `StreamWorker` and open it.
    pub fn new_and_open(
        tx: Arc<Mutex<Downstreamer>>,
        src_port: u16,
        local_port: u16,
        dst: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> io::Result<StreamWorker> {
        let (mut reader, writer) = socks::connect(remote, dst)?;

        let is_closed = AtomicBool::new(false);
        let a_is_closed = Arc::new(is_closed);
        let a_is_closed_cloned = Arc::clone(&a_is_closed);
        let thread = thread::spawn(move || {
            let mut buffer = [0u8; u16::MAX as usize];
            loop {
                if !a_is_closed_cloned.load(Ordering::Relaxed) {
                    return;
                }
                match reader.read(&mut buffer) {
                    Ok(size) => {
                        if !a_is_closed_cloned.load(Ordering::Relaxed) {
                            return;
                        }
                        debug!(
                            "receive from SOCKS: {}: {} -> {} ({} Bytes)",
                            "TCP", dst, local_port, size
                        );

                        // Send
                        if let Err(ref e) =
                            tx.lock()
                                .unwrap()
                                .send_tcp_ack(dst, src_port, &buffer[..size])
                        {
                            warn!("handle {}: {}", "TCP", e);
                        }
                    }
                    Err(ref e) => {
                        if e.kind() == io::ErrorKind::TimedOut {
                            continue;
                        }
                        warn!("SOCKS: {}", e);
                        a_is_closed_cloned.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            }
        });

        Ok(StreamWorker {
            src_port,
            local_port,
            dst,
            writer,
            thread,
            is_closed: a_is_closed,
        })
    }

    /// Sends data on the SOCKS5 in TCP to the destination.
    pub fn send(&mut self, buffer: &[u8]) -> io::Result<()> {
        debug!(
            "send to SOCKS {}: {} -> {} ({} Bytes)",
            "TCP",
            self.local_port,
            self.dst,
            buffer.len()
        );

        // Send
        self.writer.write_all(buffer)
    }

    /// Closes the worker.
    pub fn close(&mut self) {
        self.is_closed.store(true, Ordering::Relaxed);
    }

    /// Get the source port and the destination of the SOCKS5 TCP client.
    pub fn get_src_port_and_dst(&self) -> (u16, SocketAddrV4) {
        (self.src_port, self.dst)
    }

    /// Returns if the worker is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }
}

/// Represents a worker of a SOCKS5 UDP client.
pub struct DatagramWorker {
    src_port: u16,
    local_port: u16,
    datagram: Arc<SocksDatagram>,
    thread: JoinHandle<()>,
    is_closed: Arc<AtomicBool>,
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
        let is_closed = AtomicBool::new(false);
        let a_is_closed = Arc::new(is_closed);
        let a_is_closed_cloned = Arc::clone(&a_is_closed);
        let thread = thread::spawn(move || {
            let mut buffer = [0u8; u16::MAX as usize];
            loop {
                if !a_is_closed_cloned.load(Ordering::Relaxed) {
                    return;
                }
                match a_datagram_cloned.recv_from(&mut buffer) {
                    Ok((size, addr)) => {
                        if !a_is_closed_cloned.load(Ordering::Relaxed) {
                            return;
                        }
                        debug!(
                            "receive from SOCKS: {}: {} -> {} ({} Bytes)",
                            "UDP", addr, local_port, size
                        );

                        // Send
                        if let Err(ref e) =
                            tx.lock().unwrap().send_udp(addr, src_port, &buffer[..size])
                        {
                            warn!("handle {}: {}", "UDP", e);
                        }
                    }
                    Err(ref e) => {
                        if e.kind() == io::ErrorKind::TimedOut {
                            continue;
                        }
                        warn!("SOCKS: {}", e);
                        a_is_closed_cloned.store(true, Ordering::Relaxed);

                        return;
                    }
                }
            }
        });

        Ok(DatagramWorker {
            src_port,
            local_port,
            datagram: a_datagram,
            thread: thread,
            is_closed: a_is_closed,
        })
    }

    /// Sends data on the SOCKS5 in UDP to the destination.
    pub fn send_to(&mut self, buffer: &[u8], dst: SocketAddrV4) -> io::Result<usize> {
        debug!(
            "send to SOCKS {}: {} -> {} ({} Bytes)",
            "UDP",
            self.local_port,
            dst,
            buffer.len()
        );

        // Send
        self.datagram.send_to(buffer, dst)
    }

    /// Closes the worker.
    pub fn close(&mut self) {
        self.is_closed.store(true, Ordering::Relaxed);
    }

    /// Get the source port of the SOCKS5 UDP client.
    pub fn get_src_port(&self) -> u16 {
        self.src_port
    }

    /// Returns if the worker is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }
}
