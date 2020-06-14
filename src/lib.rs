use std::cmp::min;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

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
use packet::layer::{Layer, LayerTypes, Layers};
use packet::{Defraggler, Indicator};
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

/// Represents the initial UDP port for binding in local.
const INITIAL_PORT: u16 = 32768;
/// Represents the max limit of UDP port for binding in local.
const PORT_COUNT: usize = 64;

/// Represents the wait time after a `TimedOut` `IoError`.
const TIMEDOUT_WAIT: u64 = 20;

/// Represents the MSS of packet sending from local to source, this will become an option in the future.
const MSS: u32 = 1200;

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

    /// Get TCP acknowledgement to an TCP connection.
    pub fn get_tcp_acknowledgement(&mut self, dst: SocketAddrV4, src_port: u16) -> u32 {
        *self
            .tcp_acknowledgement_map
            .get(&(src_port, dst))
            .unwrap_or(&0)
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
        let ipv4_identification = *self.ipv4_identification_map.get(dst.ip()).unwrap();

        // IPv4
        let ipv4 = Ipv4::new(
            ipv4_identification,
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

        // Fragmentation
        let ipv4_header_size = ipv4.get_size();
        let udp_header_size = udp.get_size();
        let t = udp.get_type();
        if (MSS as usize) < ipv4_header_size + udp_header_size + payload.len() {
            let size = udp_header_size + payload.len();
            let mut n = 0;

            // First fragmentation with UDP layer
            {
                let mut length = min(size - n, MSS as usize - ipv4_header_size);
                let mut remain = size - n - length;

                // Alignment
                if remain > 0 {
                    length = length / 8 * 8;
                    remain = size - n - length;
                }

                // Leave at least 8 Bytes for last fragment
                if remain > 0 && remain < 8 {
                    length = length - 8;
                }

                // IPv4
                if n / 8 > u16::MAX as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "payload too big",
                    ));
                }
                let ipv4 = Ipv4::new_more_fragment(
                    ipv4_identification,
                    t,
                    (n / 8) as u16,
                    dst.ip().clone(),
                    self.src_ip_addr,
                )
                .unwrap();

                // Indicator
                let indicator = Indicator::new(
                    Layers::Ethernet(ethernet.clone()),
                    Some(Layers::Ipv4(ipv4)),
                    Some(Layers::Udp(udp)),
                );

                // Send
                self.send_with_payload(&indicator, &payload[..length - udp_header_size])?;

                n = n + length;
            }

            // Other fragmentations
            loop {
                let mut length = min(size - n, MSS as usize - ipv4_header_size);
                let mut remain = size - n - length;

                // Alignment
                if remain > 0 {
                    length = length / 8 * 8;
                    remain = size - n - length;
                }

                // Leave at least 8 Bytes for last fragment
                if remain > 0 && remain < 8 {
                    length = length - 8;
                    remain = size - n - length;
                }

                // IPv4
                let ipv4;
                if n / 8 > u16::MAX as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "payload too big",
                    ));
                }
                if remain > 0 {
                    ipv4 = Ipv4::new_more_fragment(
                        ipv4_identification,
                        t,
                        (n / 8) as u16,
                        dst.ip().clone(),
                        self.src_ip_addr,
                    )
                    .unwrap();
                } else {
                    ipv4 = Ipv4::new_last_fragment(
                        ipv4_identification,
                        t,
                        (n / 8) as u16,
                        dst.ip().clone(),
                        self.src_ip_addr,
                    )
                    .unwrap();
                }

                // Indicator
                let indicator = Indicator::new(
                    Layers::Ethernet(ethernet.clone()),
                    Some(Layers::Ipv4(ipv4)),
                    None,
                );

                // Send
                self.send_with_payload(
                    &indicator,
                    &payload[n - udp_header_size..n + length - udp_header_size],
                )?;

                n = n + length;
                if remain == 0 {
                    break;
                }
            }
        } else {
            // Indicator
            let indicator = Indicator::new(
                Layers::Ethernet(ethernet),
                Some(Layers::Ipv4(ipv4)),
                Some(Layers::Udp(udp)),
            );

            // Send
            self.send_with_payload(&indicator, payload)?;
        }

        // Update IPv4 identification
        let ipv4_identification_entry = self
            .ipv4_identification_map
            .entry(dst.ip().clone())
            .or_insert(0);
        *ipv4_identification_entry += 1;

        Ok(())
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
        let ipv4_identification = *self.ipv4_identification_map.get(dst.ip()).unwrap();

        // IPv4
        let ipv4 = Ipv4::new(
            ipv4_identification,
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

        // Segmentation
        let header_size = ipv4.get_size() + tcp.get_size();
        let max_payload_size = MSS as usize - header_size;
        if (MSS as usize) < header_size + payload.len() {
            let mut i = 0;
            loop {
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
                let ipv4_identification = *self.ipv4_identification_map.get(dst.ip()).unwrap();

                // IPv4
                let ipv4 = Ipv4::new(
                    ipv4_identification,
                    tcp.get_type(),
                    dst.ip().clone(),
                    self.src_ip_addr,
                )
                .unwrap();

                // Indicator
                let indicator = Indicator::new(
                    Layers::Ethernet(ethernet.clone()),
                    Some(Layers::Ipv4(ipv4)),
                    Some(Layers::Tcp(tcp)),
                );

                // Send
                let length = min(max_payload_size, payload.len() - i * max_payload_size);
                self.send_with_payload(
                    &indicator,
                    &payload[i * max_payload_size..i * max_payload_size + length],
                )?;

                // Update TCP sequence
                let tcp_sequence_entry = self.tcp_sequence_map.entry(key).or_insert(0);
                if length > u32::MAX as usize {
                    return Err(io::Error::new(io::ErrorKind::Other, "length too big"));
                }
                *tcp_sequence_entry = (*tcp_sequence_entry)
                    .checked_add(length as u32)
                    .unwrap_or_else(|| length as u32 - (u32::MAX - *tcp_sequence_entry));

                // Update IPv4 identification
                let ipv4_identification_entry = self
                    .ipv4_identification_map
                    .entry(dst.ip().clone())
                    .or_insert(0);
                *ipv4_identification_entry += 1;

                i += 1;
                if max_payload_size * i >= payload.len() {
                    break;
                }
            }
        } else {
            // Indicator
            let indicator = Indicator::new(
                Layers::Ethernet(ethernet),
                Some(Layers::Ipv4(ipv4)),
                Some(Layers::Tcp(tcp)),
            );

            // Send
            self.send_with_payload(&indicator, payload)?;

            // Update TCP sequence
            let tcp_sequence_entry = self.tcp_sequence_map.entry(key).or_insert(0);
            if payload.len() > u32::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "payload too big",
                ));
            }
            *tcp_sequence_entry = (*tcp_sequence_entry)
                .checked_add(payload.len() as u32)
                .unwrap_or_else(|| payload.len() as u32 - (u32::MAX - *tcp_sequence_entry));

            // Update IPv4 identification
            let ipv4_identification_entry = self
                .ipv4_identification_map
                .entry(dst.ip().clone())
                .or_insert(0);
            *ipv4_identification_entry += 1;
        }

        Ok(())
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
        // TCP acknowledgement
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

    /// Sends an TCP ACK/FIN packet.
    pub fn send_tcp_ack_fin(
        &mut self,
        dst: SocketAddrV4,
        src_port: u16,
        sequence: u32,
    ) -> io::Result<()> {
        // TCP acknowledgement
        let key = (src_port, dst);
        self.tcp_acknowledgement_map.insert(key, sequence);

        // TCP
        let tcp = Tcp::new_ack_fin(
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

    /// Sends an TCP RST packet.
    pub fn send_tcp_rst(
        &mut self,
        dst: SocketAddrV4,
        src_port: u16,
        sequence: u32,
    ) -> io::Result<()> {
        // TCP acknowledgement
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
            "send to pcap: {} ({} + {} Bytes)",
            indicator.brief(),
            size,
            payload.len()
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
    streams: HashMap<(u16, SocketAddrV4), StreamWorker>,
    next_udp_port: u16,
    datagrams: Vec<Option<DatagramWorker>>,
    datagram_map: Vec<u16>,
    datagram_reverse_map: Vec<u16>,
    defrag: Defraggler,
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
            streams: HashMap::new(),
            next_udp_port: INITIAL_PORT,
            datagrams: (0..PORT_COUNT).map(|_| None).collect(),
            datagram_map: vec![0u16; u16::MAX as usize],
            datagram_reverse_map: vec![0u16; PORT_COUNT],
            defrag: Defraggler::new(),
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
                        thread::sleep(Duration::from_millis(TIMEDOUT_WAIT));
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
                    // Fragmentation
                    let frag = match self.defrag.add(indicator, buffer) {
                        Some(frag) => frag,
                        None => return Ok(()),
                    };
                    let (indicator, buffer) = frag.concatenate();

                    if let Some(t) = indicator.get_transport_type() {
                        match t {
                            LayerTypes::Tcp => self.handle_tcp(&indicator, buffer)?,
                            LayerTypes::Udp => self.handle_udp(&indicator, buffer)?,
                            _ => unreachable!(),
                        }
                    }
                } else {
                    if let Some(t) = indicator.get_transport_type() {
                        match t {
                            LayerTypes::Tcp => self.handle_tcp(indicator, buffer)?,
                            LayerTypes::Udp => self.handle_udp(indicator, buffer)?,
                            _ => unreachable!(),
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_tcp(&mut self, indicator: &Indicator, buffer: &[u8]) -> io::Result<()> {
        if let Some(ref tcp) = indicator.get_tcp() {
            let dst = SocketAddrV4::new(tcp.get_dst_ip_addr(), tcp.get_dst());
            let key = (tcp.get_src(), dst);
            let mut is_alive = false;
            let mut is_last_ack = false;
            match self.streams.get(&key) {
                Some(ref stream) => {
                    is_alive = !stream.is_closed();
                    is_last_ack = stream.is_last_ack();
                }
                None => {}
            };

            // TODO: Record window size

            if tcp.is_rst() {
                if is_alive {
                    self.streams.get_mut(&key).unwrap().close();
                }
            } else if tcp.is_fin() {
                if is_alive {
                    self.streams.get_mut(&key).unwrap().set_last_ack(true);
                    self.streams.get_mut(&key).unwrap().close();

                    // Send ACK/FIN
                    self.tx.lock().unwrap().send_tcp_ack_fin(
                        dst,
                        tcp.get_src(),
                        tcp.get_sequence() + 1,
                    )?;
                } else {
                    // Send RST
                    self.tx.lock().unwrap().send_tcp_rst(
                        dst,
                        tcp.get_src(),
                        tcp.get_sequence() + 1,
                    )?;
                }
            } else if tcp.is_syn() {
                // Close before reconnect
                if is_alive {
                    self.streams.get_mut(&key).unwrap().close();
                }

                // Connect
                let stream = match StreamWorker::new_and_open(
                    self.get_tx(),
                    tcp.get_src(),
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

                        stream
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
                };

                self.streams.insert(key, stream);
            } else if tcp.is_ack() {
                if is_alive {
                    if buffer.len() > indicator.get_size() {
                        let record_sequence = self.tx.lock().unwrap().get_tcp_acknowledgement(
                            SocketAddrV4::new(tcp.get_dst_ip_addr(), tcp.get_dst()),
                            tcp.get_src(),
                        );

                        // Check valid
                        if record_sequence == tcp.get_sequence() {
                            // Send
                            match self
                                .streams
                                .get_mut(&key)
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
                        } else {
                            // Unordered packet or retransmission
                            // Send ACK0
                            self.tx.lock().unwrap().send_tcp_ack_0(dst, tcp.get_src())?;
                        }
                    }
                } else {
                    if is_last_ack {
                        self.streams.get_mut(&key).unwrap().set_last_ack(false);
                    } else {
                        // Send RST
                        self.tx.lock().unwrap().send_tcp_rst(
                            dst,
                            tcp.get_src(),
                            tcp.get_sequence(),
                        )?;
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

    fn get_local_udp_port(&mut self, src_port: u16) -> u16 {
        if self.datagram_map[src_port as usize] == 0 {
            let index = (self.next_udp_port - INITIAL_PORT) as usize;

            if self.datagram_reverse_map[index] != 0 {
                self.datagram_map[self.datagram_reverse_map[index] as usize] = 0;
            }
            self.datagram_map[src_port as usize] = self.next_udp_port;
            self.datagram_reverse_map[index] = src_port;

            // To next port
            if self.next_udp_port == u16::MAX {
                self.next_udp_port = 0;
            } else {
                self.next_udp_port = self.next_udp_port + 1;
            }
            if self.next_udp_port > INITIAL_PORT + (PORT_COUNT - 1) as u16
                || self.next_udp_port == 0
            {
                self.next_udp_port = INITIAL_PORT;
            }
        }

        self.datagram_map[src_port as usize]
    }
}

/// Represents a worker of a SOCKS5 TCP client.
pub struct StreamWorker {
    src_port: u16,
    dst: SocketAddrV4,
    stream: TcpStream,
    thread: Option<JoinHandle<()>>,
    is_closed: Arc<AtomicBool>,
    is_last_ack: bool,
}

impl StreamWorker {
    /// Construct a new `StreamWorker` and open it.
    pub fn new_and_open(
        tx: Arc<Mutex<Downstreamer>>,
        src_port: u16,
        dst: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> io::Result<StreamWorker> {
        let stream = socks::connect(remote, dst)?;
        let mut stream_cloned = stream.try_clone()?;

        let is_closed = AtomicBool::new(false);
        let a_is_closed = Arc::new(is_closed);
        let a_is_closed_cloned = Arc::clone(&a_is_closed);
        let thread = thread::spawn(move || {
            let mut buffer = [0u8; u16::MAX as usize];
            loop {
                if a_is_closed_cloned.load(Ordering::Relaxed) {
                    return;
                }
                match stream_cloned.read(&mut buffer) {
                    Ok(size) => {
                        if a_is_closed_cloned.load(Ordering::Relaxed) {
                            return;
                        }
                        if size == 0 {
                            a_is_closed_cloned.store(true, Ordering::Relaxed);
                            return;
                        }
                        debug!(
                            "receive from SOCKS: {}: {} -> {} ({} Bytes)",
                            "TCP", dst, 0, size
                        );

                        // TODO: Make a large array to cache and send according to the window size
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
                            thread::sleep(Duration::from_millis(TIMEDOUT_WAIT));
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
            dst,
            stream,
            thread: Some(thread),
            is_closed: a_is_closed,
            is_last_ack: false,
        })
    }

    /// Sends data on the SOCKS5 in TCP to the destination.
    pub fn send(&mut self, buffer: &[u8]) -> io::Result<()> {
        debug!(
            "send to SOCKS {}: {} -> {} ({} Bytes)",
            "TCP",
            "0",
            self.dst,
            buffer.len()
        );

        // Send
        self.stream.write_all(buffer)
    }

    /// Closes the worker.
    pub fn close(&mut self) {
        self.is_closed.store(true, Ordering::Relaxed);
    }

    /// Set the state LAST_ACK of the worker.
    pub fn set_last_ack(&mut self, value: bool) {
        self.close();
        self.is_last_ack = value;
    }

    /// Get the source port and the destination of the SOCKS5 TCP client.
    pub fn get_src_port_and_dst(&self) -> (u16, SocketAddrV4) {
        (self.src_port, self.dst)
    }

    /// Returns if the worker is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }

    /// Returns if the worker is in state LAST_ACK.
    pub fn is_last_ack(&self) -> bool {
        self.is_last_ack
    }
}

impl Drop for StreamWorker {
    fn drop(&mut self) {
        self.close();
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

/// Represents a worker of a SOCKS5 UDP client.
pub struct DatagramWorker {
    src_port: u16,
    local_port: u16,
    datagram: Arc<SocksDatagram>,
    thread: Option<JoinHandle<()>>,
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
                if a_is_closed_cloned.load(Ordering::Relaxed) {
                    return;
                }
                match a_datagram_cloned.recv_from(&mut buffer) {
                    Ok((size, addr)) => {
                        if a_is_closed_cloned.load(Ordering::Relaxed) {
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
                            thread::sleep(Duration::from_millis(TIMEDOUT_WAIT));
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
            thread: Some(thread),
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

impl Drop for DatagramWorker {
    fn drop(&mut self) {
        self.close();
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
