use std::cmp::{max, min};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::ops::Bound::Included;
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
use packet::layer::{Layer, LayerType, LayerTypes, Layers};
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

/// Represents the initial size of cache.
const INITIAL_CACHE_SIZE: usize = 65536;
/// Represents the max size of cache.
const MAX_CACHE_SIZE: usize = 262144;

/// Represents the max distance of u32 values between packets in an u32 window.
const MAX_U32_WINDOW_SIZE: usize = 524288;

/// Represents the linear cache.
pub struct Cacher {
    buffer: Vec<u8>,
    sequence: u32,
    head: usize,
    size: usize,
}

impl Cacher {
    /// Creates a new `Cacher`.
    pub fn new(sequence: u32) -> Cacher {
        Cacher {
            buffer: vec![0; INITIAL_CACHE_SIZE],
            sequence,
            head: 0,
            size: 0,
        }
    }

    /// Get the buffer in the given size. The returned vector's length will be no more than the given size.
    pub fn get(&self, size: usize) -> Option<Vec<u8>> {
        if self.size == 0 {
            return None;
        }

        let length = min(self.size, size);
        let mut vector = vec![0u8; length];

        // From the head to the end of the buffer
        let length_a = min(length, self.buffer.len() - self.head);
        vector[..length_a].copy_from_slice(&self.buffer[self.head..self.head + length_a]);

        // From the begin of the buffer to the tail
        let length_b = length - length_a;
        if length_b > 0 {
            vector[length_a..].copy_from_slice(&self.buffer[..length_b]);
        }

        Some(vector)
    }

    /// Appends some bytes to the end of the cache.
    pub fn append(&mut self, buffer: &[u8]) -> io::Result<()> {
        if buffer.len() > self.buffer.len() - self.size {
            // Extend the buffer
            let size = min(
                max(self.buffer.len() * 2, self.buffer.len() + buffer.len()),
                MAX_CACHE_SIZE,
            );
            if self.size + buffer.len() > size {
                return Err(io::Error::new(io::ErrorKind::Other, "cache is full"));
            }

            trace!("extend cache to {} Bytes", size);
            warn!("cache is extended: a congestion may be in your network");
            let mut new_buffer = vec![0u8; size];

            // From the head to the end of the buffer
            let length_a = min(self.head + self.size, self.buffer.len());
            new_buffer[..length_a].copy_from_slice(&self.buffer[length_a..]);

            // From the begin of the buffer to the tail
            let length_b = self.size - length_a;
            if length_b > 0 {
                new_buffer[length_a..length_a + length_b].copy_from_slice(&self.buffer[..length_b]);
            }

            self.buffer = new_buffer;
            self.head = 0;
        }

        trace!("append {} Bytes to cache", buffer.len());

        // From the tail to the end of the buffer
        let mut length_a = 0;
        if self.head + self.size < self.buffer.len() {
            length_a = min(buffer.len(), self.buffer.len() - (self.head + self.size));
            self.buffer[self.head + self.size..self.head + self.size + length_a]
                .copy_from_slice(&buffer[..length_a]);
        }

        // From the begin of the buffer to the head
        let length_b = buffer.len() - length_a;
        if length_b > 0 {
            self.buffer[..length_b].copy_from_slice(&buffer[length_a..]);
        }

        self.size += buffer.len();

        Ok(())
    }

    // Invalidates cache to the certain sequence.
    pub fn invalidate_to(&mut self, sequence: u32) {
        trace!("invalidate cache to sequence {}", sequence);

        let size = sequence
            .checked_sub(self.sequence)
            .unwrap_or_else(|| u32::MAX - self.sequence + sequence) as usize;

        if size <= MAX_U32_WINDOW_SIZE as usize {
            self.sequence = sequence;
            self.size = self.size.checked_sub(size).unwrap_or(0);
            if self.size == 0 {
                self.head = 0;
            } else {
                self.head = (self.head + (size % self.buffer.len())) % self.buffer.len();
            }
        }
    }
}

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
    tcp_cache_map: HashMap<(u16, SocketAddrV4), Cacher>,
}

impl Downstreamer {
    /// Creates a new `Downstreamer`.
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
            tcp_cache_map: HashMap::new(),
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
        *entry = entry
            .checked_add(n)
            .unwrap_or_else(|| n - (u32::MAX - *entry));
    }

    /// Invalidates TCP cache to the given sequence.
    pub fn invalidate_cache_to(&mut self, dst: SocketAddrV4, src_port: u16, sequence: u32) {
        trace!(
            "invalidate cache {} -> {} to sequence {}",
            dst,
            src_port,
            sequence
        );
        if let Some(cache) = self.tcp_cache_map.get_mut(&(src_port, dst)) {
            cache.invalidate_to(sequence);
        }
    }

    /// Removes a TCP cache.
    pub fn remove_cache(&mut self, dst: SocketAddrV4, src_port: u16) {
        trace!("remove cache {} -> {}", dst, src_port,);
        self.tcp_cache_map.remove(&(src_port, dst));
    }

    fn increase_ipv4_identification(&mut self, ip_addr: Ipv4Addr) {
        let entry = self.ipv4_identification_map.entry(ip_addr).or_insert(0);

        *entry = entry.checked_add(1).unwrap_or(0);
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

        // Send
        self.send(&indicator)
    }

    /// Resends TCP ACK packets from the given sequence if necessary.
    pub fn resend_tcp_ack(
        &mut self,
        dst: SocketAddrV4,
        src_port: u16,
        sequence: u32,
    ) -> io::Result<()> {
        let key = (src_port, dst);

        // Psuedo headers
        let tcp = Tcp::new_ack(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 0, 0, 0, 0);
        let ipv4 = Ipv4::new(
            0,
            tcp.get_type(),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        )
        .unwrap();

        // Resend
        let header_size = ipv4.get_size() + tcp.get_size();
        let length = MSS as usize - header_size;
        let buffer = match self.tcp_cache_map.get(&key) {
            Some(cache) => match cache.get(length) {
                Some(buffer) => Some(buffer),
                None => None,
            },
            None => None,
        };

        if let Some(buffer) = buffer {
            // Send
            self.send_tcp_ack_raw(dst, src_port, sequence, &buffer)?;
        }

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

        // Psuedo headers
        let tcp = Tcp::new_ack(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 0, 0, 0, 0);
        let ipv4 = Ipv4::new(
            0,
            tcp.get_type(),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        )
        .unwrap();

        // Segmentation
        let header_size = ipv4.get_size() + tcp.get_size();
        let max_payload_size = MSS as usize - header_size;
        let mut i = 0;
        while max_payload_size * i < payload.len() {
            // Send
            let length = min(max_payload_size, payload.len() - i * max_payload_size);
            let payload = &payload[i * max_payload_size..i * max_payload_size + length];
            let sequence = *self.tcp_sequence_map.get(&key).or(Some(&0)).unwrap();
            self.send_tcp_ack_raw(dst, src_port, sequence, payload)?;

            // Append to cache
            let cache = self
                .tcp_cache_map
                .entry(key)
                .or_insert_with(|| Cacher::new(sequence));
            cache.append(payload)?;

            // Update TCP sequence
            let tcp_sequence_entry = self.tcp_sequence_map.entry(key).or_insert(0);
            if length > u32::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "payload too big",
                ));
            }
            *tcp_sequence_entry = (*tcp_sequence_entry)
                .checked_add(length as u32)
                .unwrap_or_else(|| length as u32 - (u32::MAX - *tcp_sequence_entry));

            i += 1;
        }

        Ok(())
    }

    fn send_tcp_ack_raw(
        &mut self,
        dst: SocketAddrV4,
        src_port: u16,
        sequence: u32,
        payload: &[u8],
    ) -> io::Result<()> {
        let key = (src_port, dst);

        // TCP
        let tcp = Tcp::new_ack(
            dst.ip().clone(),
            self.src_ip_addr,
            dst.port(),
            src_port,
            sequence,
            *self.tcp_acknowledgement_map.get(&key).unwrap(),
        );

        // Send
        self.send_ipv4_with_transport(Layers::Tcp(tcp), Some(payload))
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

        // Send
        self.send_ipv4_with_transport(Layers::Tcp(tcp), None)
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

        // Send
        self.send_ipv4_with_transport(Layers::Tcp(tcp), None)?;

        // Update TCP sequence
        let tcp_sequence_entry = self.tcp_sequence_map.entry(key).or_insert(0);
        *tcp_sequence_entry = tcp_sequence_entry.checked_add(1).unwrap_or(0);

        Ok(())
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

        // Send
        self.send_ipv4_with_transport(Layers::Tcp(tcp), None)
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
            0,
        );

        // Send
        self.send_ipv4_with_transport(Layers::Tcp(tcp), None)
    }

    /// Sends an UDP packet.
    pub fn send_udp(&mut self, dst: SocketAddrV4, src_port: u16, payload: &[u8]) -> io::Result<()> {
        // Psuedo headers
        let udp = Udp::new(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 0, 0);
        let ipv4 = Ipv4::new(
            0,
            udp.get_type(),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        )
        .unwrap();

        // Fragmentation
        let ipv4_header_size = ipv4.get_size();
        let udp_header_size = udp.get_size();

        let size = udp_header_size + payload.len();
        let mut n = 0;
        while n < size {
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

            // Send
            if n / 8 > u16::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "payload too big",
                ));
            }
            if n == 0 {
                if remain > 0 {
                    // UDP
                    let udp = Udp::new(dst.ip().clone(), self.src_ip_addr, dst.port(), src_port);

                    self.send_ipv4_more_fragment(
                        dst.ip().clone(),
                        udp.get_type(),
                        (n / 8) as u16,
                        Some(Layers::Udp(udp)),
                        &payload[..length - udp_header_size],
                    )?;
                } else {
                    self.send_udp_raw(dst, src_port, payload)?;
                }
            } else {
                if remain > 0 {
                    self.send_ipv4_more_fragment(
                        dst.ip().clone(),
                        udp.get_type(),
                        (n / 8) as u16,
                        None,
                        &payload[n - udp_header_size..n + length - udp_header_size],
                    )?;
                } else {
                    self.send_ipv4_last_fragment(
                        dst.ip().clone(),
                        udp.get_type(),
                        (n / 8) as u16,
                        &payload[n - udp_header_size..n + length - udp_header_size],
                    )?;
                }
            }

            n = n + length;
        }

        Ok(())
    }

    pub fn send_udp_raw(
        &mut self,
        dst: SocketAddrV4,
        src_port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        // UDP
        let udp = Udp::new(dst.ip().clone(), self.src_ip_addr, dst.port(), src_port);

        self.send_ipv4_with_transport(Layers::Udp(udp), Some(payload))
    }

    fn send_ipv4_more_fragment(
        &mut self,
        dst_ip_addr: Ipv4Addr,
        t: LayerType,
        fragment_offset: u16,
        transport: Option<Layers>,
        payload: &[u8],
    ) -> io::Result<()> {
        // IPv4 identification
        if !self.ipv4_identification_map.contains_key(&dst_ip_addr) {
            self.ipv4_identification_map.insert(dst_ip_addr, 0);
        }
        let ipv4_identification = *self.ipv4_identification_map.get(&dst_ip_addr).unwrap();

        // IPv4
        let ipv4 = Ipv4::new_more_fragment(
            ipv4_identification,
            t,
            fragment_offset,
            dst_ip_addr,
            self.src_ip_addr,
        )
        .unwrap();

        // Send
        self.send_ethernet(Layers::Ipv4(ipv4), transport, Some(payload))
    }

    fn send_ipv4_last_fragment(
        &mut self,
        dst_ip_addr: Ipv4Addr,
        t: LayerType,
        fragment_offset: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        // IPv4 identification
        if !self.ipv4_identification_map.contains_key(&dst_ip_addr) {
            self.ipv4_identification_map.insert(dst_ip_addr, 0);
        }
        let ipv4_identification = *self.ipv4_identification_map.get(&dst_ip_addr).unwrap();

        // IPv4
        let ipv4 = Ipv4::new_last_fragment(
            ipv4_identification,
            t,
            fragment_offset,
            dst_ip_addr,
            self.src_ip_addr,
        )
        .unwrap();

        // Send
        self.send_ethernet(Layers::Ipv4(ipv4), None, Some(payload))?;

        // Update IPv4 identification
        self.increase_ipv4_identification(dst_ip_addr);

        Ok(())
    }

    fn send_ipv4_with_transport(
        &mut self,
        transport: Layers,
        payload: Option<&[u8]>,
    ) -> io::Result<()> {
        let dst_ip_addr = match transport {
            Layers::Tcp(ref tcp) => tcp.get_src_ip_addr(),
            Layers::Udp(ref udp) => udp.get_dst_ip_addr(),
            _ => unreachable!(),
        };

        // IPv4 identification
        if !self.ipv4_identification_map.contains_key(&dst_ip_addr) {
            self.ipv4_identification_map.insert(dst_ip_addr, 0);
        }
        let ipv4_identification = *self.ipv4_identification_map.get(&dst_ip_addr).unwrap();

        // IPv4
        let ipv4 = Ipv4::new(
            ipv4_identification,
            transport.get_type(),
            dst_ip_addr,
            self.src_ip_addr,
        )
        .unwrap();

        // Send
        self.send_ethernet(Layers::Ipv4(ipv4), Some(transport), payload)?;

        // Update IPv4 identification
        self.increase_ipv4_identification(dst_ip_addr);

        Ok(())
    }

    fn send_ethernet(
        &mut self,
        network: Layers,
        transport: Option<Layers>,
        payload: Option<&[u8]>,
    ) -> io::Result<()> {
        // Ethernet
        let ethernet = Ethernet::new(
            network.get_type(),
            self.local_hardware_addr,
            self.src_hardware_addr,
        )
        .unwrap();

        // Indicator
        let indicator = Indicator::new(Layers::Ethernet(ethernet), Some(network), transport);

        // Send
        match payload {
            Some(payload) => self.send_with_payload(&indicator, payload),
            None => self.send(&indicator),
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

/// Represents the random cache.
pub struct RandomCacher {
    buffer: Vec<u8>,
    sequence: u32,
    head: usize,
    /// Represents ranges of existing values. Use an u64 instead of an u32 because the sequence is used as a ring.
    ranges: BTreeMap<u64, usize>,
}

impl RandomCacher {
    /// Creates a new `RandomCacher`.
    pub fn new(sequence: u32) -> RandomCacher {
        RandomCacher {
            buffer: vec![0u8; INITIAL_CACHE_SIZE],
            sequence,
            head: 0,
            ranges: BTreeMap::new(),
        }
    }

    /// Appends some bytes to the cache and returns continuous bytes from the beginning.
    pub fn append(&mut self, buffer: &[u8], sequence: u32) -> io::Result<Option<Vec<u8>>> {
        let sub_sequence = sequence
            .checked_sub(self.sequence)
            .unwrap_or_else(|| sequence + (u32::MAX - self.sequence))
            as usize;
        if sub_sequence > MAX_U32_WINDOW_SIZE {
            return Ok(None);
        }

        let size = sub_sequence + buffer.len();
        if size > self.buffer.len() {
            // Extend the buffer
            let size = min(max(self.buffer.len() * 2, size), MAX_CACHE_SIZE);
            if self.buffer.len() + buffer.len() > size {
                return Err(io::Error::new(io::ErrorKind::Other, "cache is full"));
            }

            trace!("extend cache to {} Bytes", size);
            warn!("cache is extended: a congestion may be in your network");
            let mut new_buffer = vec![0u8; size];

            // TODO: the procedure may by optimized to copy valid bytes only
            // From the head to the end of the buffer
            new_buffer[..self.buffer.len() - self.head].copy_from_slice(&self.buffer[self.head..]);

            // From the begin of the buffer to the tail
            if self.head > 0 {
                new_buffer[self.buffer.len() - self.head..self.buffer.len()]
                    .copy_from_slice(&self.buffer[..self.head]);
            }

            self.buffer = new_buffer;
            self.head = 0;
        }

        trace!("append {} Bytes to cache", buffer.len());

        // TODO: the procedure may by optimized to copy valid bytes only
        // To the end of the buffer
        let mut length_a = 0;
        if self.buffer.len() - self.head > sub_sequence {
            length_a = min(self.buffer.len() - self.head - sub_sequence, buffer.len());
            self.buffer[self.head + sub_sequence..self.head + sub_sequence + length_a]
                .copy_from_slice(&buffer[..length_a]);
        }

        // From the begin of the buffer
        let length_b = buffer.len() - length_a;
        if length_b > 0 {
            self.buffer[..length_b].copy_from_slice(&buffer[length_a..]);
        }

        // Insert and merge ranges
        {
            let mut sequence = sequence as u64;
            if (sequence as u32) < self.sequence {
                sequence += u32::MAX as u64;
            }

            // Select ranges which can be merged
            let mut pop_keys = Vec::new();
            let mut end = sequence + buffer.len() as u64;
            for (&key, &value) in self.ranges.range((
                Included(&sequence),
                Included(&(sequence + buffer.len() as u64)),
            )) {
                pop_keys.push(key);
                end = max(end, key + value as u64);
            }

            // Pop
            for ref pop_key in pop_keys {
                self.ranges.remove(pop_key);
            }

            // Select the previous range if exists
            let mut prev_key = None;
            for &key in self.ranges.keys() {
                if key < sequence {
                    prev_key = Some(key);
                }
            }

            // Merge previous range
            let mut size = buffer.len();
            if let Some(prev_key) = prev_key {
                let prev_size = *self.ranges.get(&prev_key).unwrap();
                if prev_key + (prev_size as u64) >= sequence {
                    size += (sequence - prev_key) as usize;
                    sequence = prev_key;
                }
            }

            // Insert range
            self.ranges.insert(sequence, size);
        }

        // Pop if possible
        let first_key = *self.ranges.keys().next().unwrap();
        if first_key as u32 == self.sequence {
            let size = self.ranges.remove(&first_key).unwrap();

            // Shrink range sequence is possible
            if ((u32::MAX - self.sequence) as usize) < size {
                let keys: Vec<_> = self.ranges.keys().map(|x| *x).collect();

                for key in keys {
                    let value = self.ranges.remove(&key).unwrap();
                    self.ranges.insert(key - u32::MAX as u64, value);
                }
            }

            let mut vector = vec![0u8; size];

            // From the head to the end of the buffer
            let length_a = min(size, self.buffer.len() - self.head);
            vector[..length_a].copy_from_slice(&self.buffer[self.head..self.head + length_a]);

            // From the begin of the buffer to the tail
            let length_b = size - length_a;
            if length_b > 0 {
                vector[length_a..].copy_from_slice(&self.buffer[..length_b]);
            }

            self.sequence = self
                .sequence
                .checked_add(size as u32)
                .unwrap_or_else(|| size as u32 - (u32::MAX - self.sequence));
            self.head = (self.head + (size % self.buffer.len())) % self.buffer.len();

            trace!("pop cache to sequence {}", self.sequence);

            return Ok(Some(vector));
        }

        Ok(None)
    }
}

/// Represents the initial UDP port for binding in local.
const INITIAL_PORT: u16 = 32768;
/// Represents the max limit of UDP port for binding in local.
const PORT_COUNT: usize = 64;

/// Represents the channel upstream traffic to the proxy of SOCKS or loopback to the source in pcap.
pub struct Upstreamer {
    tx: Arc<Mutex<Downstreamer>>,
    is_tx_src_hardware_addr_set: bool,
    src_ip_addr: Ipv4Addr,
    local_ip_addr: Option<Ipv4Addr>,
    remote: SocketAddrV4,
    streams: HashMap<(u16, SocketAddrV4), StreamWorker>,
    tcp_acknowledgement_map: HashMap<(u16, SocketAddrV4), u32>,
    tcp_acknowledgement_count_map: HashMap<(u16, SocketAddrV4), u8>,
    tcp_cache_map: HashMap<(u16, SocketAddrV4), RandomCacher>,
    next_udp_port: u16,
    datagrams: Vec<Option<DatagramWorker>>,
    datagram_map: Vec<u16>,
    datagram_reverse_map: Vec<u16>,
    defrag: Defraggler,
}

impl Upstreamer {
    /// Creates a new `Upstreamer`.
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
            tcp_acknowledgement_map: HashMap::new(),
            tcp_acknowledgement_count_map: HashMap::new(),
            tcp_cache_map: HashMap::new(),
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

            if tcp.is_rst() {
                if is_alive {
                    self.streams.get_mut(&key).unwrap().close();
                }
            } else if tcp.is_fin() {
                if is_alive {
                    let stream = self.streams.get_mut(&key).unwrap();
                    stream.set_last_ack(true);
                    stream.close();

                    // Send ACK/FIN
                    let mut tx_locked = self.tx.lock().unwrap();
                    tx_locked.remove_cache(dst, tcp.get_src());
                    tx_locked.send_tcp_ack_fin(
                        dst,
                        tcp.get_src(),
                        tcp.get_sequence().checked_add(1).unwrap_or(0),
                    )?;
                } else {
                    // Send RST
                    self.tx.lock().unwrap().send_tcp_rst(
                        dst,
                        tcp.get_src(),
                        tcp.get_sequence().checked_add(1).unwrap_or(0),
                    )?;
                }
            } else if tcp.is_syn() {
                // Close before reconnect
                if is_alive {
                    self.streams.get_mut(&key).unwrap().close();
                    self.tx.lock().unwrap().remove_cache(dst, tcp.get_src());
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
                            tcp.get_sequence().checked_add(1).unwrap_or(0),
                        )?;

                        stream
                    }
                    Err(e) => {
                        // Send RST
                        self.tx.lock().unwrap().send_tcp_rst(
                            dst,
                            tcp.get_src(),
                            tcp.get_sequence().checked_add(1).unwrap_or(0),
                        )?;

                        return Err(e);
                    }
                };

                self.streams.insert(key, stream);
            } else if tcp.is_ack() {
                if is_alive {
                    // ACK
                    self.update_tcp_acknowledgement(indicator);
                    if buffer.len() > indicator.get_size() {
                        // Append to cache
                        let cache = self
                            .tcp_cache_map
                            .entry(key)
                            .or_insert_with(|| RandomCacher::new(tcp.get_sequence()));

                        let payload =
                            cache.append(&buffer[indicator.get_size()..], tcp.get_sequence())?;
                        if let Some(payload) = payload {
                            // Send
                            match self.streams.get_mut(&key).unwrap().send(payload.as_slice()) {
                                Ok(_) => {
                                    // Update TCP acknowledgement
                                    let mut tx_locked = self.tx.lock().unwrap();
                                    tx_locked.add_tcp_acknowledgement(
                                        dst,
                                        tcp.get_src(),
                                        payload.len() as u32,
                                    );
                                    // Send ACK0
                                    tx_locked.send_tcp_ack_0(dst, tcp.get_src())?;
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
                        // ACK0
                        if *self
                            .tcp_acknowledgement_count_map
                            .get(&(tcp.get_src(), dst))
                            .unwrap_or(&0)
                            > 3
                        {
                            // Retransmit
                            self.tx.lock().unwrap().resend_tcp_ack(
                                dst,
                                tcp.get_src(),
                                *self
                                    .tcp_acknowledgement_map
                                    .get(&(tcp.get_src(), dst))
                                    .unwrap_or(&0),
                            )?;
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

    fn update_tcp_acknowledgement(&mut self, indicator: &Indicator) {
        if let Some(tcp) = indicator.get_tcp() {
            let dst = SocketAddrV4::new(tcp.get_dst_ip_addr(), tcp.get_dst());
            let key = (tcp.get_src(), dst);

            let record_acknowledgement = *self.tcp_acknowledgement_map.get(&key).unwrap_or(&0);
            let sub_acknowledgement = tcp
                .get_acknowledgement()
                .checked_sub(record_acknowledgement)
                .unwrap_or_else(|| tcp.get_acknowledgement() - (u32::MAX - record_acknowledgement));

            if sub_acknowledgement == 0 {
                let entry = self.tcp_acknowledgement_count_map.entry(key).or_insert(0);

                *entry = entry.checked_add(1).unwrap_or(0);
            } else if sub_acknowledgement < u16::MAX as u32 {
                self.tcp_acknowledgement_map
                    .insert(key, tcp.get_acknowledgement());
            }
        }
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
            self.next_udp_port = self.next_udp_port.checked_add(1).unwrap_or(0);
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
    /// Creates a new `StreamWorker` and open it.
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
    /// Creates a new `DatagramWorker` and open it.
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
