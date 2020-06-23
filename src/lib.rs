use env_logger::fmt::{Color, Target};
use log::{debug, info, trace, warn, Level, LevelFilter};
use lru::LruCache;
use std::cmp::{max, min};
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub mod args;
pub mod cacher;
pub mod packet;
pub mod pcap;
pub mod socks;

use self::socks::{DatagramWorker, Forward, StreamWorker};
use args::Flags;
use cacher::{Cacher, RandomCacher};
use packet::layer::arp::Arp;
use packet::layer::ethernet::Ethernet;
use packet::layer::ipv4::Ipv4;
use packet::layer::tcp::Tcp;
use packet::layer::udp::Udp;
use packet::layer::{Layer, LayerType, LayerTypes, Layers};
use packet::{Defraggler, Indicator};
use pcap::Interface;
use pcap::{HardwareAddr, Receiver, Sender};

/// Sets the logger.
pub fn set_logger(flags: &Flags) {
    let level = match &flags.vverbose {
        true => LevelFilter::Trace,
        false => match flags.verbose {
            true => LevelFilter::Debug,
            false => LevelFilter::Info,
        },
    };
    env_logger::builder()
        .target(Target::Stdout)
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

/// Gets a list of available network interfaces which is possibly can be used for the current machine.
fn auto_interfaces() -> Vec<Interface> {
    // With specified IP address
    let mut inters: Vec<Interface> = interfaces()
        .into_iter()
        .filter(|inter| !inter.ip_addrs[0].is_unspecified())
        .collect();
    // Is up
    if inters.len() > 1 {
        inters = inters.into_iter().filter(|inter| inter.is_up).collect();
    }

    inters
}

/// Gets an available network interface match the name.
pub fn interface(name: Option<String>) -> Option<Interface> {
    let inters = match name {
        Some(name) => {
            let mut inters = interfaces();
            inters.retain(|current_inter| current_inter.name == name);
            inters
        }
        None => auto_interfaces(),
    };

    if inters.len() != 1 {
        None
    } else {
        Some(inters[0].clone())
    }
}

/// Prints the dialog with information how to set up the proxied device.
pub fn show_info(ip_addr: Ipv4Addr, gateway: Ipv4Addr, mtu: u16) {
    let ip_addr_octets = ip_addr.octets();
    let gateway_octets = gateway.octets();
    let mask = Ipv4Addr::new(
        !(ip_addr_octets[0] ^ gateway_octets[0]),
        !(ip_addr_octets[1] ^ gateway_octets[1]),
        !(ip_addr_octets[2] ^ gateway_octets[2]),
        0,
    );
    info!("Please set the network of your device which is going to be proxied with the following parameters:");
    info!("    ┌─{:─<10}─{:─>15}─┐", "", "");
    info!("    │ {:<10} {:>15} │", "IP Address", ip_addr);
    info!("    │ {:<10} {:>15} │", "Mask", mask);
    info!("    │ {:<10} {:>15} │", "Gateway", gateway);
    info!("    │─{:─<10}─{:─>15}─│", "", "");
    info!("    │ {:<10} {:>15} │", "MTU", mtu);
    info!("    └─{:─<10}─{:─>15}─┘", "", "");
}

/// Represents the wait time after a `TimedOut` `IoError`.
const TIMEDOUT_WAIT: u64 = 20;

/// Represents the max distance of `u32` values between packets in an `u32` window.
const MAX_U32_WINDOW_SIZE: usize = 256 * 1024;

/// Represents the minimum packet size.
/// Because all traffic is in Ethernet, and the 802.3 specifies the minimum is 64 Bytes.
/// Exclude the 4 bytes used in FCS, the minimum packet size in pcap2socks is 60 Bytes.
const MINIMUM_PACKET_SIZE: usize = 60;

/// Represents the channel forward traffic to the source in pcap.
pub struct Forwarder {
    tx: Sender,
    mtu: u16,
    src_hardware_addr: HardwareAddr,
    local_hardware_addr: HardwareAddr,
    src_ip_addr: Ipv4Addr,
    local_ip_addr: Ipv4Addr,
    ipv4_identification_map: HashMap<Ipv4Addr, u16>,
    tcp_send_window_map: HashMap<(u16, SocketAddrV4), u16>,
    tcp_sequence_map: HashMap<(u16, SocketAddrV4), u32>,
    tcp_acknowledgement_map: HashMap<(u16, SocketAddrV4), u32>,
    tcp_window_map: HashMap<(u16, SocketAddrV4), u16>,
    tcp_cache_map: HashMap<(u16, SocketAddrV4), Cacher>,
    tcp_cache2_map: HashMap<(u16, SocketAddrV4), Cacher>,
}

impl Forwarder {
    /// Creates a new `Forwarder`.
    pub fn new(
        tx: Sender,
        mtu: u16,
        local_hardware_addr: HardwareAddr,
        src_ip_addr: Ipv4Addr,
        local_ip_addr: Ipv4Addr,
    ) -> Forwarder {
        Forwarder {
            tx,
            mtu,
            src_hardware_addr: pcap::HARDWARE_ADDR_UNSPECIFIED,
            local_hardware_addr,
            src_ip_addr,
            local_ip_addr,
            ipv4_identification_map: HashMap::new(),
            tcp_send_window_map: HashMap::new(),
            tcp_sequence_map: HashMap::new(),
            tcp_acknowledgement_map: HashMap::new(),
            tcp_window_map: HashMap::new(),
            tcp_cache_map: HashMap::new(),
            tcp_cache2_map: HashMap::new(),
        }
    }

    /// Sets the source hardware address.
    pub fn set_src_hardware_addr(&mut self, hardware_addr: HardwareAddr) {
        self.src_hardware_addr = hardware_addr;
        trace!("set source hardware address to {}", hardware_addr);
    }

    /// Sets the local IP address.
    pub fn set_local_ip_addr(&mut self, ip_addr: Ipv4Addr) {
        self.local_ip_addr = ip_addr;
        trace!("set local IP address to {}", ip_addr);
    }

    fn increase_ipv4_identification(&mut self, ip_addr: Ipv4Addr) {
        let entry = self.ipv4_identification_map.entry(ip_addr).or_insert(0);
        *entry = entry.checked_add(1).unwrap_or(0);
        trace!("increase IPv4 identification of {} to {}", ip_addr, entry);
    }

    /// Sets the send window size of a TCP connection. This window
    pub fn set_tcp_send_window(&mut self, dst: SocketAddrV4, src_port: u16, window: u16) {
        self.tcp_send_window_map.insert((src_port, dst), window);
        trace!(
            "set TCP send window of {} -> {} to {}",
            src_port,
            dst,
            window,
        );
    }

    /// Sets the sequence of a TCP connection. In fact, this function should never be used.
    #[deprecated(note = "this function should never be used")]
    pub fn set_tcp_sequence(&mut self, dst: SocketAddrV4, src_port: u16, acknowledgement: u32) {
        self.tcp_sequence_map
            .insert((src_port, dst), acknowledgement);
        trace!(
            "set TCP sequence of {} -> {} to {}",
            dst,
            src_port,
            acknowledgement
        );
    }

    /// Sets the acknowledgement of a TCP connection.
    pub fn set_tcp_acknowledgement(&mut self, dst: SocketAddrV4, src_port: u16, sequence: u32) {
        self.tcp_acknowledgement_map
            .insert((src_port, dst), sequence);
        trace!(
            "set TCP acknowledgement of {} -> {} to {}",
            dst,
            src_port,
            sequence
        );
    }

    /// Adds acknowledgement to a TCP connection.
    pub fn add_tcp_acknowledgement(&mut self, dst: SocketAddrV4, src_port: u16, n: u32) {
        let entry = self
            .tcp_acknowledgement_map
            .entry((src_port, dst))
            .or_insert(0);
        *entry = entry
            .checked_add(n)
            .unwrap_or_else(|| n - (u32::MAX - *entry));
        trace!(
            "add TCP acknowledgement of {} -> {} to {}",
            dst,
            src_port,
            entry
        );
    }

    /// Sets the window size of a TCP connection.
    pub fn set_tcp_window(&mut self, dst: SocketAddrV4, src_port: u16, window: u16) {
        self.tcp_window_map.insert((src_port, dst), window);
        trace!("set TCP window of {} -> {} to {}", dst, src_port, window);
    }

    /// Invalidates TCP cache to the given sequence.
    pub fn invalidate_cache_to(&mut self, dst: SocketAddrV4, src_port: u16, sequence: u32) {
        if let Some(cache) = self.tcp_cache_map.get_mut(&(src_port, dst)) {
            cache.invalidate_to(sequence);
        }
        trace!(
            "invalidate cache {} -> {} to sequence {}",
            dst,
            src_port,
            sequence
        );
    }

    /// Removes all information related to a TCP connection.
    pub fn remove(&mut self, dst: SocketAddrV4, src_port: u16) {
        let key = (src_port, dst);

        self.tcp_sequence_map.remove(&key);
        self.tcp_acknowledgement_map.remove(&key);
        self.tcp_window_map.remove(&key);
        self.tcp_cache_map.remove(&key);
        trace!("remove {} -> {}", dst, src_port);
    }

    /// Get the size of the cache of a TCP connection.
    pub fn get_cache_size(&mut self, dst: SocketAddrV4, src_port: u16) -> usize {
        let key = (src_port, dst);

        let mut size = 0;
        if let Some(cache) = self.tcp_cache_map.get(&key) {
            size += cache.get_size();
        }
        if let Some(cache) = self.tcp_cache2_map.get(&key) {
            size += cache.get_size();
        }

        size
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

    /// Appends TCP ACK payload to cache.
    pub fn append_to_cache(
        &mut self,
        dst: SocketAddrV4,
        src_port: u16,
        payload: &[u8],
    ) -> io::Result<()> {
        let key = (src_port, dst);

        // TCP sequence
        let sequence = *self.tcp_sequence_map.get(&key).unwrap_or(&0);

        // Append to cache
        let cache = self
            .tcp_cache2_map
            .entry(key)
            .or_insert_with(|| Cacher::new_expandable(sequence));
        cache.append(payload)?;

        self.send_tcp_ack(dst, src_port)
    }

    /// Resends TCP ACK packets from first (sent) cache.
    pub fn resend_tcp_ack(&mut self, dst: SocketAddrV4, src_port: u16) -> io::Result<()> {
        let key = (src_port, dst);

        // Resend
        let payload;
        let sequence;
        match self.tcp_cache_map.get(&key) {
            Some(cache) => {
                match cache.get_all() {
                    Ok(buffer) => {
                        payload = buffer;
                    }
                    Err(e) => return Err(e),
                }
                sequence = cache.get_sequence();
            }
            None => return Ok(()),
        };

        if payload.len() > 0 {
            return self.send_tcp_ack_raw(dst, src_port, sequence, payload.as_slice());
        }

        Ok(())
    }

    /// Sends TCP ACK packets from second (unsent) cache.
    pub fn send_tcp_ack(&mut self, dst: SocketAddrV4, src_port: u16) -> io::Result<()> {
        let key = (src_port, dst);

        if let None = self.tcp_cache2_map.get(&key) {
            return Ok(());
        }

        let cache2 = self.tcp_cache2_map.get_mut(&key).unwrap();
        let sequence = cache2.get_sequence();
        let window = *self.tcp_send_window_map.get(&key).unwrap_or(&0);
        if window > 0 {
            let cache = self
                .tcp_cache_map
                .entry(key)
                .or_insert_with(|| Cacher::new(sequence));
            let sent_size = cache.get_size();
            let remain_size = (window as usize).checked_sub(sent_size).unwrap_or(0);
            let remain_size = min(remain_size, u16::MAX as usize) as u16;

            let size = min(remain_size as usize, cache2.get_size());
            if size > 0 {
                let payload = cache2.get(size).unwrap();

                let sequence_tail = sequence
                    .checked_add(size as u32)
                    .unwrap_or_else(|| size as u32 - (u32::MAX - sequence));
                cache2.invalidate_to(sequence_tail);

                // Append to cache
                let cache = self
                    .tcp_cache_map
                    .entry(key)
                    .or_insert_with(|| Cacher::new(sequence));
                cache.append(&payload)?;

                // Send
                self.send_tcp_ack_raw(dst, src_port, sequence, &payload)?;
            }
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

        // Pseudo headers
        let tcp = Tcp::new_ack(0, 0, 0, 0, 0);
        let ipv4 = Ipv4::new(
            0,
            tcp.get_type(),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
        )
        .unwrap();

        // Segmentation
        let header_size = ipv4.get_size() + tcp.get_size();
        let max_payload_size = self.mtu as usize - header_size;
        let mut i = 0;
        while max_payload_size * i < payload.len() {
            let length = min(max_payload_size, payload.len() - i * max_payload_size);
            let payload = &payload[i * max_payload_size..i * max_payload_size + length];
            let sequence = sequence
                .checked_add((i * max_payload_size) as u32)
                .unwrap_or_else(|| (i * max_payload_size) as u32 - (u32::MAX - sequence));

            // TCP
            let tcp = Tcp::new_ack(
                dst.port(),
                src_port,
                sequence,
                *self.tcp_acknowledgement_map.get(&key).unwrap_or(&0),
                *self.tcp_window_map.get(&key).unwrap_or(&65535),
            );

            // Send
            self.send_ipv4_with_transport(dst.ip().clone(), Layers::Tcp(tcp), Some(payload))?;

            // Update TCP sequence
            let next_sequence = sequence
                .checked_add(length as u32)
                .unwrap_or_else(|| length as u32 - (u32::MAX - sequence));
            let record_sequence = *self.tcp_sequence_map.get(&key).unwrap_or(&0);
            let sub_sequence = next_sequence
                .checked_sub(record_sequence)
                .unwrap_or_else(|| next_sequence + (u32::MAX - record_sequence));
            if (sub_sequence as usize) < MAX_U32_WINDOW_SIZE {
                self.tcp_sequence_map.insert(key, next_sequence);
            }

            i = i + 1;
        }

        Ok(())
    }

    /// Sends an TCP ACK packet without payload.
    pub fn send_tcp_ack_0(&mut self, dst: SocketAddrV4, src_port: u16) -> io::Result<()> {
        let key = (src_port, dst);

        // TCP
        let tcp = Tcp::new_ack(
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).unwrap_or(&0),
            *self.tcp_acknowledgement_map.get(&key).unwrap_or(&0),
            *self.tcp_window_map.get(&key).unwrap_or(&65535),
        );

        // Send
        self.send_ipv4_with_transport(dst.ip().clone(), Layers::Tcp(tcp), None)
    }

    /// Sends an TCP ACK/SYN packet.
    pub fn send_tcp_ack_syn(&mut self, dst: SocketAddrV4, src_port: u16) -> io::Result<()> {
        let key = (src_port, dst);

        // TCP
        let tcp = Tcp::new_ack_syn(
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).unwrap_or(&0),
            *self.tcp_acknowledgement_map.get(&key).unwrap_or(&0),
            *self.tcp_window_map.get(&key).unwrap_or(&65535),
        );

        // Send
        self.send_ipv4_with_transport(dst.ip().clone(), Layers::Tcp(tcp), None)?;

        // Update TCP sequence
        let tcp_sequence_entry = self.tcp_sequence_map.entry(key).or_insert(0);
        *tcp_sequence_entry = tcp_sequence_entry.checked_add(1).unwrap_or(0);

        Ok(())
    }

    /// Sends an TCP ACK/RST packet.
    pub fn send_tcp_ack_rst(&mut self, dst: SocketAddrV4, src_port: u16) -> io::Result<()> {
        let key = (src_port, dst);

        // TCP
        let tcp = Tcp::new_ack_rst(
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).unwrap_or(&0),
            *self.tcp_acknowledgement_map.get(&key).unwrap_or(&0),
            *self.tcp_window_map.get(&key).unwrap_or(&65535),
        );

        // Send
        self.send_ipv4_with_transport(dst.ip().clone(), Layers::Tcp(tcp), None)
    }

    /// Sends an TCP ACK/FIN packet.
    pub fn send_tcp_ack_fin(&mut self, dst: SocketAddrV4, src_port: u16) -> io::Result<()> {
        let key = (src_port, dst);

        // TCP
        let tcp = Tcp::new_ack_fin(
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).unwrap_or(&0),
            *self.tcp_acknowledgement_map.get(&key).unwrap_or(&0),
            *self.tcp_window_map.get(&key).unwrap_or(&65535),
        );

        // Send
        self.send_ipv4_with_transport(dst.ip().clone(), Layers::Tcp(tcp), None)
    }

    /// Sends an TCP RST packet.
    pub fn send_tcp_rst(&mut self, dst: SocketAddrV4, src_port: u16) -> io::Result<()> {
        let key = (src_port, dst);

        // TCP
        let tcp = Tcp::new_rst(
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).unwrap_or(&0),
            0,
            *self.tcp_window_map.get(&key).unwrap_or(&65535),
        );

        // Send
        self.send_ipv4_with_transport(dst.ip().clone(), Layers::Tcp(tcp), None)
    }

    /// Sends UDP packets.
    pub fn send_udp(&mut self, dst: SocketAddrV4, src_port: u16, payload: &[u8]) -> io::Result<()> {
        // Pseudo headers
        let udp = Udp::new(0, 0);
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
            let mut length = min(size - n, self.mtu as usize - ipv4_header_size);
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
            if n == 0 {
                if remain > 0 {
                    // UDP
                    let udp = Udp::new(dst.port(), src_port);

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

    fn send_udp_raw(&mut self, dst: SocketAddrV4, src_port: u16, payload: &[u8]) -> io::Result<()> {
        // UDP
        let udp = Udp::new(dst.port(), src_port);

        self.send_ipv4_with_transport(dst.ip().clone(), Layers::Udp(udp), Some(payload))
    }

    fn send_ipv4_more_fragment(
        &mut self,
        dst_ip_addr: Ipv4Addr,
        t: LayerType,
        fragment_offset: u16,
        mut transport: Option<Layers>,
        payload: &[u8],
    ) -> io::Result<()> {
        // IPv4
        let ipv4 = Ipv4::new_more_fragment(
            *self.ipv4_identification_map.get(&dst_ip_addr).unwrap_or(&0),
            t,
            fragment_offset,
            dst_ip_addr,
            self.src_ip_addr,
        )
        .unwrap();

        // Set IPv4 layer for checksum
        if let Some(ref mut transport) = transport {
            match transport {
                Layers::Tcp(ref mut tcp) => tcp.set_ipv4_layer(&ipv4),
                Layers::Udp(ref mut udp) => udp.set_ipv4_layer(&ipv4),
                _ => {}
            }
        };

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
        // IPv4
        let ipv4 = Ipv4::new_last_fragment(
            *self.ipv4_identification_map.get(&dst_ip_addr).unwrap_or(&0),
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
        dst_ip_addr: Ipv4Addr,
        mut transport: Layers,
        payload: Option<&[u8]>,
    ) -> io::Result<()> {
        // IPv4
        let ipv4 = Ipv4::new(
            *self.ipv4_identification_map.get(&dst_ip_addr).unwrap_or(&0),
            transport.get_type(),
            dst_ip_addr,
            self.src_ip_addr,
        )
        .unwrap();

        // Set IPv4 layer for checksum
        match transport {
            Layers::Tcp(ref mut tcp) => tcp.set_ipv4_layer(&ipv4),
            Layers::Udp(ref mut udp) => udp.set_ipv4_layer(&ipv4),
            _ => {}
        }

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
        let buffer_size = max(size, MINIMUM_PACKET_SIZE);
        let mut buffer = vec![0u8; buffer_size];
        indicator.serialize(&mut buffer[..size])?;

        // Send
        self.tx.send_to(&buffer, None).unwrap_or(Ok(()))?;
        debug!("send to pcap: {} ({} Bytes)", indicator.brief(), size);

        Ok(())
    }

    fn send_with_payload(&mut self, indicator: &Indicator, payload: &[u8]) -> io::Result<()> {
        // Serialize
        let size = indicator.get_size();
        let buffer_size = max(size + payload.len(), MINIMUM_PACKET_SIZE);
        let mut buffer = vec![0u8; buffer_size];
        indicator.serialize_with_payload(&mut buffer[..size + payload.len()], payload)?;

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

impl Forward for Forwarder {
    fn forward_tcp(&mut self, dst: SocketAddrV4, src_port: u16, payload: &[u8]) -> io::Result<()> {
        self.append_to_cache(dst, src_port, payload)
    }

    fn forward_udp(&mut self, dst: SocketAddrV4, src_port: u16, payload: &[u8]) -> io::Result<()> {
        self.send_udp(dst, src_port, payload)
    }
}

/// Represents the TCP ACK duplicates before trigger a fast retransmission.
const DUPLICATES_BEFORE_FAST_RETRANSMISSION: usize = 3;
/// Represents the cool down time between 2 retransmissions.
const RETRANSMISSION_COOL_DOWN: u128 = 1000;

/// Represents the max limit of UDP port for binding in local.
const PORT_COUNT: usize = 64;

/// Represents the channel redirect traffic to the proxy of SOCKS or loopback to the source in pcap.
pub struct Redirector {
    tx: Arc<Mutex<Forwarder>>,
    is_tx_src_hardware_addr_set: bool,
    src_ip_addr: Ipv4Addr,
    local_ip_addr: Option<Ipv4Addr>,
    remote: SocketAddrV4,
    streams: HashMap<(u16, SocketAddrV4), StreamWorker>,
    tcp_sequence_map: HashMap<(u16, SocketAddrV4), u32>,
    tcp_acknowledgement_map: HashMap<(u16, SocketAddrV4), u32>,
    tcp_duplicate_map: HashMap<(u16, SocketAddrV4), usize>,
    tcp_last_retransmission_map: HashMap<(u16, SocketAddrV4), Instant>,
    tcp_cache_map: HashMap<(u16, SocketAddrV4), RandomCacher>,
    datagrams: Vec<Option<DatagramWorker>>,
    udp_initial_port: u16,
    /// Represents the map mapping a source port to a local port (datagram).
    datagram_map: Vec<u16>,
    /// Represents the LRU mapping a local port to a source port.
    udp_lru: LruCache<u16, u16>,
    defrag: Defraggler,
}

impl Redirector {
    /// Creates a new `Redirector`.
    pub fn new(
        tx: Arc<Mutex<Forwarder>>,
        src_ip_addr: Ipv4Addr,
        local_ip_addr: Option<Ipv4Addr>,
        remote: SocketAddrV4,
        initial: u16,
    ) -> Redirector {
        let mut redirector = Redirector {
            tx,
            is_tx_src_hardware_addr_set: false,
            src_ip_addr,
            local_ip_addr,
            remote,
            streams: HashMap::new(),
            tcp_sequence_map: HashMap::new(),
            tcp_acknowledgement_map: HashMap::new(),
            tcp_duplicate_map: HashMap::new(),
            tcp_last_retransmission_map: HashMap::new(),
            tcp_cache_map: HashMap::new(),
            datagrams: (0..PORT_COUNT).map(|_| None).collect(),
            udp_initial_port: initial,
            datagram_map: vec![0u16; u16::MAX as usize],
            udp_lru: LruCache::new(PORT_COUNT),
            defrag: Defraggler::new(),
        };
        if let Some(local_ip_addr) = local_ip_addr {
            redirector
                .tx
                .lock()
                .unwrap()
                .set_local_ip_addr(local_ip_addr);
        }
        for i in 0..PORT_COUNT {
            redirector.udp_lru.put(i as u16, 0);
        }

        redirector
    }

    /// Opens an `Interface` for redirect.
    pub fn open(&mut self, rx: &mut Receiver) -> io::Result<()> {
        loop {
            match rx.next() {
                Ok(frame) => {
                    if let Some(ref indicator) = Indicator::from(frame) {
                        if let Some(t) = indicator.get_network_type() {
                            match t {
                                LayerTypes::Arp => {
                                    if let Err(ref e) = self.handle_arp(indicator) {
                                        warn!("handle {}: {}", indicator.brief(), e);
                                    }
                                }
                                LayerTypes::Ipv4 => {
                                    if let Err(ref e) = self.handle_ipv4(indicator, frame) {
                                        warn!("handle {}: {}", indicator.brief(), e);
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

    fn handle_arp(&mut self, indicator: &Indicator) -> io::Result<()> {
        if let Some(local_ip_addr) = self.local_ip_addr {
            if let Some(arp) = indicator.get_arp() {
                if arp.is_request_of(self.src_ip_addr, local_ip_addr) {
                    debug!(
                        "receive from pcap: {} ({} Bytes)",
                        indicator.brief(),
                        indicator.get_size()
                    );

                    // Set forwarder's hardware address
                    if !self.is_tx_src_hardware_addr_set {
                        self.tx
                            .lock()
                            .unwrap()
                            .set_src_hardware_addr(arp.get_src_hardware_addr());
                        self.is_tx_src_hardware_addr_set = true;
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
            let buffer_without_padding = &buffer
                [..indicator.get_ethernet().unwrap().get_size() + ipv4.get_total_length() as usize];
            if ipv4.get_src() == self.src_ip_addr {
                debug!(
                    "receive from pcap: {} ({} + {} Bytes)",
                    indicator.brief(),
                    indicator.get_size(),
                    buffer_without_padding.len() - indicator.get_size()
                );
                // Set forwarder's hardware address
                if !self.is_tx_src_hardware_addr_set {
                    self.tx
                        .lock()
                        .unwrap()
                        .set_src_hardware_addr(indicator.get_ethernet().unwrap().get_src());
                    self.is_tx_src_hardware_addr_set = true;
                }

                if ipv4.is_fragment() {
                    // Fragmentation
                    let frag = match self.defrag.add(indicator, buffer_without_padding) {
                        Some(frag) => frag,
                        None => return Ok(()),
                    };
                    let (indicator, buffer_without_padding) = frag.concatenate();

                    if let Some(t) = indicator.get_transport_type() {
                        match t {
                            LayerTypes::Tcp => {
                                self.handle_tcp(&indicator, buffer_without_padding)?
                            }
                            LayerTypes::Udp => {
                                self.handle_udp(&indicator, buffer_without_padding)?
                            }
                            _ => unreachable!(),
                        }
                    }
                } else {
                    if let Some(t) = indicator.get_transport_type() {
                        match t {
                            LayerTypes::Tcp => {
                                self.handle_tcp(indicator, buffer_without_padding)?
                            }
                            LayerTypes::Udp => {
                                self.handle_udp(indicator, buffer_without_padding)?
                            }
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
            if tcp.is_rst() {
                self.handle_tcp_rst(indicator);
            } else if tcp.is_ack() {
                return self.handle_tcp_ack(indicator, buffer);
            } else if tcp.is_syn() {
                // Pure TCP SYN
                return self.handle_tcp_syn(indicator);
            } else if tcp.is_fin() {
                // Pure TCP FIN
                return self.handle_tcp_fin(indicator);
            }
        }

        Ok(())
    }

    fn handle_tcp_ack(&mut self, indicator: &Indicator, buffer: &[u8]) -> io::Result<()> {
        if let Some(tcp) = indicator.get_tcp() {
            let dst = SocketAddrV4::new(tcp.get_dst_ip_addr(), tcp.get_dst());
            let key = (tcp.get_src(), dst);
            let is_exist = self.streams.get(&key).is_some();
            let is_alive = match self.streams.get(&key) {
                Some(ref stream) => !stream.is_closed(),
                None => false,
            };

            if is_exist {
                if is_alive {
                    // ACK
                    self.update_tcp_sequence(indicator);
                    self.update_tcp_acknowledgement(indicator);
                    {
                        let mut tx_locked = self.tx.lock().unwrap();
                        tx_locked.invalidate_cache_to(
                            dst,
                            tcp.get_src(),
                            tcp.get_acknowledgement(),
                        );
                        tx_locked.set_tcp_send_window(dst, tcp.get_src(), tcp.get_window());
                    }

                    let cache = self
                        .tcp_cache_map
                        .entry(key)
                        .or_insert_with(|| RandomCacher::new(tcp.get_sequence()));
                    let stream = self.streams.get_mut(&key).unwrap();
                    if buffer.len() > indicator.get_size() {
                        // ACK
                        // Append to cache
                        let payload =
                            cache.append(tcp.get_sequence(), &buffer[indicator.get_size()..])?;

                        match payload {
                            Some(payload) => {
                                // Send
                                match stream.send(payload.as_slice()) {
                                    Ok(_) => {
                                        // Update window size
                                        let mut tx_locked = self.tx.lock().unwrap();
                                        tx_locked.set_tcp_window(
                                            dst,
                                            tcp.get_src(),
                                            cache.get_remaining_size(),
                                        );

                                        // Update TCP acknowledgement
                                        tx_locked.add_tcp_acknowledgement(
                                            dst,
                                            tcp.get_src(),
                                            payload.len() as u32,
                                        );

                                        // Send ACK0
                                        // If there is a heavy traffic, the ACK reported may be inaccurate, which would results in retransmission
                                        tx_locked.send_tcp_ack_0(dst, tcp.get_src())?;
                                    }
                                    Err(e) => {
                                        // Clean up
                                        self.remove(indicator);

                                        // Send ACK/RST
                                        let mut tx_locked = self.tx.lock().unwrap();
                                        tx_locked.send_tcp_ack_rst(dst, tcp.get_src())?;

                                        // Clean up
                                        tx_locked.remove(dst, tcp.get_src());

                                        return Err(e);
                                    }
                                }
                            }
                            None => {
                                // Retransmission or unordered
                                // Update window size
                                let mut tx_locked = self.tx.lock().unwrap();
                                tx_locked.set_tcp_window(
                                    dst,
                                    tcp.get_src(),
                                    cache.get_remaining_size(),
                                );

                                // Send ACK0
                                tx_locked.send_tcp_ack_0(dst, tcp.get_src())?;
                            }
                        }
                    } else {
                        // ACK0
                        if *self.tcp_duplicate_map.get(&key).unwrap_or(&0)
                            >= DUPLICATES_BEFORE_FAST_RETRANSMISSION
                        {
                            if !tcp.is_zero_window() {
                                let is_cooled_down =
                                    match self.tcp_last_retransmission_map.get(&key) {
                                        Some(instant) => {
                                            instant.elapsed().as_millis() < RETRANSMISSION_COOL_DOWN
                                        }
                                        None => false,
                                    };
                                if !is_cooled_down {
                                    if tcp.is_fin() {
                                        // Because we cannot distinguish whether the server still have data to send,
                                        // we wait for some continuos ACKs before sending an ACK/FIN to close.
                                        // Expect all the data is handled by the server.
                                        let mut tx_locked = self.tx.lock().unwrap();
                                        // Check if all the data are sent
                                        if tx_locked.get_cache_size(dst, tcp.get_src()) == 0 {
                                            tx_locked.set_tcp_acknowledgement(
                                                dst,
                                                tcp.get_src(),
                                                tcp.get_sequence().checked_add(1).unwrap_or(0),
                                            );
                                            // Send ACK/FIN
                                            tx_locked.send_tcp_ack_fin(dst, tcp.get_src())?;
                                        }
                                    } else {
                                        // Fast retransmit
                                        // TODO: the procedure is in back N
                                        self.tx
                                            .lock()
                                            .unwrap()
                                            .resend_tcp_ack(dst, tcp.get_src())?;

                                        self.tcp_duplicate_map.insert(key, 0);
                                        self.tcp_last_retransmission_map
                                            .insert(key, Instant::now());
                                    }
                                }
                            }
                        }
                    }

                    // FIN
                    if tcp.is_fin() && cache.is_empty() {
                        stream.finish();
                    }

                    // Trigger sending remaining data
                    self.tx.lock().unwrap().send_tcp_ack(dst, tcp.get_src())?;
                } else {
                    // Expect in LAST_ACK state (or the stream met an error)
                    if tcp.is_fin() {
                        let mut tx_locked = self.tx.lock().unwrap();
                        tx_locked.set_tcp_acknowledgement(
                            dst,
                            tcp.get_src(),
                            tcp.get_sequence().checked_add(1).unwrap_or(0),
                        );
                        // Send ACK/FIN
                        tx_locked.send_tcp_ack_fin(dst, tcp.get_src())?;
                    } else {
                        self.remove(indicator);
                        self.tx.lock().unwrap().remove(dst, tcp.get_src());
                    }
                }
            } else {
                if tcp.is_fin() {
                    // Though a RST is enough, reply with respect
                    let mut tx_locked = self.tx.lock().unwrap();
                    #[allow(deprecated)]
                    tx_locked.set_tcp_sequence(dst, tcp.get_src(), tcp.get_acknowledgement());
                    tx_locked.set_tcp_acknowledgement(
                        dst,
                        tcp.get_src(),
                        tcp.get_sequence().checked_add(1).unwrap_or(0),
                    );
                    // Send ACK/FIN
                    tx_locked.send_tcp_ack_fin(dst, tcp.get_src())?;

                    // Clean up
                    tx_locked.remove(dst, tcp.get_src());
                } else {
                    let mut tx_locked = self.tx.lock().unwrap();
                    #[allow(deprecated)]
                    tx_locked.set_tcp_sequence(dst, tcp.get_src(), tcp.get_acknowledgement());
                    tx_locked.set_tcp_acknowledgement(
                        dst,
                        tcp.get_src(),
                        tcp.get_sequence().checked_add(1).unwrap_or(0),
                    );
                    // Send ACK/RST
                    tx_locked.send_tcp_ack_rst(dst, tcp.get_src())?;

                    // Clean up
                    tx_locked.remove(dst, tcp.get_src());
                }
            }
        }

        Ok(())
    }

    fn handle_tcp_syn(&mut self, indicator: &Indicator) -> io::Result<()> {
        if let Some(tcp) = indicator.get_tcp() {
            let dst = SocketAddrV4::new(tcp.get_dst_ip_addr(), tcp.get_dst());
            let key = (tcp.get_src(), dst);
            let is_exist = self.streams.get(&key).is_some();

            // Connect if not connected, drop if established
            if !is_exist {
                // Clean up
                self.remove(indicator);

                self.tcp_sequence_map.insert(key, tcp.get_sequence());

                // Latency test
                let timer = Instant::now();

                // Connect
                let stream = StreamWorker::connect(self.get_tx(), tcp.get_src(), dst, self.remote);

                let stream = match stream {
                    Ok(stream) => {
                        // Latency test result (not accurate)
                        debug!(
                            "Latency to {}: {} ms (RTT)",
                            dst,
                            timer.elapsed().as_millis()
                        );

                        let mut tx_locked = self.tx.lock().unwrap();
                        // Clean up
                        tx_locked.remove(dst, tcp.get_src());

                        tx_locked.set_tcp_acknowledgement(
                            dst,
                            tcp.get_src(),
                            tcp.get_sequence().checked_add(1).unwrap_or(0),
                        );
                        // Send ACK/SYN
                        tx_locked.send_tcp_ack_syn(dst, tcp.get_src())?;

                        stream
                    }
                    Err(e) => {
                        // Clean up
                        self.remove(indicator);

                        let mut tx_locked = self.tx.lock().unwrap();
                        tx_locked.set_tcp_acknowledgement(
                            dst,
                            tcp.get_src(),
                            tcp.get_sequence().checked_add(1).unwrap_or(0),
                        );
                        // Send ACK/RST
                        tx_locked.send_tcp_ack_rst(dst, tcp.get_src())?;

                        // Clean up
                        tx_locked.remove(dst, tcp.get_src());

                        return Err(e);
                    }
                };

                self.streams.insert(key, stream);
            }
        }

        Ok(())
    }

    fn handle_tcp_rst(&mut self, indicator: &Indicator) {
        if let Some(ref tcp) = indicator.get_tcp() {
            let dst = SocketAddrV4::new(tcp.get_dst_ip_addr(), tcp.get_dst());
            let key = (tcp.get_src(), dst);
            let is_exist = self.streams.get(&key).is_some();

            if is_exist {
                // Clean up
                self.remove(indicator);
                self.tx.lock().unwrap().remove(dst, tcp.get_src());
            }
        }
    }

    fn handle_tcp_fin(&mut self, indicator: &Indicator) -> io::Result<()> {
        if let Some(ref tcp) = indicator.get_tcp() {
            let dst = SocketAddrV4::new(tcp.get_dst_ip_addr(), tcp.get_dst());
            let key = (tcp.get_src(), dst);
            let is_exist = self.streams.get(&key).is_some();

            if is_exist {
                let remain_cache_size = self.tx.lock().unwrap().get_cache_size(dst, tcp.get_src());
                if remain_cache_size > 0 {
                    // Trigger sending remaining data
                    self.tx.lock().unwrap().send_tcp_ack(dst, tcp.get_src())?;
                } else {
                    let stream = self.streams.get_mut(&key).unwrap();
                    stream.close();

                    let mut tx_locked = self.tx.lock().unwrap();
                    tx_locked.set_tcp_acknowledgement(
                        dst,
                        tcp.get_src(),
                        tcp.get_sequence().checked_add(1).unwrap_or(0),
                    );
                    // Send ACK/FIN
                    tx_locked.send_tcp_ack_fin(dst, tcp.get_src())?;
                }
            } else {
                // Though a RST is enough, reply with respect
                let mut tx_locked = self.tx.lock().unwrap();
                #[allow(deprecated)]
                tx_locked.set_tcp_sequence(dst, tcp.get_src(), tcp.get_acknowledgement());
                tx_locked.set_tcp_acknowledgement(
                    dst,
                    tcp.get_src(),
                    tcp.get_sequence().checked_add(1).unwrap_or(0),
                );
                // Send ACK/FIN
                tx_locked.send_tcp_ack_fin(dst, tcp.get_src())?;

                // Clean up
                tx_locked.remove(dst, tcp.get_src());
            }
        }

        Ok(())
    }

    fn handle_udp(&mut self, indicator: &Indicator, buffer: &[u8]) -> io::Result<()> {
        if let Some(ref udp) = indicator.get_udp() {
            let port = self.get_local_udp_port(udp.get_src());
            let index = (port - self.udp_initial_port) as usize;

            // Bind
            let is_create;
            let is_set;
            match self.datagrams[index] {
                Some(ref worker) => {
                    is_create = worker.is_closed();
                    is_set = worker.get_src_port() != udp.get_src();
                }
                None => {
                    is_create = true;
                    is_set = false;
                }
            };
            if is_create {
                // Bind
                self.datagrams[index] = Some(DatagramWorker::bind(
                    self.get_tx(),
                    udp.get_src(),
                    port,
                    self.remote,
                )?);
            } else if is_set {
                // Replace
                self.datagrams[index]
                    .as_mut()
                    .unwrap()
                    .set_src_port(udp.get_src());
            }

            // Send
            self.datagrams[index].as_mut().unwrap().send_to(
                &buffer[indicator.get_size()..],
                SocketAddrV4::new(udp.get_dst_ip_addr(), udp.get_dst()),
            )?;
        }

        Ok(())
    }

    fn update_tcp_sequence(&mut self, indicator: &Indicator) {
        if let Some(tcp) = indicator.get_tcp() {
            let dst = SocketAddrV4::new(tcp.get_dst_ip_addr(), tcp.get_dst());
            let key = (tcp.get_src(), dst);

            let record_sequence = *self.tcp_sequence_map.get(&key).unwrap_or(&0);
            let sub_sequence = tcp
                .get_sequence()
                .checked_sub(record_sequence)
                .unwrap_or_else(|| tcp.get_sequence() + (u32::MAX - record_sequence));

            if sub_sequence == 0 {
                // Duplicate
                trace!(
                    "TCP retransmission of {} -> {} at {}",
                    tcp.get_src(),
                    dst,
                    tcp.get_sequence()
                );
            } else if sub_sequence < MAX_U32_WINDOW_SIZE as u32 {
                self.tcp_sequence_map.insert(key, tcp.get_sequence());

                trace!(
                    "set TCP sequence of {} -> {} to {}",
                    tcp.get_src(),
                    dst,
                    tcp.get_sequence()
                );
            } else {
                trace!(
                    "TCP out of order of {} -> {} at {}",
                    tcp.get_src(),
                    dst,
                    tcp.get_sequence()
                );
            }
        }
    }

    fn update_tcp_acknowledgement(&mut self, indicator: &Indicator) {
        if let Some(tcp) = indicator.get_tcp() {
            let dst = SocketAddrV4::new(tcp.get_dst_ip_addr(), tcp.get_dst());
            let key = (tcp.get_src(), dst);

            let record_acknowledgement = *self.tcp_acknowledgement_map.get(&key).unwrap_or(&0);
            let sub_acknowledgement = tcp
                .get_acknowledgement()
                .checked_sub(record_acknowledgement)
                .unwrap_or_else(|| tcp.get_acknowledgement() + (u32::MAX - record_acknowledgement));

            if sub_acknowledgement == 0 {
                // Duplicate
                let entry = self.tcp_duplicate_map.entry(key).or_insert(0);
                *entry = entry.checked_add(1).unwrap_or(usize::MAX);
                trace!(
                    "duplicate TCP acknowledgement of {} -> {} at {}",
                    tcp.get_src(),
                    dst,
                    tcp.get_acknowledgement()
                );
            } else if sub_acknowledgement < MAX_U32_WINDOW_SIZE as u32 {
                self.tcp_acknowledgement_map
                    .insert(key, tcp.get_acknowledgement());

                self.tcp_duplicate_map.insert(key, 0);
                trace!(
                    "set TCP acknowledgement of {} -> {} to {}",
                    tcp.get_src(),
                    dst,
                    tcp.get_acknowledgement()
                );
            }
        }
    }

    fn remove(&mut self, indicator: &Indicator) {
        if let Some(tcp) = indicator.get_tcp() {
            let dst = SocketAddrV4::new(tcp.get_dst_ip_addr(), tcp.get_dst());
            let key = (tcp.get_src(), dst);

            self.streams.remove(&key);
            self.tcp_sequence_map.remove(&key);
            self.tcp_acknowledgement_map.remove(&key);
            self.tcp_duplicate_map.remove(&key);
            self.tcp_last_retransmission_map.remove(&key);
            self.tcp_cache_map.remove(&key);
            trace!("remove {} -> {}", dst, tcp.get_dst());
        }
    }

    fn get_tx(&self) -> Arc<Mutex<Forwarder>> {
        Arc::clone(&self.tx)
    }

    fn get_local_udp_port(&mut self, src_port: u16) -> u16 {
        let local_port = self.datagram_map[src_port as usize];
        if local_port == 0 {
            let pair = self.udp_lru.pop_lru().unwrap();
            let index = pair.0;
            let prev_src_port = pair.1;
            let local_port = self.udp_initial_port + index;

            // Update LRU
            self.udp_lru.put(index, src_port);

            if prev_src_port != 0 {
                // Reuse
                self.datagram_map[prev_src_port as usize] = 0;
                trace!(
                    "reuse UDP port {} = {} to {} = {}",
                    prev_src_port,
                    local_port,
                    src_port,
                    local_port
                );
            }
            self.datagram_map[src_port as usize] = local_port;

            local_port
        } else {
            // Update LRU
            self.udp_lru.get(&local_port);

            local_port
        }
    }
}
