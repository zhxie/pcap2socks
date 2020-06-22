use super::cacher::Cacher;
use super::packet::layer::arp::Arp;
use super::packet::layer::ethernet::Ethernet;
use super::packet::layer::ipv4::Ipv4;
use super::packet::layer::tcp::Tcp;
use super::packet::layer::udp::Udp;
use super::packet::layer::{Layer, LayerType, Layers};
use super::packet::Indicator;
use super::pcap::{self, HardwareAddr, Sender};
use log::{debug, trace};
use std::cmp::{max, min};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

/// Represents the minimum packet size.
/// Because all traffic is in Ethernet, and the 802.3 specifies the minimum is 64 Bytes.
/// Exclude the 4 bytes used in FCS, the minimum packet size in pcap2socks is 60 Bytes.
const MINIMUM_PACKET_SIZE: usize = 60;

/// Represents the channel downstream traffic to the source in pcap.
pub struct Downstreamer {
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

impl Downstreamer {
    /// Creates a new `Downstreamer`.
    pub fn new(
        tx: Sender,
        mtu: u16,
        local_hardware_addr: HardwareAddr,
        src_ip_addr: Ipv4Addr,
        local_ip_addr: Ipv4Addr,
    ) -> Downstreamer {
        Downstreamer {
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
        let tcp = Tcp::new_ack(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 0, 0, 0, 0, 0);
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
                dst.ip().clone(),
                self.src_ip_addr,
                dst.port(),
                src_port,
                sequence,
                *self.tcp_acknowledgement_map.get(&key).unwrap_or(&0),
                *self.tcp_window_map.get(&key).unwrap_or(&65535),
            );

            // Send
            self.send_ipv4_with_transport(Layers::Tcp(tcp), Some(payload))?;

            // Update TCP sequence
            let next_sequence = sequence
                .checked_add(length as u32)
                .unwrap_or_else(|| length as u32 - (u32::MAX - sequence));
            let record_sequence = *self.tcp_sequence_map.get(&key).unwrap_or(&0);
            let sub_sequence = next_sequence
                .checked_sub(record_sequence)
                .unwrap_or_else(|| next_sequence + (u32::MAX - record_sequence));
            if (sub_sequence as usize) < super::MAX_U32_WINDOW_SIZE {
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
            dst.ip().clone(),
            self.src_ip_addr,
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).unwrap_or(&0),
            *self.tcp_acknowledgement_map.get(&key).unwrap_or(&0),
            *self.tcp_window_map.get(&key).unwrap_or(&65535),
        );

        // Send
        self.send_ipv4_with_transport(Layers::Tcp(tcp), None)
    }

    /// Sends an TCP ACK/SYN packet.
    pub fn send_tcp_ack_syn(&mut self, dst: SocketAddrV4, src_port: u16) -> io::Result<()> {
        let key = (src_port, dst);

        // TCP
        let tcp = Tcp::new_ack_syn(
            dst.ip().clone(),
            self.src_ip_addr,
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).unwrap_or(&0),
            *self.tcp_acknowledgement_map.get(&key).unwrap_or(&0),
            *self.tcp_window_map.get(&key).unwrap_or(&65535),
        );

        // Send
        self.send_ipv4_with_transport(Layers::Tcp(tcp), None)?;

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
            dst.ip().clone(),
            self.src_ip_addr,
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).unwrap_or(&0),
            *self.tcp_acknowledgement_map.get(&key).unwrap_or(&0),
            *self.tcp_window_map.get(&key).unwrap_or(&65535),
        );

        // Send
        self.send_ipv4_with_transport(Layers::Tcp(tcp), None)
    }

    /// Sends an TCP ACK/FIN packet.
    pub fn send_tcp_ack_fin(&mut self, dst: SocketAddrV4, src_port: u16) -> io::Result<()> {
        let key = (src_port, dst);

        // TCP
        let tcp = Tcp::new_ack_fin(
            dst.ip().clone(),
            self.src_ip_addr,
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).unwrap_or(&0),
            *self.tcp_acknowledgement_map.get(&key).unwrap_or(&0),
            *self.tcp_window_map.get(&key).unwrap_or(&65535),
        );

        // Send
        self.send_ipv4_with_transport(Layers::Tcp(tcp), None)
    }

    /// Sends an TCP RST packet.
    pub fn send_tcp_rst(&mut self, dst: SocketAddrV4, src_port: u16) -> io::Result<()> {
        let key = (src_port, dst);

        // TCP
        let tcp = Tcp::new_rst(
            dst.ip().clone(),
            self.src_ip_addr,
            dst.port(),
            src_port,
            *self.tcp_sequence_map.get(&key).unwrap_or(&0),
            0,
            *self.tcp_window_map.get(&key).unwrap_or(&65535),
        );

        // Send
        self.send_ipv4_with_transport(Layers::Tcp(tcp), None)
    }

    /// Sends UDP packets.
    pub fn send_udp(&mut self, dst: SocketAddrV4, src_port: u16, payload: &[u8]) -> io::Result<()> {
        // Pseudo headers
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

    fn send_udp_raw(&mut self, dst: SocketAddrV4, src_port: u16, payload: &[u8]) -> io::Result<()> {
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
        // IPv4
        let ipv4 = Ipv4::new_more_fragment(
            *self.ipv4_identification_map.get(&dst_ip_addr).unwrap_or(&0),
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
        transport: Layers,
        payload: Option<&[u8]>,
    ) -> io::Result<()> {
        let dst_ip_addr = match transport {
            Layers::Tcp(ref tcp) => tcp.get_src_ip_addr(),
            Layers::Udp(ref udp) => udp.get_src_ip_addr(),
            _ => unreachable!(),
        };

        // IPv4
        let ipv4 = Ipv4::new(
            *self.ipv4_identification_map.get(&dst_ip_addr).unwrap_or(&0),
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
