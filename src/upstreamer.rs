use log::{debug, trace, warn};
use lru::LruCache;
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddrV4},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use super::{
    cacher::RandomCacher,
    datagram_worker::DatagramWorker,
    downstreamer::Downstreamer,
    packet::{
        layer::{Layer, LayerTypes},
        Defraggler, Indicator,
    },
    pcap::Receiver,
    stream_worker::StreamWorker,
};

/// Represents the TCP ACK duplicates before trigger a fast retransmission.
const DUPLICATES_BEFORE_FAST_RETRANSMISSION: usize = 3;
/// Represents the cool down time between 2 retransmissions.
const RETRANSMISSION_COOL_DOWN: u128 = 1000;

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
    tcp_sequence_map: HashMap<(u16, SocketAddrV4), u32>,
    tcp_acknowledgement_map: HashMap<(u16, SocketAddrV4), u32>,
    tcp_duplicate_map: HashMap<(u16, SocketAddrV4), usize>,
    tcp_last_retransmission_map: HashMap<(u16, SocketAddrV4), Instant>,
    tcp_cache_map: HashMap<(u16, SocketAddrV4), RandomCacher>,
    datagrams: Vec<Option<DatagramWorker>>,
    /// Represents the map mapping a source port to a local port (datagram)
    datagram_map: Vec<u16>,
    /// Represents the LRU mapping a local port to a source port
    udp_lru: LruCache<u16, u16>,
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
        let mut upstreamer = Upstreamer {
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
            datagram_map: vec![0u16; u16::MAX as usize],
            udp_lru: LruCache::new(PORT_COUNT),
            defrag: Defraggler::new(),
        };
        if let Some(local_ip_addr) = local_ip_addr {
            upstreamer
                .tx
                .lock()
                .unwrap()
                .set_local_ip_addr(local_ip_addr);
        }
        for i in 0..PORT_COUNT {
            upstreamer.udp_lru.put(i as u16, 0);
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
                        thread::sleep(Duration::from_millis(super::TIMEDOUT_WAIT));
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

                    // Set downstreamer's hardware address
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
                // Set downstreamer's hardware address
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

                    if buffer.len() > indicator.get_size() {
                        // ACK
                        // Append to cache
                        let cache = self
                            .tcp_cache_map
                            .entry(key)
                            .or_insert_with(|| RandomCacher::new(tcp.get_sequence()));
                        let payload =
                            cache.append(tcp.get_sequence(), &buffer[indicator.get_size()..])?;

                        match payload {
                            Some(payload) => {
                                // Send
                                match self.streams.get_mut(&key).unwrap().send(payload.as_slice()) {
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
                        // ACK0 or FIN
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
                                        // Expect all the data is handled
                                        let mut tx_locked = self.tx.lock().unwrap();
                                        tx_locked.set_tcp_acknowledgement(
                                            dst,
                                            tcp.get_src(),
                                            tcp.get_sequence().checked_add(1).unwrap_or(0),
                                        );
                                        // Send ACK/FIN
                                        tx_locked.send_tcp_ack_fin(dst, tcp.get_src())?;
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
            let index = (port - INITIAL_PORT) as usize;

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
            } else if sub_sequence < super::MAX_U32_WINDOW_SIZE as u32 {
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
            } else if sub_acknowledgement < super::MAX_U32_WINDOW_SIZE as u32 {
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

    fn get_tx(&self) -> Arc<Mutex<Downstreamer>> {
        Arc::clone(&self.tx)
    }

    fn get_local_udp_port(&mut self, src_port: u16) -> u16 {
        let local_port = self.datagram_map[src_port as usize];
        if local_port == 0 {
            let pair = self.udp_lru.pop_lru().unwrap();
            let index = pair.0;
            let prev_src_port = pair.1;
            let local_port = INITIAL_PORT + index;

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
