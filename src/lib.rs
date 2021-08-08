#![recursion_limit = "256"]

//! Redirect traffic to a SOCKS proxy with pcap.

use ipnetwork::Ipv4Network;
use log::{debug, info, trace, warn};
use lru::LruCache;
use rand::{self, Rng};
use stat::Traffic;
use std::cmp::{max, min};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::io;

pub mod packet;
pub mod pcap;
pub mod proxy;
pub mod stat;
pub mod tcp;

pub use self::proxy::ProxyConfig;
use self::proxy::{DatagramWorker, ForwardDatagram, ForwardStream, StreamWorker};
use packet::layer::arp::Arp;
use packet::layer::ethernet::Ethernet;
use packet::layer::icmpv4::Icmpv4;
use packet::layer::ipv4::Ipv4;
use packet::layer::tcp::Tcp;
use packet::layer::udp::Udp;
use packet::layer::{Layer, LayerKinds, Layers};
use packet::{Defraggler, Indicator};
use pcap::Interface;
use pcap::{HardwareAddr, Receiver, Sender};
use tcp::{TcpRxState, TcpTxState};

/// Gets a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<Interface> {
    pcap::interfaces()
        .into_iter()
        .filter(|inter| inter.is_up() && !inter.is_loopback())
        .collect()
}

/// Gets an available network interface.
pub fn interface(name: Option<String>) -> Option<Interface> {
    let mut inters = match name {
        Some(ref name) => {
            let mut inters = interfaces();
            inters.retain(|ref inter| inter.name() == name);

            inters
        }
        None => interfaces(),
    };

    if inters.len() != 1 {
        None
    } else {
        Some(inters.pop().unwrap())
    }
}

/// Represents the max distance of `u32` values between packets in an `u32` window.
const MAX_U32_WINDOW_SIZE: usize = 16 * 1024 * 1024;

/// Represents the wait time after a `TimedOut` `IoError`.
const TIMEDOUT_WAIT: u64 = 20;

/// Represents if the receive-side silly window syndrome avoidance, Clark's algorithm, is enabled.
const ENABLE_RECV_SWS_AVOID: bool = true;
/// Represents if the send-side silly window syndrome avoidance, Clark's algorithm, is enabled.
const ENABLE_SEND_SWS_AVOID: bool = true;

/// Represents if the delayed ACK is enabled.
const ENABLE_DELAYED_ACK: bool = true;

/// Represents if the TCP MSS option is enabled.
const ENABLE_MSS: bool = true;

/// Represents the minimum frame size.
/// Because all traffic is in Ethernet, and the 802.3 specifies the minimum is 64 Bytes.
/// Exclude the 4 bytes used in FCS, the minimum frame size in pcap2socks is 60 Bytes.
const MINIMUM_FRAME_SIZE: usize = 60;

/// Represents a channel forward traffic to the source in pcap.
pub struct Forwarder {
    tx: Sender,
    src_mtu_map: HashMap<Ipv4Addr, usize>,
    local_mtu: usize,
    src_hardware_addr_map: HashMap<Ipv4Addr, HardwareAddr>,
    local_hardware_addr: HardwareAddr,
    local_ip_addr: Ipv4Addr,
    ipv4_identification_map: HashMap<(Ipv4Addr, Ipv4Addr), u16>,
    states: HashMap<(SocketAddrV4, SocketAddrV4), TcpTxState>,
    traffic_size: Option<Arc<AtomicUsize>>,
    traffic_count: Option<Arc<AtomicUsize>>,
}

impl Forwarder {
    /// Creates a new `Forwarder`.
    pub fn new(
        tx: Sender,
        mtu: usize,
        local_hardware_addr: HardwareAddr,
        local_ip_addr: Ipv4Addr,
    ) -> Forwarder {
        Forwarder::new_monitored(tx, mtu, local_hardware_addr, local_ip_addr, None)
    }

    /// Creates a new `Forwarder` which is monitored.
    pub fn new_monitored(
        tx: Sender,
        mtu: usize,
        local_hardware_addr: HardwareAddr,
        local_ip_addr: Ipv4Addr,
        traffic: Option<Traffic>,
    ) -> Forwarder {
        let size = match &traffic {
            Some(traffic) => Some(traffic.size()),
            None => None,
        };
        let count = match &traffic {
            Some(traffic) => Some(traffic.count()),
            None => None,
        };
        Forwarder {
            tx,
            src_mtu_map: HashMap::new(),
            local_mtu: mtu,
            src_hardware_addr_map: HashMap::new(),
            local_hardware_addr,
            local_ip_addr,
            ipv4_identification_map: HashMap::new(),
            states: HashMap::new(),
            traffic_size: size,
            traffic_count: count,
        }
    }

    /// Sets the source MTU.
    pub fn set_src_mtu(&mut self, src_ip_addr: Ipv4Addr, mtu: usize) -> bool {
        let prev_mtu = *self
            .src_mtu_map
            .get(&src_ip_addr)
            .unwrap_or(&self.local_mtu);

        self.src_mtu_map
            .insert(src_ip_addr, min(self.local_mtu, mtu));
        trace!("set source MTU of {} to {}", src_ip_addr, mtu);

        return *self
            .src_mtu_map
            .get(&src_ip_addr)
            .unwrap_or(&self.local_mtu)
            != prev_mtu;
    }

    /// Sets the source hardware address.
    pub fn set_src_hardware_addr(&mut self, src_ip_addr: Ipv4Addr, hardware_addr: HardwareAddr) {
        self.src_hardware_addr_map
            .insert(src_ip_addr, hardware_addr);
        trace!(
            "set source hardware address of {} to {}",
            src_ip_addr,
            hardware_addr
        );
    }

    /// Sets the local IP address.
    pub fn set_local_ip_addr(&mut self, ip_addr: Ipv4Addr) {
        self.local_ip_addr = ip_addr;
        trace!("set local IP address to {}", ip_addr);
    }

    fn increase_ipv4_identification(&mut self, dst_ip_addr: Ipv4Addr, src_ip_addr: Ipv4Addr) {
        let entry = self
            .ipv4_identification_map
            .entry((src_ip_addr, dst_ip_addr))
            .or_insert(0);
        *entry = entry.checked_add(1).unwrap_or(0);
        trace!(
            "increase IPv4 identification of {} -> {} to {}",
            dst_ip_addr,
            src_ip_addr,
            entry
        );
    }

    /// Sets the state of a TCP connection.
    pub fn set_state(&mut self, dst: SocketAddrV4, src: SocketAddrV4, state: TcpTxState) {
        let key = (src, dst);

        self.states.insert(key, state);
    }

    /// Removes all information related to a TCP connection.
    pub fn clean_up(&mut self, dst: SocketAddrV4, src: SocketAddrV4) {
        let key = (src, dst);

        self.states.remove(&key);
    }

    /// Returns the source MTU.
    pub fn get_src_mtu(&self, src_ip_addr: Ipv4Addr) -> usize {
        *self
            .src_mtu_map
            .get(&src_ip_addr)
            .unwrap_or(&self.local_mtu)
    }

    /// Returns the state of a TCP connection.
    pub fn get_state(&self, dst: SocketAddrV4, src: SocketAddrV4) -> Option<&TcpTxState> {
        let key = (src, dst);

        self.states.get(&key)
    }

    /// Returns the mutable state of a TCP connection.
    pub fn get_state_mut(
        &mut self,
        dst: SocketAddrV4,
        src: SocketAddrV4,
    ) -> Option<&mut TcpTxState> {
        let key = (src, dst);

        self.states.get_mut(&key)
    }

    fn get_tcp_window(&self, dst: SocketAddrV4, src: SocketAddrV4) -> u16 {
        let key = (src, dst);

        let state = self.states.get(&key).unwrap();

        // Avoid SWS
        if ENABLE_RECV_SWS_AVOID {
            let thresh = min(state.half_max_window() as usize, self.local_mtu);

            if (state.window() as usize) < thresh {
                0
            } else {
                state.window()
            }
        } else {
            state.window()
        }
    }

    /// Returns the size of the cache and the queue of a TCP connection.
    pub fn get_cache_size(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> usize {
        let key = (src, dst);

        let state = self.states.get(&key).unwrap();

        state.cache().len() + state.queue().len()
    }

    /// Sends an ARP reply packet.
    pub fn send_arp_reply(&mut self, src_ip_addr: Ipv4Addr) -> io::Result<()> {
        // ARP
        let arp = Arp::new_reply(
            self.local_hardware_addr,
            self.local_ip_addr,
            *self
                .src_hardware_addr_map
                .get(&src_ip_addr)
                .unwrap_or(&pcap::HARDWARE_ADDR_UNSPECIFIED),
            src_ip_addr,
        );

        // Send
        self.send_ethernet(arp.dst_hardware_addr(), Layers::Arp(arp), None, None)
    }

    /// Sends an gratuitous ARP packet.
    pub fn send_gratuitous_arp(&mut self) -> io::Result<()> {
        // ARP
        let arp = Arp::gratuitous_arp(self.local_hardware_addr, self.local_ip_addr);

        // Send
        self.send_ethernet(pcap::HARDWARE_ADDR_BROADCAST, Layers::Arp(arp), None, None)
    }

    /// Sends an ICMPv4 echo reply packet.
    pub fn send_icmpv4_echo_reply(
        &mut self,
        dst_ip_addr: Ipv4Addr,
        src_ip_addr: Ipv4Addr,
        identifier: u16,
        sequence_number: u16,
    ) -> io::Result<()> {
        // ICMPv4
        let icmpv4 = Icmpv4::new_echo_reply(identifier, sequence_number);

        self.send_ipv4(dst_ip_addr, src_ip_addr, Layers::Icmpv4(icmpv4), None)
    }

    /// Sends an ICMPv4 destination host unreachable packet.
    pub fn send_icmpv4_destination_host_unreachable(
        &mut self,
        dst_ip_addr: Ipv4Addr,
        src_ip_addr: Ipv4Addr,
        payload: &[u8],
    ) -> io::Result<()> {
        // ICMPv4
        let icmpv4 = Icmpv4::new_destination_host_unreachable(payload);

        self.send_ipv4(dst_ip_addr, src_ip_addr, Layers::Icmpv4(icmpv4), None)
    }

    /// Sends an ICMPv4 destination port unreachable packet.
    pub fn send_icmpv4_destination_port_unreachable(
        &mut self,
        dst_ip_addr: Ipv4Addr,
        src_ip_addr: Ipv4Addr,
        payload: &[u8],
    ) -> io::Result<()> {
        // ICMPv4
        let icmpv4 = Icmpv4::new_destination_port_unreachable(payload);

        self.send_ipv4(dst_ip_addr, src_ip_addr, Layers::Icmpv4(icmpv4), None)
    }

    /// Appends TCP payload to the queue.
    pub fn queue_tcp(
        &mut self,
        dst: SocketAddrV4,
        src: SocketAddrV4,
        payload: &[u8],
    ) -> io::Result<()> {
        // Append to queue
        let state = self
            .get_state_mut(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        state.append_queue(payload);

        self.send_tcp(dst, src)
    }

    /// Retransmits TCP packets from the cache. This method is used for fast retransmission.
    pub fn retransmit_tcp(
        &mut self,
        dst: SocketAddrV4,
        src: SocketAddrV4,
        sacks: Option<Vec<(u32, u32)>>,
    ) -> io::Result<()> {
        let state = self
            .get_state_mut(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        let sequence = state.cache().sequence();
        let recv_next = state.cache().recv_next();

        // Congestion control
        if let Some(cc) = &mut state.cc_mut() {
            cc.fast_retransmission();
        }

        // Find all disjointed ranges
        let mut ranges = Vec::new();
        ranges.push((sequence, recv_next));
        if let Some(sacks) = sacks {
            for sack in sacks {
                let mut temp_ranges = Vec::new();

                for range in ranges {
                    for temp_range in disjoint_u32_range(range, sack) {
                        temp_ranges.push(temp_range);
                    }
                }

                ranges = temp_ranges;
            }
        }
        let ranges = ranges;

        // Retransmit
        for range in &ranges {
            let size = range
                .1
                .checked_sub(range.0)
                .unwrap_or_else(|| range.1 + (u32::MAX - range.0)) as usize;
            let state = self
                .get_state(dst, src)
                .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
            let payload = state.cache().get(range.0, size)?;
            if payload.len() > 0 {
                if range.1 == recv_next && state.cache_fin().is_some() {
                    // ACK/FIN
                    trace!(
                        "retransmit TCP ACK/FIN ({} Bytes) {} -> {} from {}",
                        payload.len(),
                        dst,
                        src,
                        sequence
                    );

                    // Send
                    self.send_tcp_ack(dst, src, range.0, payload.as_slice(), true)?;
                } else {
                    // ACK
                    trace!(
                        "retransmit TCP ACK ({} Bytes) {} -> {} from {}",
                        payload.len(),
                        dst,
                        src,
                        sequence
                    );

                    // Send
                    self.send_tcp_ack(dst, src, range.0, payload.as_slice(), false)?;
                }
            }
        }

        // Pure FIN
        let state = self
            .get_state(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        if ranges.len() == 0 && state.cache_fin().is_some() {
            // FIN
            trace!("retransmit TCP FIN {} -> {}", dst, src);

            // Send
            self.send_tcp_fin(dst, src)?;
        }

        Ok(())
    }

    /// Retransmits timed out TCP packets from the cache. This method is used for transmitting
    /// timed out data.
    pub fn retransmit_tcp_timedout(
        &mut self,
        dst: SocketAddrV4,
        src: SocketAddrV4,
    ) -> io::Result<()> {
        let state = self
            .get_state_mut(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        let next_rto = state.next_rto();
        let payload = state.cache_mut().get_timed_out_and_update(next_rto);
        let sequence = state.cache().sequence();
        let size = state.cache().len();

        if size > 0 {
            if payload.len() > 0 {
                // Double RTO
                state.double_rto();

                // Congestion control
                if let Some(cc) = &mut state.cc_mut() {
                    cc.timedout();
                }

                // If all the cache is get, the FIN should also be sent
                if size == payload.len() && state.cache_fin().is_some() {
                    // ACK/FIN
                    state.update_fin_timer();
                    trace!(
                        "retransmit TCP ACK/FIN ({} Bytes) and FIN {} -> {} from {} due to timeout",
                        payload.len(),
                        dst,
                        src,
                        sequence
                    );

                    // Send
                    self.send_tcp_ack(dst, src, sequence, payload.as_slice(), true)?;
                } else {
                    // ACK
                    trace!(
                        "retransmit TCP ACK ({} Bytes) {} -> {} from {} due to timeout",
                        payload.len(),
                        dst,
                        src,
                        sequence
                    );

                    // Send
                    self.send_tcp_ack(dst, src, sequence, payload.as_slice(), false)?;
                }
            }
        } else {
            // FIN
            if let Some(timer) = state.cache_fin() {
                if timer.is_timedout() {
                    // Double RTO
                    state.double_rto();
                    state.update_fin_timer();
                    trace!("retransmit TCP FIN {} -> {} due to timeout", dst, src);

                    // Send
                    self.send_tcp_fin(dst, src)?;
                }
            }
        }

        // Delayed ACK0
        let state = self
            .get_state(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        if state.delayed_ack() {
            self.send_tcp_ack_0(dst, src)?;
        }

        Ok(())
    }

    /// Sends TCP packets from the queue.
    pub fn send_tcp(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<()> {
        // Retransmit unhandled SYN
        let state = self
            .get_state(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        if state.cache_syn().is_some() {
            return self.send_tcp_ack_syn(dst, src);
        }

        if state.src_window() > 0 {
            // TCP sequence
            let sent_size = state.cache().len();
            let remain_size = state.send_window().checked_sub(sent_size).unwrap_or(0);
            let remain_size = min(remain_size, u16::MAX as usize) as u16;

            let mut size = min(remain_size as usize, state.queue().len());
            // Avoid SWS
            if ENABLE_SEND_SWS_AVOID {
                let mtu = *self.src_mtu_map.get(src.ip()).unwrap_or(&self.local_mtu);
                let mss = mtu - (Ipv4::minimum_len() + Tcp::minimum_len());

                if size < mss && !state.cache().is_empty() {
                    size = 0;
                }
            }
            let size = size;
            if size > 0 {
                let state = self
                    .get_state_mut(dst, src)
                    .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
                let payload = state.append_cache(size)?;

                // If the queue is empty and a FIN is in the queue, pop it
                if state.queue().is_empty() && state.queue_fin() {
                    // ACK/FIN
                    state.append_cache_fin();

                    // Send
                    let state = self
                        .get_state(dst, src)
                        .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
                    let sequence = state.sequence();
                    self.send_tcp_ack(dst, src, sequence, &payload, true)?;
                } else {
                    // ACK
                    let state = self
                        .get_state(dst, src)
                        .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
                    let sequence = state.sequence();
                    self.send_tcp_ack(dst, src, sequence, &payload, false)?;
                }
            }
        }

        // If the queue is empty and a FIN is in the queue, pop it
        // FIN
        let state = self
            .get_state_mut(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        if state.queue_fin() {
            if state.cache().is_empty() {
                // FIN
                state.append_cache_fin();

                // Send
                self.send_tcp_fin(dst, src)?;
            }
        }

        Ok(())
    }

    fn send_tcp_ack(
        &mut self,
        dst: SocketAddrV4,
        src: SocketAddrV4,
        sequence: u32,
        payload: &[u8],
        is_fin: bool,
    ) -> io::Result<()> {
        // Segmentation
        let mss = *self.src_mtu_map.get(src.ip()).unwrap_or(&self.local_mtu)
            - (Ipv4::minimum_len() + Tcp::minimum_len());
        let mut i = 0;
        while mss * i < payload.len() {
            let state = self
                .get_state(dst, src)
                .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
            let size = min(mss, payload.len() - i * mss);
            let payload = &payload[i * mss..i * mss + size];
            let sequence = sequence
                .checked_add((i * mss) as u32)
                .unwrap_or_else(|| (i * mss) as u32 - (u32::MAX - sequence));
            let mut recv_next = sequence
                .checked_add(size as u32)
                .unwrap_or_else(|| size as u32 - (u32::MAX - sequence));

            // TCP
            let tcp;
            if is_fin && mss * (i + 1) >= payload.len() {
                // ACK/FIN
                tcp = Tcp::new_ack_fin(
                    dst.port(),
                    src.port(),
                    sequence,
                    state.acknowledgement(),
                    self.get_tcp_window(dst, src),
                    None,
                );
                recv_next = recv_next.checked_add(1).unwrap_or(0);
            } else {
                // ACK
                tcp = Tcp::new_ack(
                    dst.port(),
                    src.port(),
                    sequence,
                    state.acknowledgement(),
                    self.get_tcp_window(dst, src),
                    None,
                    None,
                );
            }

            // Send
            self.send_ipv4(
                dst.ip().clone(),
                src.ip().clone(),
                Layers::Tcp(tcp),
                Some(payload),
            )?;

            // Clear TCP delayed ACK
            let state = self
                .get_state_mut(dst, src)
                .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
            state.clear_delayed_ack();

            // Update TCP sequence
            let record_sequence = state.sequence();
            let sub_sequence = recv_next
                .checked_sub(record_sequence)
                .unwrap_or_else(|| recv_next + (u32::MAX - record_sequence));
            if (sub_sequence as usize) <= MAX_U32_WINDOW_SIZE {
                state.add_sequence(sub_sequence);
            }

            i = i + 1;
        }

        Ok(())
    }

    /// Sends an TCP delayed ACK packet without payload.
    pub fn send_tcp_delay_ack_0(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<()> {
        if ENABLE_DELAYED_ACK {
            let state = self
                .get_state_mut(dst, src)
                .ok_or(io::Error::from(io::ErrorKind::NotFound))?;

            if state.delayed_ack() {
                self.send_tcp_ack_0(dst, src)?;
            } else {
                state.set_delayed_ack();
            }
        } else {
            self.send_tcp_ack_0(dst, src)?;
        }

        Ok(())
    }

    /// Sends an TCP ACK packet without payload.
    pub fn send_tcp_ack_0(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<()> {
        // TCP
        let state = self
            .get_state(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        let tcp = Tcp::new_ack(
            dst.port(),
            src.port(),
            state.sequence(),
            state.acknowledgement(),
            self.get_tcp_window(dst, src),
            state.sacks().clone(),
            None,
        );

        // Send
        self.send_ipv4(dst.ip().clone(), src.ip().clone(), Layers::Tcp(tcp), None)?;

        // Clear TCP delayed ACK
        let state = self
            .get_state_mut(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        state.clear_delayed_ack();

        Ok(())
    }

    fn send_tcp_ack_syn(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<()> {
        let mss = match ENABLE_MSS {
            true => {
                let mss = self.local_mtu - (Ipv4::minimum_len() + Tcp::minimum_len());
                let mss = if mss > u16::MAX as usize {
                    u16::MAX
                } else {
                    mss as u16
                };

                Some(mss)
            }
            false => None,
        };

        // TCP
        let state = self
            .get_state(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        let tcp = Tcp::new_ack_syn(
            dst.port(),
            src.port(),
            state.sequence(),
            state.acknowledgement(),
            self.get_tcp_window(dst, src),
            mss,
            state.src_wscale(),
            state.sack_perm(),
            None,
        );

        // Send
        self.send_ipv4(dst.ip().clone(), src.ip().clone(), Layers::Tcp(tcp), None)?;

        // Clear TCP delayed ACK
        let state = self
            .get_state_mut(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        state.clear_delayed_ack();

        Ok(())
    }

    /// Sends an TCP ACK/RST packet.
    pub fn send_tcp_ack_rst(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<()> {
        // TCP
        let state = self
            .get_state(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        let tcp = Tcp::new_ack_rst(
            dst.port(),
            src.port(),
            state.sequence(),
            state.acknowledgement(),
            self.get_tcp_window(dst, src),
            None,
        );

        // Send
        self.send_ipv4(dst.ip().clone(), src.ip().clone(), Layers::Tcp(tcp), None)?;

        // Clear TCP delayed ACK
        let state = self
            .get_state_mut(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        state.clear_delayed_ack();

        Ok(())
    }

    /// Sends an TCP ACK/RST packet of an untracked connection.
    pub fn send_tcp_ack_rst_untracked(
        &mut self,
        dst: SocketAddrV4,
        src: SocketAddrV4,
        sequence: u32,
    ) -> io::Result<()> {
        // TCP
        let tcp = Tcp::new_ack_rst(dst.port(), src.port(), sequence, 0, 0, None);

        // Send
        self.send_ipv4(dst.ip().clone(), src.ip().clone(), Layers::Tcp(tcp), None)
    }

    /// Sends an TCP RST packet.
    pub fn send_tcp_rst(
        &mut self,
        dst: SocketAddrV4,
        src: SocketAddrV4,
        sequence: u32,
    ) -> io::Result<()> {
        // TCP
        let tcp = Tcp::new_rst(dst.port(), src.port(), sequence, 0, 0, None);

        // Send
        self.send_ipv4(dst.ip().clone(), src.ip().clone(), Layers::Tcp(tcp), None)
    }

    fn send_tcp_fin(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<()> {
        // TCP
        let state = self
            .get_state(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        let tcp = Tcp::new_fin(
            dst.port(),
            src.port(),
            state.sequence(),
            state.acknowledgement(),
            self.get_tcp_window(dst, src),
            None,
        );

        // Send
        self.send_ipv4(dst.ip().clone(), src.ip().clone(), Layers::Tcp(tcp), None)
    }

    /// Sends UDP packets.
    pub fn send_udp(
        &mut self,
        dst: SocketAddrV4,
        src: SocketAddrV4,
        payload: &[u8],
    ) -> io::Result<()> {
        // UDP
        let udp = Udp::new(dst.port(), src.port());

        self.send_ipv4(
            dst.ip().clone(),
            src.ip().clone(),
            Layers::Udp(udp),
            Some(payload),
        )
    }

    fn send_ipv4(
        &mut self,
        dst_ip_addr: Ipv4Addr,
        src_ip_addr: Ipv4Addr,
        mut transport: Layers,
        payload: Option<&[u8]>,
    ) -> io::Result<()> {
        // Fragmentation
        let size = &transport.len()
            + match payload {
                Some(payload) => payload.len(),
                None => 0,
            };
        let mss = *self
            .src_mtu_map
            .get(&src_ip_addr)
            .unwrap_or(&self.local_mtu)
            - Ipv4::minimum_len();
        if size <= mss {
            // IPv4
            let ipv4 = Ipv4::new(
                *self
                    .ipv4_identification_map
                    .get(&(src_ip_addr, dst_ip_addr))
                    .unwrap_or(&0),
                transport.kind(),
                dst_ip_addr,
                src_ip_addr,
            )
            .unwrap();

            // Set IPv4 layer for checksum
            match transport {
                Layers::Tcp(ref mut tcp) => tcp.set_ipv4_layer(&ipv4),
                Layers::Udp(ref mut udp) => udp.set_ipv4_layer(&ipv4),
                _ => {}
            }

            // Send
            self.send_ethernet(
                *self
                    .src_hardware_addr_map
                    .get(&src_ip_addr)
                    .unwrap_or(&pcap::HARDWARE_ADDR_UNSPECIFIED),
                Layers::Ipv4(ipv4),
                Some(transport),
                payload,
            )?;
        } else {
            // Pseudo header
            let ipv4 = Ipv4::new(0, transport.kind(), dst_ip_addr, src_ip_addr).unwrap();

            // Set IPv4 layer for checksum
            match &mut transport {
                Layers::Tcp(tcp) => tcp.set_ipv4_layer(&ipv4),
                Layers::Udp(udp) => udp.set_ipv4_layer(&ipv4),
                _ => {}
            }

            // Payload
            let mut buffer = vec![0u8; size];
            match payload {
                Some(payload) => transport.serialize_with_payload(
                    buffer.as_mut_slice(),
                    payload,
                    transport.len() + payload.len(),
                )?,
                None => transport.serialize(buffer.as_mut_slice(), transport.len())?,
            };

            let mut n = 0;
            while n < size {
                let mut length = min(size - n, mss);
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
                let ipv4 = if remain > 0 {
                    Ipv4::new_more_fragment(
                        *self
                            .ipv4_identification_map
                            .get(&(src_ip_addr, dst_ip_addr))
                            .unwrap_or(&0),
                        transport.kind(),
                        (n / 8) as u16,
                        dst_ip_addr,
                        src_ip_addr,
                    )
                    .unwrap()
                } else {
                    Ipv4::new_last_fragment(
                        *self
                            .ipv4_identification_map
                            .get(&(src_ip_addr, dst_ip_addr))
                            .unwrap_or(&0),
                        transport.kind(),
                        (n / 8) as u16,
                        dst_ip_addr,
                        src_ip_addr,
                    )
                    .unwrap()
                };

                // Send
                self.send_ethernet(
                    *self
                        .src_hardware_addr_map
                        .get(&src_ip_addr)
                        .unwrap_or(&pcap::HARDWARE_ADDR_UNSPECIFIED),
                    Layers::Ipv4(ipv4),
                    None,
                    Some(&buffer[n..n + length]),
                )?;

                n += length;
            }
        }

        // Update IPv4 identification
        self.increase_ipv4_identification(dst_ip_addr, src_ip_addr);

        Ok(())
    }

    fn send_ethernet(
        &mut self,
        src_hardware_addr: HardwareAddr,
        network: Layers,
        transport: Option<Layers>,
        payload: Option<&[u8]>,
    ) -> io::Result<()> {
        // Ethernet
        let ethernet =
            Ethernet::new(network.kind(), self.local_hardware_addr, src_hardware_addr).unwrap();

        // Indicator
        let indicator = Indicator::new(Layers::Ethernet(ethernet), Some(network), transport);

        // Send
        match payload {
            Some(payload) => self.send_with_payload(&indicator, payload),
            None => self.send(&indicator),
        }
    }

    fn send(&mut self, indicator: &Indicator) -> io::Result<()> {
        // Serialize and send
        let size = indicator.len();
        let buffer_size = max(size, MINIMUM_FRAME_SIZE);
        let mut result = None;
        self.tx.build_and_send(1, buffer_size, &mut |buffer| {
            if let Err(e) = indicator.serialize(&mut buffer[..size]) {
                result = Some(e);
            }
        });
        match result {
            Some(e) => return Err(e),
            None => debug!("send to pcap: {} ({} Bytes)", indicator.brief(), size),
        }

        // Monitor
        if let Some(size) = &self.traffic_size {
            size.fetch_add(buffer_size, Ordering::Relaxed);
        }
        if let Some(count) = &self.traffic_count {
            count.fetch_add(1, Ordering::Relaxed);
        }

        Ok(())
    }

    fn send_with_payload(&mut self, indicator: &Indicator, payload: &[u8]) -> io::Result<()> {
        // Serialize and send
        let size = indicator.len();
        let buffer_size = max(size + payload.len(), MINIMUM_FRAME_SIZE);
        let mut result = None;
        self.tx
            .build_and_send(1, buffer_size, &mut |buffer| {
                if let Err(e) =
                    indicator.serialize_with_payload(&mut buffer[..size + payload.len()], payload)
                {
                    result = Some(e);
                }
            })
            .unwrap_or(Ok(()))?;
        match result {
            Some(e) => return Err(e),
            None => debug!(
                "send to pcap: {} ({} + {} Bytes)",
                indicator.brief(),
                size,
                payload.len()
            ),
        }

        // Monitor
        if let Some(size) = &self.traffic_size {
            size.fetch_add(buffer_size, Ordering::Relaxed);
        }
        if let Some(count) = &self.traffic_count {
            count.fetch_add(1, Ordering::Relaxed);
        }

        Ok(())
    }
}

impl ForwardStream for Forwarder {
    fn open(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<()> {
        self.send_tcp_ack_syn(dst, src)?;

        let state = self
            .get_state_mut(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        state.update_syn_timer();

        Ok(())
    }

    fn forward(&mut self, dst: SocketAddrV4, src: SocketAddrV4, payload: &[u8]) -> io::Result<()> {
        let state = self
            .get_state(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        if state.cache_fin().is_some() || state.queue_fin() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        self.queue_tcp(dst, src, payload)
    }

    fn tick(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<()> {
        self.retransmit_tcp_timedout(dst, src)
    }

    fn close(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<()> {
        let state = match self.get_state_mut(dst, src) {
            Some(state) => state,
            None => return Ok(()),
        };
        state.append_queue_fin();

        self.send_tcp(dst, src)
    }

    fn check(&self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<usize> {
        let state = self
            .get_state(dst, src)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
        Ok(state.queue_remaining())
    }
}

impl ForwardDatagram for Forwarder {
    fn forward(&mut self, dst: SocketAddrV4, src: SocketAddrV4, payload: &[u8]) -> io::Result<()> {
        self.send_udp(dst, src, payload)
    }
}

fn disjoint_u32_range(main: (u32, u32), sub: (u32, u32)) -> Vec<(u32, u32)> {
    let size_main = main
        .1
        .checked_sub(main.0)
        .unwrap_or_else(|| main.1 + (u32::MAX - main.0)) as usize;
    let diff_first = sub
        .0
        .checked_sub(main.0)
        .unwrap_or_else(|| sub.0 + (u32::MAX - main.0)) as usize;
    let diff_second = sub
        .1
        .checked_sub(main.1)
        .unwrap_or_else(|| sub.1 + (u32::MAX - main.1)) as usize;
    let mut vector = Vec::with_capacity(2);

    if diff_first <= MAX_U32_WINDOW_SIZE {
        if diff_second > MAX_U32_WINDOW_SIZE {
            // sub is in the main
            vector.push((main.0, sub.0));
            vector.push((sub.1, main.1));
        } else {
            if diff_first >= size_main {
                // sub is in the right of the main
                vector.push((main.0, main.1));
            } else {
                // sub overlaps the right part of the main
                vector.push((main.0, sub.0));
            }
        }
    } else {
        if diff_second > MAX_U32_WINDOW_SIZE {
            // The distance between the main's left edge and the sub's right edge
            let diff = sub
                .1
                .checked_sub(main.0)
                .unwrap_or_else(|| sub.1 + (u32::MAX - main.0)) as usize;
            if diff > MAX_U32_WINDOW_SIZE {
                // sub is in the left of the main
                vector.push((main.0, main.1));
            } else {
                // sub overlaps the left part of the main
                vector.push((sub.1, main.1));
            }
        } else {
            // sub covers the main
        }
    }

    vector
}

/// Represents the threshold of TCP ACK duplicates before trigger a fast retransmission.
const DUPLICATES_THRESHOLD: usize = 3;
/// Represents the cool down time between 2 retransmissions.
const RETRANS_COOL_DOWN: u128 = 200;

/// Represents if the TCP selective acknowledgment option is enabled.
const ENABLE_SACK: bool = true;

/// Represents if the TCP window scale option is enabled.
const ENABLE_WSCALE: bool = true;
/// Represents the max window scale of the receive window.
const MAX_RECV_WSCALE: u8 = 8;

/// Represents the max limit of UDP port for binding in local.
const MAX_UDP_PORT: usize = 256;

/// Represents a channel redirect traffic to the proxy or loopback to the source in pcap.
pub struct Redirector {
    tx: Arc<Mutex<Forwarder>>,
    tx_src_hardware_addr_set_ip_addr_set: HashSet<Ipv4Addr>,
    src_ip_addr: Ipv4Network,
    local_ip_addr: Ipv4Addr,
    gw_ip_addr: Option<Ipv4Addr>,
    proxy: ProxyConfig,
    streams: HashMap<(SocketAddrV4, SocketAddrV4), StreamWorker>,
    states: HashMap<(SocketAddrV4, SocketAddrV4), TcpRxState>,
    datagrams: HashMap<u16, DatagramWorker>,
    /// Represents the map mapping a source port to a local port.
    datagram_map: HashMap<SocketAddrV4, u16>,
    /// Represents the LRU mapping a local port to a source port.
    udp_lru: LruCache<u16, SocketAddrV4>,
    defrag: Defraggler,
    traffic_size: Option<Arc<AtomicUsize>>,
    traffic_count: Option<Arc<AtomicUsize>>,
}

impl Redirector {
    /// Creates a new `Redirector`.
    pub fn new(
        tx: Arc<Mutex<Forwarder>>,
        src_ip_addr: Ipv4Network,
        local_ip_addr: Ipv4Addr,
        gw_ip_addr: Option<Ipv4Addr>,
        proxy: ProxyConfig,
        traffic: Option<Traffic>,
    ) -> Redirector {
        let size = match &traffic {
            Some(traffic) => Some(traffic.size()),
            None => None,
        };
        let count = match &traffic {
            Some(traffic) => Some(traffic.count()),
            None => None,
        };
        let redirector = Redirector {
            tx,
            tx_src_hardware_addr_set_ip_addr_set: HashSet::new(),
            src_ip_addr,
            local_ip_addr,
            gw_ip_addr,
            proxy,
            streams: HashMap::new(),
            states: HashMap::new(),
            datagrams: HashMap::new(),
            datagram_map: HashMap::new(),
            udp_lru: LruCache::new(MAX_UDP_PORT),
            defrag: Defraggler::new(),
            traffic_size: size,
            traffic_count: count,
        };
        if let Some(gw_ip_addr) = gw_ip_addr {
            redirector.tx.lock().unwrap().set_local_ip_addr(gw_ip_addr);
        }

        redirector
    }

    /// Opens an `Interface` for redirection.
    pub async fn open(&mut self, rx: &mut Receiver) -> io::Result<()> {
        self.open_monitored(rx, None).await
    }

    /// Opens an `Interface` for redirection and monitoring.
    pub async fn open_monitored(
        &mut self,
        rx: &mut Receiver,
        is_running: Option<Arc<AtomicBool>>,
    ) -> io::Result<()> {
        // Send gratuitous ARP
        if self.gw_ip_addr.is_some() {
            self.tx.lock().unwrap().send_gratuitous_arp()?;
        }

        loop {
            // Monitor
            if let Some(is_running) = &is_running {
                if !is_running.load(Ordering::Relaxed) {
                    return Ok(());
                }
            }
            match rx.next() {
                Ok(frame) => {
                    if let Some(ref indicator) = Indicator::from(frame) {
                        if let Some(t) = indicator.network_kind() {
                            match t {
                                LayerKinds::Arp => {
                                    if let Err(ref e) = self.handle_arp(indicator) {
                                        warn!("handle {}: {}", indicator.brief(), e);
                                    }
                                }
                                LayerKinds::Ipv4 => {
                                    if let Err(ref e) = self.handle_ipv4(indicator, frame).await {
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
        if let Some(gw_ip_addr) = self.gw_ip_addr {
            if let Some(arp) = indicator.arp() {
                let src = arp.src();
                if src != self.local_ip_addr
                    && self.src_ip_addr.contains(src)
                    && arp.dst() == gw_ip_addr
                {
                    let src = arp.src();
                    debug!(
                        "receive from pcap: {} ({} Bytes)",
                        indicator.brief(),
                        indicator.len()
                    );

                    // Set forwarder's hardware address
                    self.set_tx_hardware_addr(src, arp.src_hardware_addr());

                    // Send
                    self.tx.lock().unwrap().send_arp_reply(src)?;

                    // Monitor
                    if let Some(size) = &self.traffic_size {
                        size.fetch_add(indicator.content_len(), Ordering::Relaxed);
                    }
                    if let Some(count) = &self.traffic_count {
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_ipv4(&mut self, indicator: &Indicator, frame: &[u8]) -> io::Result<()> {
        if let Some(ipv4) = indicator.ipv4() {
            let src = ipv4.src();
            if src != self.local_ip_addr && self.src_ip_addr.contains(src) {
                let src = ipv4.src();
                debug!(
                    "receive from pcap: {} ({} + {} Bytes)",
                    indicator.brief(),
                    indicator.len(),
                    indicator.content_len() - indicator.len()
                );
                // Set forwarder's hardware address
                self.set_tx_hardware_addr(src, indicator.ethernet().unwrap().src());

                let frame_without_padding = &frame[..indicator.content_len()];
                if ipv4.is_fragment() {
                    // Fragmentation
                    let frag = match self.defrag.add(indicator, frame_without_padding) {
                        Some(frag) => frag,
                        None => return Ok(()),
                    };
                    let (transport, payload) = frag.concatenate();

                    if let Some(transport) = transport {
                        match transport {
                            Layers::Icmpv4(ref icmpv4) => self.handle_icmpv4(icmpv4)?,
                            Layers::Tcp(ref tcp) => self.handle_tcp(tcp, &payload).await?,
                            Layers::Udp(ref udp) => self.handle_udp(udp, &payload).await?,
                            _ => unreachable!(),
                        }
                    }
                } else {
                    if let Some(transport) = indicator.transport() {
                        match transport {
                            Layers::Icmpv4(icmpv4) => self.handle_icmpv4(icmpv4)?,
                            Layers::Tcp(tcp) => {
                                self.handle_tcp(tcp, &frame_without_padding[indicator.len()..])
                                    .await?
                            }
                            Layers::Udp(udp) => {
                                self.handle_udp(udp, &frame_without_padding[indicator.len()..])
                                    .await?
                            }
                            _ => unreachable!(),
                        }
                    }
                }

                // Monitor
                if let Some(size) = &self.traffic_size {
                    size.fetch_add(indicator.content_len(), Ordering::Relaxed);
                }
                if let Some(count) = &self.traffic_count {
                    count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        Ok(())
    }

    fn handle_icmpv4(&mut self, icmpv4: &Icmpv4) -> io::Result<()> {
        if icmpv4.is_destination_port_unreachable() {
            // Destination port unreachable
            let kind = match icmpv4.next_level_layer_kind() {
                Some(kind) => kind,
                None => return Ok(()),
            };
            match kind {
                LayerKinds::Udp => {
                    let dst = icmpv4.dst().unwrap();
                    self.unbind_local_udp_port(dst);
                }
                _ => {}
            }
        } else if icmpv4.is_fragmentation_required_and_df_flag_set() {
            // Fragmentation required, and DF flag set
            let mtu = icmpv4.next_hop_mtu().unwrap();
            if self
                .tx
                .lock()
                .unwrap()
                .set_src_mtu(icmpv4.dst_ip_addr().unwrap(), mtu as usize)
            {
                info!("Update MTU of {} to {}", icmpv4.dst_ip_addr().unwrap(), mtu);
            }
        }

        Ok(())
    }

    async fn handle_tcp(&mut self, tcp: &Tcp, payload: &[u8]) -> io::Result<()> {
        if tcp.is_rst() {
            self.handle_tcp_rst(tcp);
        } else if tcp.is_ack() {
            self.handle_tcp_ack(tcp, payload)?;
        } else if tcp.is_syn() {
            // Pure TCP SYN
            self.handle_tcp_syn(tcp).await?;
        } else if tcp.is_fin() {
            // Pure TCP FIN
            self.handle_tcp_fin(tcp, payload)?;
        } else {
            unreachable!();
        }

        Ok(())
    }

    fn handle_tcp_ack(&mut self, tcp: &Tcp, payload: &[u8]) -> io::Result<()> {
        let src = SocketAddrV4::new(tcp.src_ip_addr(), tcp.src());
        let dst = SocketAddrV4::new(tcp.dst_ip_addr(), tcp.dst());
        let key = (src, dst);
        let is_exist = self.streams.get(&key).is_some();
        let is_writable = match self.streams.get(&key) {
            Some(stream) => !stream.is_tx_closed(),
            None => false,
        };

        if is_exist {
            // ACK
            let state = self
                .states
                .get_mut(&key)
                .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
            if tcp.sequence() != state.recv_next() {
                trace!(
                    "TCP out of order of {} -> {} at {}",
                    src,
                    dst,
                    tcp.sequence()
                );
            }
            {
                let mut tx_locked = self.tx.lock().unwrap();
                let tx_state = tx_locked
                    .get_state_mut(dst, src)
                    .ok_or(io::Error::from(io::ErrorKind::NotFound))?;

                tx_state.acknowledge(tcp.acknowledgement());
                tx_state.set_src_window((tcp.window() as usize) << state.wscale() as usize);
            }

            if payload.len() > 0 {
                // ACK
                if is_writable {
                    // Append to cache
                    let cont_payload = state.append_cache(tcp.sequence(), payload)?;

                    // SACK
                    if state.sack_perm() {
                        let sacks = state.cache().filled();
                        self.tx
                            .lock()
                            .unwrap()
                            .get_state_mut(dst, src)
                            .ok_or(io::Error::from(io::ErrorKind::NotFound))?
                            .set_sacks(&sacks);
                    }

                    match cont_payload {
                        Some(payload) => {
                            // Send
                            let stream = self
                                .streams
                                .get_mut(&key)
                                .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
                            let size = payload.len();
                            match stream.send(payload) {
                                Ok(_) => {
                                    let cache_remaining_size = (state.cache().remaining()
                                        >> state.wscale() as usize)
                                        as u16;

                                    state.add_recv_next(size as u32);

                                    let mut tx_locked = self.tx.lock().unwrap();
                                    let tx_state = tx_locked
                                        .get_state_mut(dst, src)
                                        .ok_or(io::Error::from(io::ErrorKind::NotFound))?;

                                    // Update window size
                                    tx_state.set_window(cache_remaining_size);

                                    // Update TCP acknowledgement
                                    tx_state.add_acknowledgement(size as u32);

                                    // Send delayed ACK0
                                    // If there is a heavy traffic, the ACK reported may be inaccurate, which would results in retransmission
                                    tx_locked.send_tcp_delay_ack_0(dst, src)?;
                                }
                                Err(e) => {
                                    // Send ACK/RST
                                    self.tx.lock().unwrap().send_tcp_ack_rst(dst, src)?;

                                    // Clean up
                                    self.clean_up(src, dst);

                                    return Err(e);
                                }
                            }
                        }
                        None => {
                            // Retransmission or unordered
                            let cache_remaining_size =
                                (state.cache().remaining() >> state.wscale() as usize) as u16;

                            // Update window size
                            let mut tx_locked = self.tx.lock().unwrap();
                            let tx_state = tx_locked
                                .get_state_mut(dst, src)
                                .ok_or(io::Error::from(io::ErrorKind::NotFound))?;

                            tx_state.set_window(cache_remaining_size);

                            // Send ACK0
                            tx_locked.send_tcp_ack_0(dst, src)?;
                        }
                    }
                } else {
                    // Send ACK/RST
                    self.tx.lock().unwrap().send_tcp_ack_rst(dst, src)?;

                    // Clean up
                    self.clean_up(src, dst);

                    return Ok(());
                }
            } else {
                // ACK0
                if !is_writable {
                    if self.tx.lock().unwrap().get_cache_size(dst, src) == 0 {
                        // LAST_ACK
                        // Clean up
                        self.clean_up(src, dst);

                        return Ok(());
                    }
                } else {
                    // Duplicate ACK
                    state.admit(tcp.acknowledgement());
                    if state.duplicate() >= DUPLICATES_THRESHOLD {
                        let is_cooled_down = match state.last_retrans() {
                            Some(ref instant) => instant.elapsed().as_millis() < RETRANS_COOL_DOWN,
                            None => false,
                        };

                        if !is_cooled_down && !tcp.is_zero_window() {
                            // Fast retransmit
                            let mut is_sr = false;
                            if state.sack_perm() {
                                if let Some(sacks) = tcp.sack() {
                                    if sacks.len() > 0 {
                                        // Selective retransmission
                                        self.tx.lock().unwrap().retransmit_tcp(
                                            dst,
                                            src,
                                            Some(sacks),
                                        )?;
                                        is_sr = true;
                                    }
                                }
                            }

                            if !is_sr {
                                // Back N
                                self.tx.lock().unwrap().retransmit_tcp(dst, src, None)?;
                            }

                            state.admit_retrans();
                        }
                    }
                }
            }

            // Trigger sending remaining data
            self.tx.lock().unwrap().send_tcp(dst, src)?;

            // FIN
            if tcp.is_fin() || state.fin_sequence().is_some() {
                self.handle_tcp_fin(tcp, payload)?;
            }
        } else {
            // Send ACK/RST
            self.tx
                .lock()
                .unwrap()
                .send_tcp_ack_rst_untracked(dst, src, tcp.acknowledgement())?;
        }

        Ok(())
    }

    async fn handle_tcp_syn(&mut self, tcp: &Tcp) -> io::Result<()> {
        let src = SocketAddrV4::new(tcp.src_ip_addr(), tcp.src());
        let dst = SocketAddrV4::new(tcp.dst_ip_addr(), tcp.dst());
        let key = (src, dst);
        let is_exist = self.streams.get(&key).is_some();

        // Connect if not connected, drop if established
        if !is_exist {
            // Clean up
            self.clean_up(src, dst);

            // Admit SYN
            let wscale = match ENABLE_WSCALE {
                true => tcp.wscale(),
                false => None,
            };
            let recv_wscale = match wscale {
                Some(wscale) => Some(min(wscale, MAX_RECV_WSCALE)),
                None => None,
            };
            let sack_perm = ENABLE_SACK && tcp.is_sack_perm();
            let state = TcpRxState::new(src, dst, tcp.sequence(), wscale.unwrap_or(0), sack_perm);

            {
                let mut tx_locked = self.tx.lock().unwrap();

                let mut rng = rand::thread_rng();
                let sequence = rng.gen::<u32>();
                let acknowledgement = tcp.sequence().checked_add(1).unwrap_or(0);
                if let Some(mss) = tcp.mss() {
                    let mtu = Ipv4::minimum_len() + Tcp::minimum_len() + mss as usize;
                    if tx_locked.set_src_mtu(tcp.src_ip_addr(), mtu) {
                        info!("Update MTU of {} to {}", tcp.src_ip_addr(), mtu);
                    }
                }

                let tx_state = TcpTxState::new(
                    src,
                    dst,
                    sequence,
                    acknowledgement,
                    tcp.window(),
                    recv_wscale,
                    sack_perm,
                    wscale,
                    tx_locked.get_src_mtu(tcp.src_ip_addr())
                        - (Ipv4::minimum_len() + Tcp::minimum_len()),
                );
                tx_locked.set_state(dst, src, tx_state);
            }

            // Connect
            let stream = StreamWorker::connect(self.get_tx(), src, dst, &self.proxy).await;

            let stream = match stream {
                Ok(stream) => stream,
                Err(e) => {
                    {
                        let mut tx_locked = self.tx.lock().unwrap();
                        let tx_state = tx_locked
                            .get_state_mut(dst, src)
                            .ok_or(io::Error::from(io::ErrorKind::NotFound))?;

                        tx_state.add_acknowledgement(1);

                        // Send ACK/RST
                        tx_locked.send_tcp_ack_rst(dst, src)?;
                    }

                    // Clean up
                    self.clean_up(src, dst);

                    return Err(e);
                }
            };

            self.states.insert(key, state);
            self.streams.insert(key, stream);
        }

        Ok(())
    }

    fn handle_tcp_rst(&mut self, tcp: &Tcp) {
        let src = SocketAddrV4::new(tcp.src_ip_addr(), tcp.src());
        let dst = SocketAddrV4::new(tcp.dst_ip_addr(), tcp.dst());
        let key = (src, dst);

        if tcp.is_ack() {
            match self.states.get(&key) {
                Some(state) => {
                    // Exam ACK
                    if tcp.sequence() == state.recv_next() {
                        // Admit RST
                        // Clean up
                        self.clean_up(src, dst);
                    }
                }
                None => {
                    // Clean up
                    self.clean_up(src, dst);
                }
            }
        } else {
            // Clean up
            self.clean_up(src, dst);
        }
    }

    fn handle_tcp_fin(&mut self, tcp: &Tcp, payload: &[u8]) -> io::Result<()> {
        let src = SocketAddrV4::new(tcp.src_ip_addr(), tcp.src());
        let dst = SocketAddrV4::new(tcp.dst_ip_addr(), tcp.dst());
        let key = (src, dst);
        let is_exist = self.streams.get(&key).is_some();
        let (is_writable, is_readable) = match self.streams.get(&key) {
            Some(stream) => (!stream.is_tx_closed(), !stream.is_rx_closed()),
            None => (false, false),
        };

        if is_exist {
            if is_writable {
                let state = self
                    .states
                    .get_mut(&key)
                    .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
                if tcp.is_fin() {
                    // Update FIN sequence
                    state.set_fin_sequence(
                        tcp.sequence()
                            .checked_add(payload.len() as u32)
                            .unwrap_or_else(|| payload.len() as u32 - (u32::MAX - tcp.sequence())),
                    );
                }

                // If the receive next is the same as the FIN sequence, the FIN should be popped
                if let Some(fin_sequence) = state.fin_sequence() {
                    if fin_sequence == state.recv_next() {
                        // Admit FIN
                        state.admit_fin();
                        state.add_recv_next(1);

                        {
                            let mut tx_locked = self.tx.lock().unwrap();
                            let tx_state = tx_locked
                                .get_state_mut(dst, src)
                                .ok_or(io::Error::from(io::ErrorKind::NotFound))?;

                            tx_state.add_acknowledgement(1);

                            // Send ACK0
                            tx_locked.send_tcp_ack_0(dst, src)?;
                        }
                        if is_readable {
                            // Close by local
                            let stream = self
                                .streams
                                .get_mut(&key)
                                .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
                            stream.shutdown(Shutdown::Write);
                        } else {
                            // Close by remote
                            // Clean up
                            self.clean_up(src, dst);
                        }
                    } else {
                        trace!(
                            "TCP out of order of {} -> {} at {}",
                            src,
                            dst,
                            tcp.sequence()
                        );

                        if payload.len() == 0 {
                            // Send ACK0
                            self.tx.lock().unwrap().send_tcp_ack_0(dst, src)?;
                        }
                    }
                }
            } else {
                // Retransmission
                // Send ACK0
                self.tx.lock().unwrap().send_tcp_ack_0(dst, src)?;
            }
        } else {
            // Send ACK/RST
            self.tx
                .lock()
                .unwrap()
                .send_tcp_ack_rst_untracked(dst, src, tcp.acknowledgement())?;
        }

        Ok(())
    }

    fn clean_up(&mut self, src: SocketAddrV4, dst: SocketAddrV4) {
        let key = (src, dst);

        self.streams.remove(&key);
        self.states.remove(&key);

        self.tx.lock().unwrap().clean_up(dst, src);
    }

    async fn handle_udp(&mut self, udp: &Udp, payload: &[u8]) -> io::Result<()> {
        let src = SocketAddrV4::new(udp.src_ip_addr(), udp.src());

        // Bind
        let port = self.bind_local_udp_port(src).await?;

        // Send
        self.datagrams
            .get_mut(&port)
            .ok_or(io::Error::from(io::ErrorKind::NotFound))?
            .send_to(
                payload.to_vec(),
                SocketAddrV4::new(udp.dst_ip_addr(), udp.dst()),
            )?;

        Ok(())
    }

    async fn bind_local_udp_port(&mut self, src: SocketAddrV4) -> io::Result<u16> {
        let local_port = self.datagram_map.get(&src);
        match local_port {
            Some(&local_port) => {
                // Update LRU
                self.udp_lru.get(&local_port);

                Ok(local_port)
            }
            None => {
                let bind_port = if self.udp_lru.len() < self.udp_lru.cap() {
                    match DatagramWorker::bind(self.get_tx(), src, &self.proxy).await {
                        Ok((worker, port)) => {
                            self.datagrams.insert(port, worker);

                            // Update map and LRU
                            self.datagram_map.insert(src, port);
                            self.udp_lru.put(port, src);

                            trace!("bind UDP port {} = {}", port, src);

                            Ok(port)
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "cannot bind UDP port"))
                };

                match bind_port {
                    Ok(port) => Ok(port),
                    Err(e) => {
                        if self.udp_lru.is_empty() {
                            Err(e)
                        } else {
                            let pair = self.udp_lru.pop_lru().unwrap();
                            let port = pair.0;
                            let prev_src = pair.1;

                            // Reuse
                            self.datagram_map.remove(&prev_src);
                            trace!("reuse UDP port {} = {} to {}", port, prev_src, src);
                            self.datagram_map.insert(src.clone(), port);
                            self.datagrams.get_mut(&port).unwrap().set_src(&src);

                            // Update LRU
                            self.udp_lru.put(port, src.clone());

                            Ok(port)
                        }
                    }
                }
            }
        }
    }

    fn unbind_local_udp_port(&mut self, src: SocketAddrV4) {
        let local_port = self.datagram_map.get(&src);
        match local_port {
            Some(&local_port) => {
                self.datagrams.remove(&local_port);
                self.udp_lru.pop(&local_port);
                self.datagram_map.remove(&src);

                trace!("unbind UDP port {} = {}", local_port, src);
            }
            None => {}
        }
    }

    fn get_tx(&self) -> Arc<Mutex<Forwarder>> {
        Arc::clone(&self.tx)
    }

    fn set_tx_hardware_addr(&mut self, ip_addr: Ipv4Addr, hardware_addr: HardwareAddr) {
        if !self.tx_src_hardware_addr_set_ip_addr_set.contains(&ip_addr) {
            self.tx
                .lock()
                .unwrap()
                .set_src_hardware_addr(ip_addr, hardware_addr);
            self.tx_src_hardware_addr_set_ip_addr_set.insert(ip_addr);
            info!("Device {} ({}) joined the network", ip_addr, hardware_addr);
        }
    }
}
