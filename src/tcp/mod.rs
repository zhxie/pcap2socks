//! Support for tracking TCP connections.

use log::trace;
use std::cmp::{max, min};
use std::collections::VecDeque;
use std::fmt::{self, Display};
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};
use tokio::io;

mod cache;
use cache::{Queue, Window};

/// Represents a timer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Timer {
    instant: Instant,
    timeout: Duration,
}

impl Timer {
    /// Creates a new `Timer`.
    pub fn new(timeout: u64) -> Timer {
        Timer {
            instant: Instant::now(),
            timeout: Duration::from_millis(timeout),
        }
    }

    /// Returns the amount of time elapsed since this timer was created.
    pub fn elapsed(&self) -> Duration {
        self.instant.elapsed()
    }

    /// Returns if the timer is timed out.
    pub fn is_timedout(&self) -> bool {
        self.instant.elapsed() > self.timeout
    }
}

/// Represents the max distance of `u32` values between packets in an `u32` window.
const MAX_U32_WINDOW_SIZE: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// Enumeration of congestion control algorithms.
pub enum TcpCcAlgorithms {
    /// Represents the TCP Tahoe congestion control algorithm.
    Tahoe,
    /// Represents the TCP Reno congestion control algorithm.
    Reno,
    /// Represents the TCP CUBIC congestion control algorithm.
    Cubic,
}

/// Represents the initial slow start threshold rate for congestion window in a TCP connection.
const INITIAL_SSTHRESH_RATE: usize = 100;

/// Trait for TCP congestion control.
pub trait TcpCc: Send + Sync {
    /// Indicates a TCP ACK event.
    fn ack(&mut self, size: usize);

    /// Indicates a TCP ACK event with RTT.
    fn ack_rtt(&mut self, size: usize, rtt: f64);

    /// Indicates a TCP timed out event.
    fn timedout(&mut self);

    /// Indicates a TCP fast retransmission event.
    fn fast_retransmission(&mut self);

    /// Returns the congestion window of the TCP connection.
    fn cwnd(&self) -> usize;
}

/// Represents the TCP Tahoe congestion control state of a TCP connection.
#[derive(Clone, Debug)]
pub struct TcpTahoeCcState {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    mss: usize,
    cwnd: usize,
    ssthresh: usize,
    cwnd_count: usize,
}

impl TcpTahoeCcState {
    /// Creates a new `TcpTahoeCcState`.
    pub fn new(src: SocketAddrV4, dst: SocketAddrV4, mss: usize) -> TcpTahoeCcState {
        TcpTahoeCcState {
            src,
            dst,
            mss,
            cwnd: mss,
            ssthresh: mss.saturating_mul(INITIAL_SSTHRESH_RATE),
            cwnd_count: 0,
        }
    }

    fn set_cwnd(&mut self, cwnd: usize) {
        self.cwnd = max(self.mss, cwnd);
        trace!(
            "set TCP congestion window of {} -> {} to {}",
            self.dst,
            self.src,
            self.cwnd
        );
    }

    fn update_ssthresh(&mut self) {
        self.ssthresh = max(self.cwnd / 2, self.mss.saturating_mul(2));
        trace!(
            "update TCP slow start threshold of {} -> {} to {}",
            self.dst,
            self.src,
            self.ssthresh
        );
    }

    fn slow_start(&mut self, size: usize) -> usize {
        let remain = self.ssthresh - self.cwnd;
        let delta = min(remain, size);

        self.set_cwnd(self.cwnd.saturating_add(delta));

        size - delta
    }

    #[allow(clippy::unnecessary_lazy_evaluations)]
    fn congestion_control(&mut self, size: usize) {
        let remain = self.cwnd - self.cwnd_count;

        let size_mod = size % self.cwnd;
        self.cwnd_count = self
            .cwnd_count
            .checked_add(size_mod)
            .unwrap_or_else(|| size_mod - (self.cwnd - self.cwnd_count))
            % self.cwnd;

        if size >= remain {
            let size_remain = size - remain;

            let n = (size_remain / self.cwnd).saturating_add(1);
            self.set_cwnd(
                self.cwnd
                    .saturating_add(self.mss.saturating_mul(n)),
            )
        }
    }
}

impl TcpCc for TcpTahoeCcState {
    fn ack(&mut self, size: usize) {
        let mut size = size;
        // Slow start
        if self.cwnd < self.ssthresh {
            size = self.slow_start(size);
        }

        // Congestion avoidance
        if size > 0 {
            self.congestion_control(size);
        }
    }

    fn ack_rtt(&mut self, size: usize, _: f64) {
        self.ack(size);
    }

    fn timedout(&mut self) {
        self.update_ssthresh();
        self.set_cwnd(self.mss);
        self.cwnd_count = 0;
    }

    fn fast_retransmission(&mut self) {
        self.timedout();
    }

    fn cwnd(&self) -> usize {
        self.cwnd
    }
}

impl Display for TcpTahoeCcState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP Tahoe State: {} -> {}, cwnd = {}, ssthresh = {}",
            self.dst, self.src, self.cwnd, self.ssthresh
        )
    }
}

/// Represents the TCP Reno congestion control state of a TCP connection.
#[derive(Clone, Debug)]
pub struct TcpRenoCcState {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    mss: usize,
    cwnd: usize,
    ssthresh: usize,
    cwnd_count: usize,
}

impl TcpRenoCcState {
    /// Creates a new `TcpRenoCcState`.
    pub fn new(src: SocketAddrV4, dst: SocketAddrV4, mss: usize) -> TcpRenoCcState {
        TcpRenoCcState {
            src,
            dst,
            mss,
            cwnd: mss,
            ssthresh: mss.saturating_mul(INITIAL_SSTHRESH_RATE),
            cwnd_count: 0,
        }
    }

    fn set_cwnd(&mut self, cwnd: usize) {
        self.cwnd = max(self.mss, cwnd);
        trace!(
            "set TCP congestion window of {} -> {} to {}",
            self.dst,
            self.src,
            self.cwnd
        );
    }

    fn update_ssthresh(&mut self) {
        self.ssthresh = max(self.cwnd / 2, self.mss.saturating_mul(2));
        trace!(
            "update TCP slow start threshold of {} -> {} to {}",
            self.dst,
            self.src,
            self.ssthresh
        );
    }

    fn slow_start(&mut self, size: usize) -> usize {
        let remain = self.ssthresh - self.cwnd;
        let delta = min(remain, size);

        self.set_cwnd(self.cwnd.saturating_add(delta));

        size - delta
    }

    #[allow(clippy::unnecessary_lazy_evaluations)]
    fn congestion_control(&mut self, size: usize) {
        let remain = self.cwnd - self.cwnd_count;

        let size_mod = size % self.cwnd;
        self.cwnd_count = self
            .cwnd_count
            .checked_add(size_mod)
            .unwrap_or_else(|| size_mod - (self.cwnd - self.cwnd_count))
            % self.cwnd;

        if size >= remain {
            let size_remain = size - remain;

            let n = (size_remain / self.cwnd).saturating_add(1);
            self.set_cwnd(
                self.cwnd
                    .saturating_add(self.mss.saturating_mul(n)),
            )
        }
    }
}

impl TcpCc for TcpRenoCcState {
    fn ack(&mut self, size: usize) {
        let mut size = size;
        // Slow start
        if self.cwnd < self.ssthresh {
            size = self.slow_start(size);
        }

        // Congestion avoidance
        if size > 0 {
            self.congestion_control(size);
        }
    }

    fn ack_rtt(&mut self, size: usize, _: f64) {
        self.ack(size);
    }

    fn timedout(&mut self) {
        self.update_ssthresh();
        self.set_cwnd(self.mss);
        self.cwnd_count = 0;
    }

    fn fast_retransmission(&mut self) {
        self.update_ssthresh();
        self.set_cwnd(self.ssthresh);
        self.cwnd_count = 0;
    }

    fn cwnd(&self) -> usize {
        self.cwnd
    }
}

impl Display for TcpRenoCcState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP Reno State: {} -> {}, cwnd = {}, ssthresh = {}",
            self.dst, self.src, self.cwnd, self.ssthresh
        )
    }
}

const CC_CUBIC_C: f64 = 0.4;
const CC_CUBIC_BETA: f64 = 0.7;

/// Represents the TCP CUBIC congestion control state of a TCP connection.
#[derive(Clone, Debug)]
pub struct TcpCubicCcState {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    w_max: usize,
    w_last_max: usize,
    k: f64,
    last_update: Instant,
    mss: usize,
    cwnd: usize,
    ssthresh: usize,
    cwnd_count: usize,
}

impl TcpCubicCcState {
    /// Creates a new `TcpCubicCcState`.
    pub fn new(src: SocketAddrV4, dst: SocketAddrV4, mss: usize) -> TcpCubicCcState {
        TcpCubicCcState {
            src,
            dst,
            w_max: mss.saturating_mul(INITIAL_SSTHRESH_RATE),
            w_last_max: mss.saturating_mul(INITIAL_SSTHRESH_RATE),
            k: 0.0,
            last_update: Instant::now(),
            mss,
            cwnd: mss,
            ssthresh: mss.saturating_mul(INITIAL_SSTHRESH_RATE),
            cwnd_count: 0,
        }
    }

    fn update(&mut self) {
        self.w_max = self.cwnd;
        // Fast convergence
        if self.w_max < self.w_last_max {
            self.w_last_max = self.w_max;
            self.w_max = ((self.w_max as f64) * (1.0 + CC_CUBIC_BETA) / 2.0) as usize;
        } else {
            self.w_last_max = self.w_max
        }
        trace!(
            "update TCP window max of {} -> {} to {}",
            self.dst,
            self.src,
            self.w_max
        );

        self.k = ((self.w_max as f64) * (1.0 - CC_CUBIC_BETA) / CC_CUBIC_C)
            .min(f64::MAX)
            .cbrt();
        trace!("update TCP K of {} -> {} to {}", self.dst, self.src, self.k);

        self.last_update = Instant::now();
    }

    fn set_cwnd(&mut self, cwnd: usize) {
        self.cwnd = max(self.mss, cwnd);
        trace!(
            "set TCP congestion window of {} -> {} to {}",
            self.dst,
            self.src,
            self.cwnd
        );
    }

    fn update_ssthresh(&mut self) {
        self.ssthresh = max(
            (self.cwnd as f64 * CC_CUBIC_BETA) as usize,
            self.mss.saturating_mul(2),
        );
        trace!(
            "update TCP slow start threshold of {} -> {} to {}",
            self.dst,
            self.src,
            self.ssthresh
        );
    }

    fn reset(&mut self) {
        self.w_max = self.mss.saturating_mul(INITIAL_SSTHRESH_RATE);
        trace!(
            "reset TCP window max of {} -> {} to {}",
            self.dst,
            self.src,
            self.w_max
        );

        self.k = 0.0;
        trace!("reset TCP K of {} -> {} to {}", self.dst, self.src, self.k);

        self.last_update = Instant::now();
    }

    fn slow_start(&mut self, size: usize) -> usize {
        let remain = self.ssthresh - self.cwnd;
        let delta = min(remain, size);

        self.set_cwnd(self.cwnd.saturating_add(delta));

        size - delta
    }

    #[allow(clippy::unnecessary_lazy_evaluations)]
    fn congestion_control_fallback(&mut self, size: usize) {
        let remain = self.cwnd - self.cwnd_count;

        let size_mod = size % self.cwnd;
        self.cwnd_count = self
            .cwnd_count
            .checked_add(size_mod)
            .unwrap_or_else(|| size_mod - (self.cwnd - self.cwnd_count))
            % self.cwnd;

        if size >= remain {
            let size_remain = size - remain;

            let n = (size_remain / self.cwnd)
                .saturating_add(1);
            self.set_cwnd(
                self.cwnd.saturating_add(self.mss.saturating_mul(n)),
            )
        }
    }

    fn w_t(&self, t: f64) -> usize {
        (CC_CUBIC_C * (t - self.k).powi(3) + self.w_max as f64)
            .max(0.0)
            .min(usize::MAX as f64) as usize
    }

    fn w_est(&self, rtt: f64) -> usize {
        (self.w_max as f64 * CC_CUBIC_BETA
            + (3.0 * (1.0 - CC_CUBIC_BETA) / (1.0 + CC_CUBIC_BETA)) * (self.t() / rtt))
            .min(usize::MAX as f64) as usize
    }

    fn t(&self) -> f64 {
        self.last_update.elapsed().as_secs_f64()
    }

    fn congestion_control(&mut self, rtt: f64) {
        let w_t = self.w_t((self.t() + rtt).min(f64::MAX));
        let w_est = self.w_est(rtt);
        if w_t < w_est {
            // TCP-friendly region
            self.set_cwnd(w_est);
        } else {
            // Concave or convex region
            self.set_cwnd(w_t);
        }
    }
}

impl TcpCc for TcpCubicCcState {
    fn ack(&mut self, size: usize) {
        let mut size = size;
        // Slow start
        if self.cwnd <= self.ssthresh {
            size = self.slow_start(size);
        }

        // Congestion avoidance
        if size > 0 {
            self.congestion_control_fallback(size);
        }
    }

    fn ack_rtt(&mut self, size: usize, rtt: f64) {
        let mut size = size;
        // Slow start
        if self.cwnd <= self.ssthresh {
            size = self.slow_start(size);
        }

        // Congestion avoidance
        if size > 0 {
            self.congestion_control(rtt);
        }
    }

    fn timedout(&mut self) {
        self.reset();
        self.update_ssthresh();
        self.set_cwnd((self.cwnd as f64 * CC_CUBIC_BETA) as usize);
        self.cwnd_count = 0;
    }

    fn fast_retransmission(&mut self) {
        self.update();
        self.update_ssthresh();
        self.set_cwnd((self.cwnd as f64 * CC_CUBIC_BETA) as usize);
        self.cwnd_count = 0;
    }

    fn cwnd(&self) -> usize {
        self.cwnd
    }
}

impl Display for TcpCubicCcState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP CUBIC State: {} -> {}, cwnd = {}, ssthresh = {}, w_max = {}",
            self.dst, self.src, self.cwnd, self.ssthresh, self.w_max
        )
    }
}

/// Represents the receive window size.
const RECV_WINDOW: u16 = u16::MAX;

/// Represents the maximum size of extra cache in a TCP connection.
const MAX_QUEUE: usize = 16777216;

/// Represents if the RTO computation is enabled.
const ENABLE_RTO_COMPUTE: bool = true;
/// Represents the initial timeout for a retransmission in a TCP connection.
const INITIAL_RTO: u64 = 1000;
/// Represents the minimum timeout for a retransmission in a TCP connection.
const MIN_RTO: u64 = 1000;
/// Represents the maximum timeout for a retransmission in a TCP connection.
const MAX_RTO: u64 = 60000;

const RTO_K: f64 = 4.0;
const RTO_ALPHA: f64 = 1.0 / 8.0;
const RTO_BETA: f64 = 1.0 / 4.0;

/// Represents if the congestion control is enabled.
const ENABLE_CC: bool = true;
/// Represents the congestion control algorithm.
const CC_ALGORITHM: TcpCcAlgorithms = TcpCcAlgorithms::Reno;

/// Represents the TX state of a TCP connection.
pub struct TcpTxState {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    src_window: usize,
    src_wscale: Option<u8>,
    sack_perm: bool,
    sequence: u32,
    acknowledgement: u32,
    window: u16,
    sacks: Option<Vec<(u32, u32)>>,
    delayed_ack: bool,
    cache: Queue,
    cache_syn: Option<Instant>,
    cache_fin: Option<Timer>,
    cache_fin_retrans: bool,
    queue: VecDeque<u8>,
    queue_fin: bool,
    rto: u64,
    srtt: Option<f64>,
    rttvar: Option<f64>,
    cc: Option<Box<dyn TcpCc>>,
}

impl TcpTxState {
    /// Creates a new `TcpTxState`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        src: SocketAddrV4,
        dst: SocketAddrV4,
        sequence: u32,
        acknowledgement: u32,
        src_window: u16,
        src_wscale: Option<u8>,
        sack_perm: bool,
        wscale: Option<u8>,
        mss: usize,
    ) -> TcpTxState {
        TcpTxState {
            src,
            dst,
            src_window: (src_window as usize) << src_wscale.unwrap_or(0),
            src_wscale,
            sack_perm,
            sequence,
            acknowledgement,
            window: RECV_WINDOW,
            sacks: None,
            delayed_ack: false,
            cache: Queue::with_capacity(
                (RECV_WINDOW as usize) << wscale.unwrap_or(0) as usize,
                sequence,
            ),
            cache_syn: None,
            cache_fin: None,
            cache_fin_retrans: true,
            queue: VecDeque::new(),
            queue_fin: false,
            rto: INITIAL_RTO,
            srtt: None,
            rttvar: None,
            cc: match ENABLE_CC {
                true => match CC_ALGORITHM {
                    TcpCcAlgorithms::Tahoe => Some(Box::new(TcpTahoeCcState::new(src, dst, mss))),
                    TcpCcAlgorithms::Reno => Some(Box::new(TcpRenoCcState::new(src, dst, mss))),
                    TcpCcAlgorithms::Cubic => Some(Box::new(TcpCubicCcState::new(src, dst, mss))),
                },
                false => None,
            },
        }
    }

    /// Sets the source window of the TCP connection.
    pub fn set_src_window(&mut self, window: usize) {
        self.src_window = window;
        trace!(
            "set TCP source window of {} -> {} to {}",
            self.dst,
            self.src,
            window
        );
    }

    /// Adds sequence to the TCP connection.
    #[allow(clippy::unnecessary_lazy_evaluations)]
    pub fn add_sequence(&mut self, n: u32) {
        self.sequence = self
            .sequence
            .checked_add(n)
            .unwrap_or_else(|| n - (u32::MAX - self.sequence));
        trace!(
            "add TCP sequence of {} -> {} to {}",
            self.dst,
            self.src,
            self.sequence
        );
    }

    /// Adds acknowledgement to the TCP connection.
    #[allow(clippy::unnecessary_lazy_evaluations)]
    pub fn add_acknowledgement(&mut self, n: u32) {
        self.acknowledgement = self
            .acknowledgement
            .checked_add(n)
            .unwrap_or_else(|| n - (u32::MAX - self.acknowledgement));
        trace!(
            "add TCP acknowledgement of {} -> {} to {}",
            self.dst,
            self.src,
            self.acknowledgement
        );
    }

    /// Sets the window of the TCP connection.
    pub fn set_window(&mut self, window: u16) {
        self.window = window;
        trace!(
            "set TCP window of {} -> {} to {}",
            self.dst,
            self.src,
            window
        );
    }

    /// Sets the SACKs of the TCP connection.
    pub fn set_sacks(&mut self, sacks: &Vec<(u32, u32)>) {
        if sacks.is_empty() {
            self.sacks = None;
            trace!("remove TCP SACK of {} -> {}", self.dst, self.src);
        } else {
            let size = min(4, sacks.len());
            self.sacks = Some(Vec::from(&sacks[..size]));

            let mut desc = format!("[{}, {}]", sacks[0].0, sacks[0].1);
            if sacks.len() > 1 {
                desc.push_str(format!(" and {} more", sacks.len() - 1).as_str());
            }
            trace!("set TCP SACK of {} -> {} to {}", self.dst, self.src, desc);
        }
    }

    /// Acknowledges to the given sequence of the TCP connection.
    #[allow(clippy::unnecessary_lazy_evaluations)]
    pub fn acknowledge(&mut self, sequence: u32) {
        let mut rtt = None;

        // SYN
        if let Some(instant) = self.cache_syn {
            let send_next = self.sequence;
            if sequence
                .checked_sub(send_next)
                .unwrap_or_else(|| sequence + (u32::MAX - send_next)) as usize
                <= MAX_U32_WINDOW_SIZE
            {
                rtt = Some(instant.elapsed());

                self.cache_syn = None;
                trace!("acknowledge TCP SYN of {} -> {}", self.dst, self.src);

                // Update TCP sequence
                self.add_sequence(1);
            }
        }

        // ACK
        let sub_sequence = sequence
            .checked_sub(self.cache.sequence())
            .unwrap_or_else(|| sequence + (u32::MAX - self.cache.sequence()));
        if sub_sequence > 0 && sub_sequence as usize <= MAX_U32_WINDOW_SIZE {
            // Invalidate cache
            let cache_rtt = self.cache.invalidate_to(sequence);
            if rtt.is_none() {
                rtt = cache_rtt;
            }
            trace!(
                "acknowledge TCP cache of {} -> {} to sequence {}",
                self.dst,
                self.src,
                sequence
            );

            // Congestion control
            if let Some(cc) = &mut self.cc {
                match self.srtt {
                    Some(srtt) => cc.ack_rtt(sub_sequence as usize, srtt),
                    None => cc.ack(sub_sequence as usize),
                }
            }
        }

        // FIN
        if let Some(timer) = self.cache_fin {
            if sequence
                .checked_sub(self.cache.recv_next())
                .unwrap_or_else(|| sequence + (u32::MAX - self.cache.recv_next()))
                as usize
                <= MAX_U32_WINDOW_SIZE
            {
                if rtt.is_none() && !self.cache_fin_retrans && !timer.is_timedout() {
                    rtt = Some(timer.elapsed());
                }

                self.cache_fin = None;
                self.cache_fin_retrans = false;
                trace!("acknowledge TCP FIN of {} -> {}", self.dst, self.src);

                // Update TCP sequence
                self.add_sequence(1);
            }
        }

        // Update RTO
        if let Some(rtt) = rtt {
            self.update_rto(rtt);
        }
    }

    /// Updates the TCP SYN timer of the TCP connection.
    pub fn update_syn_timer(&mut self) {
        self.cache_syn = Some(Instant::now());
        trace!("update TCP SYN timer of {} -> {}", self.dst, self.src);
    }

    /// Updates the TCP FIN timer of the TCP connection.
    pub fn update_fin_timer(&mut self) {
        if self.cache_fin.is_some() {
            self.cache_fin_retrans = true;
        }
        self.cache_fin = Some(Timer::new(self.rto));
        trace!("update TCP FIN timer of {} -> {}", self.dst, self.src);
    }

    /// Set the TCP delayed ACK to the cache of the TCP connection.
    pub fn set_delayed_ack(&mut self) {
        self.delayed_ack = true;

        trace!(
            "set TCP delayed ACK to TCP cache of {} -> {}",
            self.dst,
            self.src
        );
    }

    /// Clears the TCP delayed ACK from the cache of the TCP connection.
    pub fn clear_delayed_ack(&mut self) {
        self.delayed_ack = false;

        trace!(
            "clear TCP delayed ACK to TCP cache of {} -> {}",
            self.dst,
            self.src
        );
    }

    /// Appends the payload from the queue to the cache of the TCP connection.
    pub fn append_cache(&mut self, size: usize) -> io::Result<Vec<u8>> {
        let payload = self.queue.drain(..size).collect::<Vec<_>>();

        // Append to cache
        trace!(
            "append {} Bytes to TCP cache of {} -> {}",
            payload.len(),
            self.dst,
            self.src
        );
        // TODO: intermediate performance degradation
        self.cache.append(&payload, self.rto)?;

        Ok(payload)
    }

    /// Appends the TCP FIN from the queue to the cache of the TCP connection.
    pub fn append_cache_fin(&mut self) {
        self.queue_fin = false;
        trace!(
            "append TCP FIN to TCP cache of {} -> {}",
            self.dst,
            self.src
        );
        self.update_fin_timer();
    }

    /// Appends the payload to the queue of the TCP connection.
    pub fn append_queue(&mut self, payload: &[u8]) {
        // TODO: major performance degradation
        self.queue.extend(payload);
        trace!(
            "append {} Bytes to TCP queue of {} -> {}",
            payload.len(),
            self.dst,
            self.src
        );
    }

    /// Appends the TCP FIN to the queue of the TCP connection.
    pub fn append_queue_fin(&mut self) {
        self.queue_fin = true;
        trace!(
            "append TCP FIN to TCP queue of {} -> {}",
            self.dst,
            self.src
        );
    }

    fn set_rto(&mut self, rto: u64) {
        if ENABLE_RTO_COMPUTE {
            let rto = min(MAX_RTO, max(MIN_RTO, rto));

            self.rto = rto;
            trace!("set TCP RTO of {} -> {} to {}", self.dst, self.src, rto);
        }
    }

    /// Doubles the RTO of the TCP connection.
    pub fn double_rto(&mut self) {
        self.set_rto(self.rto.saturating_mul(2));
    }

    /// Updates the RTO of the TCP connection.
    pub fn update_rto(&mut self, rtt: Duration) {
        let rtt = rtt.as_secs_f64();

        let srtt;
        let rttvar;
        match self.srtt {
            Some(prev_srtt) => {
                // RTTVAR
                let prev_rttvar = self.rttvar.unwrap_or(prev_srtt / 2.0);
                rttvar = (1.0 - RTO_BETA) * prev_rttvar + RTO_BETA * (prev_srtt - rtt).abs();

                // SRTT
                srtt = (1.0 - RTO_ALPHA) * prev_srtt + RTO_ALPHA * rtt;
            }
            None => {
                // SRTT
                srtt = rtt;

                // RTTVAR
                rttvar = rtt / 2.0;
            }
        }

        // SRTT
        self.srtt = Some(srtt);
        trace!("set TCP SRTT of {} -> {} to {}", self.dst, self.src, srtt);

        // RTTVAR
        self.rttvar = Some(rttvar);
        trace!(
            "set TCP RTTVAR of {} -> {} to {}",
            self.dst,
            self.src,
            rttvar
        );

        // RTO
        let rto_f = srtt + (rttvar * RTO_K).max(1.0);
        let rto = (rto_f * 1000.0).min(u64::MAX as f64) as u64;
        self.set_rto(rto);
    }

    /// Returns the source window of the TCP connection. The source window represents the received
    /// window from the source and indicates how much payload it can receive next.
    pub fn src_window(&self) -> usize {
        self.src_window
    }

    /// Returns the source window scale of the TCP connection.
    pub fn src_wscale(&self) -> Option<u8> {
        self.src_wscale
    }

    /// Returns if the SACK is permitted of the TCP connection.
    pub fn sack_perm(&self) -> bool {
        self.sack_perm
    }

    /// Returns the sequence of the TCP connection.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Returns the acknowledgement of the TCP connection.
    pub fn acknowledgement(&self) -> u32 {
        self.acknowledgement
    }

    /// Returns the window of the TCP connection.
    pub fn window(&self) -> u16 {
        self.window
    }

    /// Returns the half of the max window of the TCP connection.
    pub fn half_max_window(&self) -> u16 {
        RECV_WINDOW / 2
    }

    /// Returns the SACKs of the TCP connection.
    pub fn sacks(&self) -> &Option<Vec<(u32, u32)>> {
        &self.sacks
    }

    /// Returns if the TCP delayed ACK exists of the TCP connection.
    pub fn delayed_ack(&self) -> bool {
        self.delayed_ack
    }

    /// Returns the cache of the TCP connection.
    pub fn cache(&self) -> &Queue {
        &self.cache
    }

    /// Returns the mutable cache of the TCP connection.
    pub fn cache_mut(&mut self) -> &mut Queue {
        &mut self.cache
    }

    /// Returns the TCP SYN in the cache of the TCP connection.
    pub fn cache_syn(&self) -> Option<Instant> {
        self.cache_syn
    }

    /// Returns the TCP FIN in the cache of the TCP connection.
    pub fn cache_fin(&self) -> Option<Timer> {
        self.cache_fin
    }

    /// Returns the queue of the TCP connection.
    pub fn queue(&self) -> &VecDeque<u8> {
        &self.queue
    }

    /// Returns if the TCP FIN is in the queue of the TCP connection.
    pub fn queue_fin(&self) -> bool {
        self.queue_fin
    }

    /// Returns the remaining size of the queue of the TCP connection.
    pub fn queue_remaining(&self) -> usize {
        MAX_QUEUE.saturating_sub(self.queue().len())
    }

    /// Returns the RTO of the TCP connection.
    pub fn rto(&self) -> u64 {
        self.rto
    }

    /// Returns the next RTO of the TCP connection.
    pub fn next_rto(&self) -> u64 {
        max(MIN_RTO, self.rto.checked_mul(2).unwrap_or(MAX_RTO))
    }

    /// Returns the congestion control state of the TCP connection.
    pub fn cc(&self) -> &Option<Box<dyn TcpCc>> {
        &self.cc
    }

    /// Returns the mutable congestion control state of the TCP connection.
    pub fn cc_mut(&mut self) -> &mut Option<Box<dyn TcpCc>> {
        &mut self.cc
    }

    /// Returns the send window of the TCP connection. The send window is the minimum one between
    /// the congestion window and the source window.
    pub fn send_window(&self) -> usize {
        if let Some(cc) = &self.cc {
            min(cc.cwnd(), self.src_window)
        } else {
            self.src_window
        }
    }
}

impl Display for TcpTxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP TX State: {} -> {}", self.dst, self.src)
    }
}

/// Represents the RX state of a TCP connection.
#[derive(Debug)]
pub struct TcpRxState {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    recv_next: u32,
    acknowledgement: u32,
    duplicate: usize,
    last_retrans: Option<Instant>,
    wscale: u8,
    sack_perm: bool,
    cache: Window,
    fin_sequence: Option<u32>,
}

impl TcpRxState {
    /// Creates a new `TcpRxState`, the sequence is the sequence in the TCP SYN packet.
    pub fn new(
        src: SocketAddrV4,
        dst: SocketAddrV4,
        sequence: u32,
        wscale: u8,
        sack_perm: bool,
    ) -> TcpRxState {
        let recv_next = sequence.checked_add(1).unwrap_or(0);

        trace!("admit TCP SYN of {} -> {}", src, dst);

        TcpRxState {
            src,
            dst,
            recv_next,
            acknowledgement: 0,
            duplicate: 0,
            last_retrans: None,
            wscale,
            sack_perm,
            cache: Window::with_capacity((RECV_WINDOW as usize) << wscale as usize, recv_next),
            fin_sequence: None,
        }
    }

    /// Adds receive next to the TCP connection.
    #[allow(clippy::unnecessary_lazy_evaluations)]
    pub fn add_recv_next(&mut self, n: u32) {
        self.recv_next = self
            .recv_next
            .checked_add(n)
            .unwrap_or_else(|| n - (u32::MAX - self.recv_next));
        trace!(
            "add TCP receive next of {} -> {} to {}",
            self.src,
            self.dst,
            self.recv_next
        );
    }

    /// Admits the acknowledgement of the TCP connection.
    pub fn admit(&mut self, acknowledgement: u32) {
        if self.acknowledgement == acknowledgement {
            self.duplicate = self.duplicate.saturating_add(1);
            trace!(
                "increase TCP duplicate of {} -> {} at {} to {}",
                self.src,
                self.dst,
                acknowledgement,
                self.duplicate
            );
        } else {
            self.clear_duplicate();
            self.acknowledgement = acknowledgement;
            trace!(
                "admit TCP acknowledgement of {} -> {} at {} to {}",
                self.src,
                self.dst,
                acknowledgement,
                self.duplicate
            );
        }
    }

    fn clear_duplicate(&mut self) {
        self.duplicate = 0;
        trace!(
            "clear TCP duplicate of {} -> {} at {}",
            self.src,
            self.dst,
            self.acknowledgement
        );
    }

    fn update_last_retrans(&mut self) {
        self.last_retrans = Some(Instant::now());
        trace!(
            "update TCP last retransmission of {} -> {}",
            self.src,
            self.dst,
        );
    }

    /// Admits a retransmission of the TCP connection.
    pub fn admit_retrans(&mut self) {
        self.clear_duplicate();
        self.update_last_retrans();
    }

    /// Appends the payload to the cache of the TCP connection.
    pub fn append_cache(&mut self, sequence: u32, payload: &[u8]) -> io::Result<Option<Vec<u8>>> {
        trace!(
            "append {} Bytes to TCP cache of {} -> {}",
            payload.len(),
            self.src,
            self.dst
        );
        self.cache.append(sequence, payload)
    }

    /// Sets the TCP FIN sequence of the TCP connection.
    pub fn set_fin_sequence(&mut self, sequence: u32) {
        self.fin_sequence = Some(sequence);
        trace!(
            "set TCP FIN sequence of {} -> {} to {}",
            self.src,
            self.dst,
            sequence
        );
    }

    /// Admits the TCP FIN of the TCP connection.
    pub fn admit_fin(&mut self) {
        self.fin_sequence = None;
        trace!("admit TCP FIN of {} -> {}", self.src, self.dst);
    }

    /// Returns the receive next of the TCP connection.
    pub fn recv_next(&self) -> u32 {
        self.recv_next
    }

    /// Returns the duplicate acknowledgement count of the TCP connection.
    pub fn duplicate(&self) -> usize {
        self.duplicate
    }

    /// Returns the last retransmission of the TCP connection.
    pub fn last_retrans(&self) -> &Option<Instant> {
        &self.last_retrans
    }

    /// Returns the window scale of the TCP connection.
    pub fn wscale(&self) -> u8 {
        self.wscale
    }

    /// Returns if the SACK is permitted of the TCP connection.
    pub fn sack_perm(&self) -> bool {
        self.sack_perm
    }

    /// Return the cache of the TCP connection.
    pub fn cache(&self) -> &Window {
        &self.cache
    }

    /// Returns the TCP FIN sequence of the TCP connection.
    pub fn fin_sequence(&self) -> Option<u32> {
        self.fin_sequence
    }
}

impl Display for TcpRxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP RX State: {} -> {}", self.src, self.dst)
    }
}
