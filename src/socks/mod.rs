//! Support for handling SOCKS proxies.

use log::{debug, trace, warn};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::prelude::*;
use tokio::time;

mod socks;
use self::socks::SocksSendHalf;
pub use self::socks::{SocksAuth, SocksOption};

/// Trait for forwarding stream.
pub trait ForwardStream: Send {
    /// Opens a stream connection.
    fn open(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<()>;

    /// Forwards stream.
    fn forward(&mut self, dst: SocketAddrV4, src: SocketAddrV4, payload: &[u8]) -> io::Result<()>;

    /// Triggers a timed event. Used in retransmitting timed out data.
    fn tick(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<()>;

    /// Closes a stream connection.
    fn close(&mut self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<()>;
}

/// Represents the wait time after a `TimedOut` `IoError`.
const TIMEDOUT_WAIT: u64 = 20;

/// Represents the wait time after receiving 0 byte from the stream.
const RECV_ZERO_WAIT: u64 = 100;
/// Represents the maximum count of receiving 0 byte from the stream before closing it.
const MAX_RECV_ZERO: usize = 3;

/// Represents the interval of a tick.
const TICK_INTERVAL: u64 = 1000;

/// Represents a worker of a SOCKS5 TCP stream.
pub struct StreamWorker {
    dst: SocketAddrV4,
    stream_tx: Option<OwnedWriteHalf>,
    is_write_closed: Arc<AtomicBool>,
    is_read_closed: Arc<AtomicBool>,
}

impl StreamWorker {
    /// Opens a new `StreamWorker`.
    pub async fn connect(
        tx: Arc<Mutex<dyn ForwardStream>>,
        src: SocketAddrV4,
        dst: SocketAddrV4,
        remote: SocketAddrV4,
        options: &SocksOption,
    ) -> io::Result<StreamWorker> {
        let tx_cloned = Arc::clone(&tx);

        let stream = socks::connect(remote, dst, &options).await?;
        let stream = stream.into_inner();
        let (mut stream_rx, stream_tx) = stream.into_split();

        let is_write_closed = Arc::new(AtomicBool::new(false));
        let is_write_closed_cloned = Arc::clone(&is_write_closed);
        let is_read_closed = Arc::new(AtomicBool::new(false));
        let is_read_closed_cloned = Arc::clone(&is_read_closed);
        let is_read_closed_cloned2 = Arc::clone(&is_read_closed);

        // Open
        tx_cloned.lock().unwrap().open(dst, src)?;

        // Forward
        tokio::spawn(async move {
            let mut buffer = vec![0u8; u16::MAX as usize];
            let mut recv_zero = 0;
            loop {
                if is_read_closed_cloned.load(Ordering::Relaxed) {
                    break;
                }
                match stream_rx.read(&mut buffer).await {
                    Ok(size) => {
                        if is_read_closed_cloned.load(Ordering::Relaxed) {
                            break;
                        }
                        if size == 0 {
                            recv_zero += 1;
                            if recv_zero > MAX_RECV_ZERO {
                                // Close by remote
                                trace!("close stream read {} -> {}", dst, 0);

                                if let Err(ref e) = tx.lock().unwrap().close(dst, src) {
                                    warn!("handle {}: {}", "TCP", e)
                                }
                                is_read_closed_cloned.store(true, Ordering::Relaxed);
                                break;
                            }
                            time::delay_for(Duration::from_millis(RECV_ZERO_WAIT)).await;
                            continue;
                        }
                        recv_zero = 0;
                        debug!(
                            "receive from SOCKS: {}: {} -> {} ({} Bytes)",
                            "TCP", dst, 0, size
                        );

                        // Send
                        if let Err(ref e) = tx.lock().unwrap().forward(dst, src, &buffer[..size]) {
                            warn!("handle {}: {}", "TCP", e);
                        }
                    }
                    Err(ref e) => {
                        if e.kind() == io::ErrorKind::TimedOut {
                            time::delay_for(Duration::from_millis(TIMEDOUT_WAIT)).await;
                            continue;
                        }
                        warn!("SOCKS: {}: {} -> {}: {}", "TCP", 0, dst, e);
                        is_read_closed_cloned.store(true, Ordering::Relaxed);
                        is_write_closed_cloned.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });

        // Triggers sending timed out data
        tokio::spawn(async move {
            loop {
                if is_read_closed_cloned2.load(Ordering::Relaxed) {
                    break;
                }
                // Tick
                trace!("tick on {} -> {}", dst, 0);

                if let Err(ref e) = tx_cloned.lock().unwrap().tick(dst, src) {
                    warn!("handle {}: {}", "TCP", e);
                }
                if is_read_closed_cloned2.load(Ordering::Relaxed) {
                    break;
                }

                time::delay_for(Duration::from_millis(TICK_INTERVAL)).await;
            }
        });

        trace!("open stream {} -> {}", 0, dst);

        Ok(StreamWorker {
            dst,
            stream_tx: Some(stream_tx),
            is_write_closed,
            is_read_closed,
        })
    }

    /// Sends data on the SOCKS5 in TCP to the destination.
    pub async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        debug!(
            "send to SOCKS {}: {} -> {} ({} Bytes)",
            "TCP",
            "0",
            self.dst,
            payload.len()
        );

        // Send
        match &mut self.stream_tx {
            Some(tx) => tx.write_all(payload).await,
            None => return Err(io::Error::from(io::ErrorKind::NotConnected)),
        }
    }

    /// Shuts down the read, write, or both halves of this connection.
    pub fn shutdown(&mut self, how: Shutdown) {
        match how {
            Shutdown::Write => {
                if !self.is_write_closed.load(Ordering::Relaxed) {
                    self.stream_tx.take().unwrap().forget();
                    self.is_write_closed.store(true, Ordering::Relaxed);
                    trace!("close stream write {} -> {}", 0, self.dst);
                }
            }
            _ => unreachable!(),
        }
    }

    /// Closes the worker.
    pub fn close(&mut self) {
        self.shutdown(Shutdown::Write);
        self.is_read_closed.store(true, Ordering::Relaxed);
    }

    /// Returns if the worker is closed for writing.
    pub fn is_write_closed(&self) -> bool {
        self.is_write_closed.load(Ordering::Relaxed)
    }

    /// Returns if the worker is closed for reading.
    pub fn is_read_closed(&self) -> bool {
        self.is_read_closed.load(Ordering::Relaxed)
    }
}

impl Drop for StreamWorker {
    fn drop(&mut self) {
        self.close();
        trace!("drop stream {} -> {}", 0, self.dst);
    }
}

/// Trait for forwarding datagram.
pub trait ForwardDatagram: Send {
    /// Forwards datagram.
    fn forward(&mut self, dst: SocketAddrV4, src: SocketAddrV4, payload: &[u8]) -> io::Result<()>;
}

/// Represents a worker of a SOCKS5 UDP client.
pub struct DatagramWorker {
    src: Arc<AtomicU64>,
    local_port: u16,
    socks_tx: SocksSendHalf,
    is_closed: Arc<AtomicBool>,
}

impl DatagramWorker {
    /// Creates a new `DatagramWorker`.
    pub async fn bind(
        tx: Arc<Mutex<dyn ForwardDatagram>>,
        src: SocketAddrV4,
        remote: SocketAddrV4,
        options: &SocksOption,
    ) -> io::Result<(DatagramWorker, u16)> {
        let (mut socks_rx, socks_tx, local_port) = socks::bind(remote, &options).await?;

        let a_src = Arc::new(AtomicU64::from(socket_addr_v4_to_u64(&src)));
        let a_src_cloned = Arc::clone(&a_src);
        let is_closed = Arc::new(AtomicBool::new(false));
        let is_closed_cloned = Arc::clone(&is_closed);
        tokio::spawn(async move {
            let mut buffer = vec![0u8; u16::MAX as usize];
            loop {
                if is_closed_cloned.load(Ordering::Relaxed) {
                    break;
                }
                match socks_rx.recv_from(&mut buffer).await {
                    Ok((size, addr)) => {
                        if is_closed_cloned.load(Ordering::Relaxed) {
                            break;
                        }
                        debug!(
                            "receive from SOCKS: {}: {} -> {} ({} Bytes)",
                            "UDP", addr, local_port, size
                        );

                        // Send
                        if let Err(ref e) = tx.lock().unwrap().forward(
                            addr,
                            u64_to_socket_addr_v4(a_src_cloned.load(Ordering::Relaxed)),
                            &buffer[..size],
                        ) {
                            warn!("handle {}: {}", "UDP", e);
                        }
                    }
                    Err(ref e) => {
                        if e.kind() == io::ErrorKind::TimedOut {
                            time::delay_for(Duration::from_millis(TIMEDOUT_WAIT)).await;
                            continue;
                        }
                        warn!(
                            "SOCKS: {}: {} = {}: {}",
                            "UDP",
                            local_port,
                            u64_to_socket_addr_v4(a_src_cloned.load(Ordering::Relaxed)),
                            e
                        );
                        is_closed_cloned.store(true, Ordering::Relaxed);

                        break;
                    }
                }
            }
        });

        trace!("create datagram {} = {}", src, local_port);

        Ok((
            DatagramWorker {
                src: a_src,
                local_port,
                socks_tx,
                is_closed,
            },
            local_port,
        ))
    }

    /// Sends data on the SOCKS5 in UDP to the destination.
    pub async fn send_to(&mut self, payload: &[u8], dst: SocketAddrV4) -> io::Result<usize> {
        debug!(
            "send to SOCKS {}: {} -> {} ({} Bytes)",
            "UDP",
            self.local_port,
            dst,
            payload.len()
        );

        // Send
        self.socks_tx.send_to(payload, dst).await
    }

    /// Sets the source of the `DatagramWorker`.
    pub fn set_src(&mut self, src: &SocketAddrV4) {
        self.src
            .store(socket_addr_v4_to_u64(src), Ordering::Relaxed);
        trace!("set datagram {} = {}", src, self.local_port);
    }

    /// Returns the source of the `DatagramWorker`.
    pub fn src(&self) -> SocketAddrV4 {
        u64_to_socket_addr_v4(self.src.load(Ordering::Relaxed))
    }

    /// Returns if the worker is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }
}

fn socket_addr_v4_to_u64(addr: &SocketAddrV4) -> u64 {
    let ip = u32::from(addr.ip().clone());

    ((ip as u64) << 16) + addr.port() as u64
}

fn u64_to_socket_addr_v4(v: u64) -> SocketAddrV4 {
    let port = v as u16;
    let ip = (v >> 16) as u32;
    let ip = Ipv4Addr::from(ip);

    SocketAddrV4::new(ip, port)
}
