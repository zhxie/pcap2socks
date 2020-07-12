//! Support for handling SOCKS proxies.

use log::{debug, trace, warn};
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::prelude::*;
use tokio::time;

mod socks;
use self::socks::SocksSendHalf;

/// Trait for forwarding stream.
pub trait ForwardStream: Send {
    /// Forward stream.
    fn forward(&mut self, dst: SocketAddrV4, src_port: u16, payload: &[u8]) -> io::Result<()>;

    /// Close a stream connection.
    fn close(&mut self, dst: SocketAddrV4, src_port: u16) -> io::Result<()>;
}

/// Represents the wait time after a `TimedOut` `IoError`.
const TIMEDOUT_WAIT: u64 = 20;
/// Represents the wait time after receiving 0 byte from the stream.
const RECV_ZERO_WAIT: u64 = 100;
/// Represents the maximum count of receiving 0 byte from the stream before closing it.
const MAX_RECV_ZERO: usize = 3;

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
        src_port: u16,
        dst: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> io::Result<StreamWorker> {
        let stream = socks::connect(remote, dst).await?;
        let stream = stream.into_inner();
        let (mut stream_rx, stream_tx) = stream.into_split();

        let is_write_closed = Arc::new(AtomicBool::new(false));
        let is_write_closed_cloned = Arc::clone(&is_write_closed);
        let is_read_closed = Arc::new(AtomicBool::new(false));
        let is_read_closed_cloned = Arc::clone(&is_read_closed);
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

                                if let Err(ref e) = tx.lock().unwrap().close(dst, src_port) {
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
                        if let Err(ref e) =
                            tx.lock().unwrap().forward(dst, src_port, &buffer[..size])
                        {
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

        trace!("open stream {} -> {}", 0, dst);

        Ok(StreamWorker {
            dst,
            stream_tx: Some(stream_tx),
            is_write_closed,
            is_read_closed,
        })
    }

    /// Sends data on the SOCKS5 in TCP to the destination.
    pub async fn send(&mut self, buffer: &[u8]) -> io::Result<()> {
        debug!(
            "send to SOCKS {}: {} -> {} ({} Bytes)",
            "TCP",
            "0",
            self.dst,
            buffer.len()
        );

        // Send
        match &mut self.stream_tx {
            Some(tx) => tx.write_all(buffer).await,
            None => return Err(io::Error::from(io::ErrorKind::NotConnected)),
        }
    }

    /// Closes the write half of the worker, sends a TCP FIN to the other side.
    pub fn close_write(&mut self) {
        if !self.is_write_closed.load(Ordering::Relaxed) {
            self.stream_tx.take().unwrap().forget();
            self.is_write_closed.store(true, Ordering::Relaxed);
            trace!("close stream write {} -> {}", 0, self.dst);
        }
    }

    /// Closes the worker.
    pub fn close(&mut self) {
        self.close_write();
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
    fn forward(&mut self, dst: SocketAddrV4, src_port: u16, payload: &[u8]) -> io::Result<()>;
}

/// Represents a worker of a SOCKS5 UDP client.
pub struct DatagramWorker {
    src_port: Arc<AtomicU16>,
    local_port: u16,
    socks_tx: SocksSendHalf,
    is_closed: Arc<AtomicBool>,
}

impl DatagramWorker {
    /// Creates a new `DatagramWorker`.
    pub async fn bind(
        tx: Arc<Mutex<dyn ForwardDatagram>>,
        src_port: u16,
        remote: SocketAddrV4,
    ) -> io::Result<(DatagramWorker, u16)> {
        let (mut socks_rx, socks_tx, local_port) = socks::bind(remote).await?;

        let a_src_port = Arc::new(AtomicU16::from(src_port));
        let a_src_port_cloned = Arc::clone(&a_src_port);
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
                            a_src_port_cloned.load(Ordering::Relaxed),
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
                            a_src_port_cloned.load(Ordering::Relaxed),
                            e
                        );
                        is_closed_cloned.store(true, Ordering::Relaxed);

                        break;
                    }
                }
            }
        });

        trace!("create datagram {} = {}", src_port, local_port);

        Ok((
            DatagramWorker {
                src_port: a_src_port,
                local_port,
                socks_tx,
                is_closed: is_closed,
            },
            local_port,
        ))
    }

    /// Sends data on the SOCKS5 in UDP to the destination.
    pub async fn send_to(&mut self, buffer: &[u8], dst: SocketAddrV4) -> io::Result<usize> {
        debug!(
            "send to SOCKS {}: {} -> {} ({} Bytes)",
            "UDP",
            self.local_port,
            dst,
            buffer.len()
        );

        // Send
        self.socks_tx.send_to(buffer, dst).await
    }

    /// Sets the source port of the `DatagramWorker`.
    pub fn set_src_port(&mut self, src_port: u16) {
        self.src_port.store(src_port, Ordering::Relaxed);
        trace!("set datagram {} = {}", src_port, self.local_port);
    }

    /// Get the source port of the `DatagramWorker`.
    pub fn src_port(&self) -> u16 {
        self.src_port.load(Ordering::Relaxed)
    }

    /// Returns if the worker is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }
}
