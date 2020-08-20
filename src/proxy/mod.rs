//! Support for handling proxies.

use futures::{self, FutureExt};
use log::{debug, trace, warn};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::prelude::*;
use tokio::sync::mpsc::{self, Sender};
use tokio::time;

mod socks;
use socks::SocksSendHalf;
use socks::{SocksAuth, SocksOption};

/// Represents the configuration of the proxy.
pub enum ProxyConfig {
    /// Represents the SOCKS proxy configuration.
    Socks(SocketAddrV4, SocksOption),
}

impl ProxyConfig {
    /// Creates a new SOCKS `ProxyConfig`.
    pub fn new_socks(
        remote: SocketAddrV4,
        force_associate_remote: bool,
        force_associate_bind_addr: bool,
        auth: Option<(String, String)>,
    ) -> ProxyConfig {
        ProxyConfig::Socks(
            remote,
            SocksOption::new(
                force_associate_remote,
                force_associate_bind_addr,
                match auth {
                    Some((username, password)) => Some(SocksAuth::new(username, password)),
                    None => None,
                },
            ),
        )
    }
}

/// Trait for forwarding a stream.
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

enum StreamWorkerEvent {
    Recv(usize),
    Timeout,
    Close,
}

/// Represents a worker of a proxied TCP stream.
pub struct StreamWorker {
    dst: SocketAddrV4,
    stream_tx: Option<OwnedWriteHalf>,
    is_tx_closed: Arc<AtomicBool>,
    is_rx_closed: Arc<AtomicBool>,
    rx_close_tx: Sender<()>,
}

impl StreamWorker {
    /// Opens a new `StreamWorker`.
    pub async fn connect(
        tx: Arc<Mutex<dyn ForwardStream>>,
        src: SocketAddrV4,
        dst: SocketAddrV4,
        proxy: &ProxyConfig,
    ) -> io::Result<StreamWorker> {
        let tx_cloned = Arc::clone(&tx);

        let stream = match proxy {
            ProxyConfig::Socks(remote, options) => {
                socks::connect(remote.clone(), dst, options).await?
            }
        };
        let stream = stream.into_inner();
        let (mut stream_rx, stream_tx) = stream.into_split();

        // Open
        tx_cloned.lock().unwrap().open(dst, src)?;

        let is_tx_closed = Arc::new(AtomicBool::new(false));
        let is_tx_closed_cloned = Arc::clone(&is_tx_closed);
        let is_rx_closed = Arc::new(AtomicBool::new(false));
        let is_rx_closed_cloned = Arc::clone(&is_rx_closed);
        let (mut timeout_tx, mut timeout_rx) = mpsc::channel(1);
        let (rx_close_tx, mut rx_close_rx) = mpsc::channel(1);
        tokio::spawn(async move {
            let mut interval = time::interval(time::Duration::from_millis(TICK_INTERVAL));
            loop {
                interval.tick().await;
                if let Err(_) = timeout_tx.send(()).await {
                    return;
                }
            }
        });
        tokio::spawn(async move {
            let mut buffer = vec![0u8; u16::MAX as usize];
            let mut recv_zero = 0;
            loop {
                let event;

                // Select
                {
                    let rx_close_rx_fuse = rx_close_rx.recv().fuse();
                    let stream_rx_fuse = stream_rx.read(&mut buffer).fuse();
                    let timeout_fuse = timeout_rx.recv().fuse();

                    futures::pin_mut!(rx_close_rx_fuse, stream_rx_fuse, timeout_fuse);

                    futures::select! {
                        _ = rx_close_rx_fuse => {
                            event = StreamWorkerEvent::Close;
                        },
                        stream_rx_result = stream_rx_fuse => match stream_rx_result {
                            Ok(size) => event = StreamWorkerEvent::Recv(size),
                            Err(ref e) => {
                                if e.kind() == io::ErrorKind::TimedOut {
                                    time::delay_for(Duration::from_millis(TIMEDOUT_WAIT)).await;
                                    continue;
                                }
                                warn!("proxy: {}: {} -> {}: {}", "TCP", 0, dst, e);

                                is_tx_closed_cloned.store(true, Ordering::Relaxed);
                                event = StreamWorkerEvent::Close;
                            }
                        },
                        _ = timeout_fuse => {
                            // Tick
                            trace!("tick on {} -> {}", dst, 0);

                            event = StreamWorkerEvent::Timeout;
                        }
                    }
                }

                // TODO: race condition may be appeared
                match event {
                    StreamWorkerEvent::Recv(size) => {
                        if size == 0 {
                            recv_zero += 1;
                            if recv_zero > MAX_RECV_ZERO {
                                // Close by remote
                                trace!("close stream RX {} -> {}", dst, 0);

                                if let Err(ref e) = tx.lock().unwrap().close(dst, src) {
                                    warn!("handle {} closing: {} -> {}: {}", "TCP", dst, 0, e)
                                }

                                is_rx_closed_cloned.store(true, Ordering::Relaxed);
                                break;
                            }
                            time::delay_for(Duration::from_millis(RECV_ZERO_WAIT)).await;
                            continue;
                        }
                        recv_zero = 0;
                        debug!(
                            "receive from proxy: {}: {} -> {} ({} Bytes)",
                            "TCP", dst, 0, size
                        );

                        // Send
                        if let Err(ref e) = tx.lock().unwrap().forward(dst, src, &buffer[..size]) {
                            warn!("handle {}: {} -> {}: {}", "TCP", dst, 0, e);
                        }
                    }
                    StreamWorkerEvent::Timeout => {
                        // Send
                        if let Err(ref e) = tx_cloned.lock().unwrap().tick(dst, src) {
                            warn!("handle {} timeout: {} -> {}: {}", "TCP", dst, 0, e);
                        }
                    }
                    StreamWorkerEvent::Close => {
                        is_rx_closed_cloned.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });

        trace!("open stream {} -> {}", 0, dst);

        Ok(StreamWorker {
            dst,
            stream_tx: Some(stream_tx),
            is_tx_closed,
            is_rx_closed,
            rx_close_tx,
        })
    }

    /// Sends data on the proxied stream in TCP to the destination.
    pub async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        debug!(
            "send to proxy {}: {} -> {} ({} Bytes)",
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

    /// Shuts down the read, write, or both halves of the worker.
    pub fn shutdown(&mut self, how: Shutdown) {
        match how {
            Shutdown::Write => {
                if !self.is_tx_closed.load(Ordering::Relaxed) {
                    self.is_tx_closed.store(true, Ordering::Relaxed);
                    self.stream_tx.take().unwrap().forget();
                    trace!("close stream TX {} -> {}", 0, self.dst);
                }
            }
            _ => unreachable!(),
        }
    }

    /// Attempts to immediately shut down the read, write, or both halves of the worker.
    pub fn try_shutdown(&mut self, how: Shutdown) {
        match how {
            Shutdown::Write => self.shutdown(Shutdown::Write),
            Shutdown::Read => {
                if !self.is_rx_closed.load(Ordering::Relaxed) {
                    let _ = self.rx_close_tx.try_send(());
                }
            }
            Shutdown::Both => {
                self.shutdown(Shutdown::Write);
                self.try_shutdown(Shutdown::Read);
            }
        }
    }

    /// Attempts to immediately close the worker.
    pub fn try_close(&mut self) {
        self.try_shutdown(Shutdown::Both);
    }

    /// Returns if the worker is closed for writing.
    pub fn is_tx_closed(&self) -> bool {
        self.is_tx_closed.load(Ordering::Relaxed)
    }

    /// Returns if the worker is closed for reading.
    pub fn is_rx_closed(&self) -> bool {
        self.is_rx_closed.load(Ordering::Relaxed)
    }
}

impl Drop for StreamWorker {
    fn drop(&mut self) {
        self.try_close();
        trace!("drop stream {} -> {}", 0, self.dst);
    }
}

/// Trait for forwarding a datagram.
pub trait ForwardDatagram: Send {
    /// Forwards datagram.
    fn forward(&mut self, dst: SocketAddrV4, src: SocketAddrV4, payload: &[u8]) -> io::Result<()>;
}

enum DatagramWorkerEvent {
    Recv(usize, SocketAddrV4),
    Close,
}

/// Represents a worker of a proxied UDP datagram.
pub struct DatagramWorker {
    src: Arc<AtomicU64>,
    local_port: u16,
    socks_tx: SocksSendHalf,
    is_closed: Arc<AtomicBool>,
    close_tx: Sender<()>,
}

impl DatagramWorker {
    /// Creates a new `DatagramWorker`.
    pub async fn bind(
        tx: Arc<Mutex<dyn ForwardDatagram>>,
        src: SocketAddrV4,
        proxy: &ProxyConfig,
    ) -> io::Result<(DatagramWorker, u16)> {
        let (mut socks_rx, socks_tx, local_port) = match proxy {
            ProxyConfig::Socks(remote, options) => socks::bind(remote.clone(), options).await?,
        };

        let a_src = Arc::new(AtomicU64::from(socket_addr_v4_to_u64(&src)));
        let a_src_cloned = Arc::clone(&a_src);
        let is_closed = Arc::new(AtomicBool::new(false));
        let is_closed_cloned = Arc::clone(&is_closed);
        let (close_tx, mut close_rx) = mpsc::channel(1);
        tokio::spawn(async move {
            let mut buffer = vec![0u8; u16::MAX as usize];
            loop {
                let event;

                // Select
                {
                    let close_rx_fuse = close_rx.recv().fuse();
                    let socks_rx_fuse = socks_rx.recv_from(&mut buffer).fuse();

                    futures::pin_mut!(close_rx_fuse, socks_rx_fuse);

                    futures::select! {
                        _ = close_rx_fuse => {
                            event = DatagramWorkerEvent::Close;
                        },
                        socks_rx_result = socks_rx_fuse => {
                            match socks_rx_result {
                                Ok((size, addr)) => event = DatagramWorkerEvent::Recv(size, addr),
                                Err(ref e) => {
                                    if e.kind() == io::ErrorKind::TimedOut {
                                        time::delay_for(Duration::from_millis(TIMEDOUT_WAIT)).await;
                                        continue;
                                    }
                                    warn!(
                                        "proxy: {}: {} = {}: {}",
                                        "UDP",
                                        local_port,
                                        u64_to_socket_addr_v4(a_src_cloned.load(Ordering::Relaxed)),
                                        e
                                    );

                                    event = DatagramWorkerEvent::Close;
                                }
                            }
                        }
                    };
                }

                // TODO: race condition may be appeared
                match event {
                    DatagramWorkerEvent::Recv(size, addr) => {
                        // Send
                        debug!(
                            "receive from proxy: {}: {} -> {} ({} Bytes)",
                            "UDP", addr, local_port, size
                        );

                        if let Err(ref e) = tx.lock().unwrap().forward(
                            addr,
                            u64_to_socket_addr_v4(a_src_cloned.load(Ordering::Relaxed)),
                            &buffer[..size],
                        ) {
                            warn!("handle {}: {} -> {}: {}", "UDP", addr, local_port, e);
                        }
                    }
                    DatagramWorkerEvent::Close => {
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
                close_tx,
            },
            local_port,
        ))
    }

    /// Sends data on the proxied datagram in UDP to the destination.
    pub async fn send_to(&mut self, payload: &[u8], dst: SocketAddrV4) -> io::Result<usize> {
        debug!(
            "send to proxy {}: {} -> {} ({} Bytes)",
            "UDP",
            self.local_port,
            dst,
            payload.len()
        );

        // Send
        self.socks_tx.send_to(payload, dst).await
    }

    /// Sets the source of the worker.
    pub fn set_src(&mut self, src: &SocketAddrV4) {
        self.src
            .store(socket_addr_v4_to_u64(src), Ordering::Relaxed);
        trace!("set datagram {} = {}", src, self.local_port);
    }

    /// Returns the source of the worker.
    pub fn src(&self) -> SocketAddrV4 {
        u64_to_socket_addr_v4(self.src.load(Ordering::Relaxed))
    }

    /// Returns if the worker is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }
}

impl Drop for DatagramWorker {
    fn drop(&mut self) {
        let _ = self.close_tx.try_send(());
        trace!("drop datagram {} = {}", self.src(), self.local_port);
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
