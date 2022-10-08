//! Support for handling proxies.

use log::{debug, trace, warn};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};
use tokio::{self, io, time};

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
                auth.map(|(username, password)| SocksAuth::new(username, password)),
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

    /// Checks the stream.
    fn check(&self, dst: SocketAddrV4, src: SocketAddrV4) -> io::Result<usize>;
}

/// Represents the wait time after a `TimedOut` `IoError`.
const TIMEDOUT_WAIT: u64 = 20;
/// Represents the wait time after a queue full event.
const QUEUE_FULL_WAIT: u64 = 200;

/// Represents the wait time after receiving 0 byte from the stream.
const RECV_ZERO_WAIT: u64 = 100;
/// Represents the maximum count of receiving 0 byte from the stream before closing it.
const MAX_RECV_ZERO: usize = 3;

/// Represents the interval of a tick.
const TICK_INTERVAL: u64 = 500;

/// Represents a worker of a proxied TCP stream.
pub struct StreamWorker {
    dst: SocketAddrV4,
    tx_tx: UnboundedSender<Vec<u8>>,
    is_tx_closed: Arc<AtomicBool>,
    is_rx_closed: Arc<AtomicBool>,
    tx_close_tx: Sender<()>,
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
                socks::connect(*remote, dst, options).await?
            }
        };
        let stream = stream.into_inner();
        let (mut stream_rx, mut stream_tx) = stream.into_split();

        // Open
        tx.lock().unwrap().open(dst, src)?;

        let (tx_tx, mut tx_rx): (UnboundedSender<Vec<u8>>, UnboundedReceiver<Vec<u8>>) =
            mpsc::unbounded_channel();
        let is_tx_closed = Arc::new(AtomicBool::new(false));
        let is_tx_closed_cloned = Arc::clone(&is_tx_closed);
        let is_rx_closed = Arc::new(AtomicBool::new(false));
        let is_rx_closed_cloned = Arc::clone(&is_rx_closed);
        let (tx_close_tx, mut tx_close_rx) = mpsc::channel(1);
        let (rx_close_tx, mut rx_close_rx) = mpsc::channel(1);

        // Send
        tokio::spawn(async move {
            loop {
                let is_close;

                // Select
                {
                    let tx_rx_fut = tx_rx.recv();
                    let tx_close_rx_fut = tx_close_rx.recv();

                    tokio::pin!(tx_rx_fut, tx_close_rx_fut);

                    tokio::select! {
                        r = tx_rx_fut => match r {
                            Some(payload) => {
                                match stream_tx.write_all(payload.as_slice()).await {
                                    Ok(_) => {
                                        debug!(
                                            "send to proxy: {}: {} -> {} ({} Bytes)",
                                            "TCP", 0, dst, payload.len()
                                        );

                                        is_close = false
                                    },
                                    Err(ref e) => {
                                        warn!("handle send: {}: {} -> {}: {}", "TCP", 0, dst, e);

                                        is_close = true
                                    }
                                };
                            }
                            None => is_close = true
                        },
                        _ = tx_close_rx_fut => is_close = true
                    }
                }

                if is_close {
                    // Close
                    is_tx_closed_cloned.store(true, Ordering::Relaxed);
                    trace!("close stream TX {} -> {}", 0, dst);
                    break;
                }
            }
        });

        // Receive
        tokio::spawn(async move {
            let mut buffer = vec![0u8; u16::MAX as usize];
            let mut recv_zero: usize = 0;
            loop {
                let size;

                // Select
                {
                    let stream_rx_fut = stream_rx.read(&mut buffer);
                    let rx_close_rx_fut = rx_close_rx.recv();

                    tokio::pin!(stream_rx_fut, rx_close_rx_fut);

                    tokio::select! {
                        r = stream_rx_fut => match r {
                            Ok(this_size) => if this_size > 0 {
                                debug!(
                                    "receive from proxy: {}: {} -> {} ({} Bytes)",
                                    "TCP", dst, 0, this_size
                                );

                                size = this_size;
                            } else {
                                recv_zero = recv_zero.checked_add(1).unwrap_or(usize::MAX);
                                if recv_zero > MAX_RECV_ZERO {
                                    size = 0;
                                } else {
                                    time::sleep(Duration::from_millis(RECV_ZERO_WAIT)).await;
                                    continue;
                                }
                            },
                            Err(ref e) => {
                                if e.kind() == io::ErrorKind::TimedOut {
                                    time::sleep(Duration::from_millis(TIMEDOUT_WAIT)).await;
                                    continue;
                                }

                                warn!("receive from proxy: {}: {} -> {}: {}", "TCP", dst, 0, e);

                                size = 0;
                            }
                        },
                        _ = rx_close_rx_fut => size = 0
                    }
                }

                if size > 0 {
                    // Loop until the data was transferred to the forwarder
                    let mut is_sent = false;
                    loop {
                        {
                            let mut tx_locked = tx.lock().unwrap();
                            match tx_locked.check(dst, src) {
                                Ok(remaining) => {
                                    // If the queue remains size
                                    if remaining >= size {
                                        if let Err(ref e) =
                                            tx_locked.forward(dst, src, &buffer[..size])
                                        {
                                            warn!(
                                                "handle receive: {}: {} -> {}: {}",
                                                "TCP", dst, 0, e
                                            );
                                        }
                                        is_sent = true;
                                    }
                                }
                                Err(ref e) => {
                                    is_sent = true;
                                    warn!("handle receive: {}: {} -> {}: {}", "TCP", dst, 0, e)
                                }
                            }
                        }

                        if is_sent {
                            break;
                        } else {
                            // Pause if the queue is full
                            time::sleep(Duration::from_millis(QUEUE_FULL_WAIT)).await;
                        }
                    }
                } else {
                    // Close
                    is_rx_closed_cloned.store(true, Ordering::Relaxed);
                    trace!("close stream RX {} -> {}", dst, 0);

                    if let Err(ref e) = tx.lock().unwrap().close(dst, src) {
                        warn!("handle close: {}: {} -> {}: {}", "TCP", dst, 0, e);
                    }

                    break;
                }
            }
        });

        // Timeout
        tokio::spawn(async move {
            loop {
                time::sleep(Duration::from_millis(TICK_INTERVAL)).await;
                // Send
                if let Err(ref e) = tx_cloned.lock().unwrap().tick(dst, src) {
                    if e.kind() == io::ErrorKind::NotFound {
                        return;
                    }
                    warn!("handle timeout: {}: {} -> {}: {}", "TCP", dst, 0, e);
                }
            }
        });

        trace!("open stream {} -> {}", 0, dst);

        Ok(StreamWorker {
            dst,
            tx_tx,
            is_tx_closed,
            is_rx_closed,
            tx_close_tx,
            rx_close_tx,
        })
    }

    /// Sends data on the proxied stream in TCP to the destination.
    pub fn send(&mut self, payload: Vec<u8>) -> io::Result<()> {
        // Send
        if self.tx_tx.send(payload).is_err() {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }

        Ok(())
    }

    /// Shuts down the read, write, or both halves of the worker.
    pub fn shutdown(&mut self, how: Shutdown) {
        match how {
            Shutdown::Write => {
                if !self.is_tx_closed.load(Ordering::Relaxed) {
                    let _ = self.tx_close_tx.try_send(());
                }
            }
            Shutdown::Read => {
                if !self.is_rx_closed.load(Ordering::Relaxed) {
                    let _ = self.rx_close_tx.try_send(());
                }
            }
            Shutdown::Both => {
                self.shutdown(Shutdown::Write);
                self.shutdown(Shutdown::Read);
            }
        }
    }

    /// Closes the worker.
    pub fn close(&mut self) {
        self.shutdown(Shutdown::Both);
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
        self.close();
        trace!("drop stream {} -> {}", 0, self.dst);
    }
}

/// Represents a worker of a proxied TCP stream. Comparing with `StreamWorker`, `StreamWorker2` do
/// not require the ownership of the sent payload, but have to wait until the payload was sent.
pub struct StreamWorker2 {
    dst: SocketAddrV4,
    stream_tx: Option<OwnedWriteHalf>,
    is_tx_closed: Arc<AtomicBool>,
    is_rx_closed: Arc<AtomicBool>,
    rx_close_tx: Sender<()>,
}

impl StreamWorker2 {
    /// Opens a new `StreamWorker2`.
    pub async fn connect(
        tx: Arc<Mutex<dyn ForwardStream>>,
        src: SocketAddrV4,
        dst: SocketAddrV4,
        proxy: &ProxyConfig,
    ) -> io::Result<StreamWorker2> {
        let tx_cloned = Arc::clone(&tx);

        let stream = match proxy {
            ProxyConfig::Socks(remote, options) => {
                socks::connect(*remote, dst, options).await?
            }
        };
        let stream = stream.into_inner();
        let (mut stream_rx, stream_tx) = stream.into_split();

        // Open
        tx.lock().unwrap().open(dst, src)?;

        let is_tx_closed = Arc::new(AtomicBool::new(false));
        let is_rx_closed = Arc::new(AtomicBool::new(false));
        let is_rx_closed_cloned = Arc::clone(&is_rx_closed);
        let (rx_close_tx, mut rx_close_rx) = mpsc::channel(1);

        // Receive
        tokio::spawn(async move {
            let mut buffer = vec![0u8; u16::MAX as usize];
            let mut recv_zero: usize = 0;
            loop {
                let size;

                // Select
                {
                    let stream_rx_fut = stream_rx.read(&mut buffer);
                    let rx_close_rx_fut = rx_close_rx.recv();

                    tokio::pin!(stream_rx_fut, rx_close_rx_fut);

                    tokio::select! {
                        r = stream_rx_fut => match r {
                            Ok(this_size) => if this_size > 0 {
                                debug!(
                                    "receive from proxy: {}: {} -> {} ({} Bytes)",
                                    "TCP", dst, 0, this_size
                                );

                                size = this_size;
                            } else {
                                recv_zero = recv_zero.checked_add(1).unwrap_or(usize::MAX);
                                if recv_zero > MAX_RECV_ZERO {
                                    size = 0;
                                } else {
                                    time::sleep(Duration::from_millis(RECV_ZERO_WAIT)).await;
                                    continue;
                                }
                            },
                            Err(ref e) => {
                                if e.kind() == io::ErrorKind::TimedOut {
                                    time::sleep(Duration::from_millis(TIMEDOUT_WAIT)).await;
                                    continue;
                                }

                                warn!("receive from proxy: {}: {} -> {}: {}", "TCP", dst, 0, e);

                                size = 0;
                            }
                        },
                        _ = rx_close_rx_fut => size = 0
                    }
                }

                if size > 0 {
                    if let Err(ref e) = tx.lock().unwrap().forward(dst, src, &buffer[..size]) {
                        warn!("handle receive: {}: {} -> {}: {}", "TCP", dst, 0, e);
                    }
                } else {
                    // Close
                    is_rx_closed_cloned.store(true, Ordering::Relaxed);
                    trace!("close stream RX {} -> {}", dst, 0);

                    if let Err(ref e) = tx.lock().unwrap().close(dst, src) {
                        warn!("handle close: {}: {} -> {}: {}", "TCP", dst, 0, e);
                    }

                    break;
                }
            }
        });

        // Timeout
        tokio::spawn(async move {
            loop {
                time::sleep(Duration::from_millis(TICK_INTERVAL)).await;
                // Send
                if let Err(ref e) = tx_cloned.lock().unwrap().tick(dst, src) {
                    if e.kind() == io::ErrorKind::NotFound {
                        return;
                    }
                    warn!("handle timeout: {}: {} -> {}: {}", "TCP", dst, 0, e);
                }
            }
        });

        trace!("open stream {} -> {}", 0, dst);

        Ok(StreamWorker2 {
            dst,
            stream_tx: Some(stream_tx),
            is_tx_closed,
            is_rx_closed,
            rx_close_tx,
        })
    }

    /// Sends data on the proxied stream in TCP to the destination.
    pub async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        // Send
        match &mut self.stream_tx {
            Some(tx) => tx.write_all(payload).await?,
            None => return Err(io::Error::from(io::ErrorKind::NotConnected)),
        }
        debug!(
            "send to proxy: {}: {} -> {} ({} Bytes)",
            "TCP",
            "0",
            self.dst,
            payload.len()
        );

        Ok(())
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
            Shutdown::Read => {
                if !self.is_rx_closed.load(Ordering::Relaxed) {
                    let _ = self.rx_close_tx.try_send(());
                }
            }
            Shutdown::Both => {
                self.shutdown(Shutdown::Write);
                self.shutdown(Shutdown::Read);
            }
        }
    }

    /// Closes the worker.
    pub fn close(&mut self) {
        self.shutdown(Shutdown::Both);
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

impl Drop for StreamWorker2 {
    fn drop(&mut self) {
        self.close();
        trace!("drop stream {} -> {}", 0, self.dst);
    }
}

/// Trait for forwarding a datagram.
pub trait ForwardDatagram: Send {
    /// Forwards datagram.
    fn forward(&mut self, dst: SocketAddrV4, src: SocketAddrV4, payload: &[u8]) -> io::Result<()>;
}

/// Represents a worker of a proxied UDP datagram.
pub struct DatagramWorker {
    src: Arc<AtomicU64>,
    local_port: u16,
    tx_tx: UnboundedSender<(Vec<u8>, SocketAddrV4)>,
    is_closed: Arc<AtomicBool>,
    close_tx: Sender<()>,
    close_tx2: Sender<()>,
}

impl DatagramWorker {
    /// Creates a new `DatagramWorker`.
    pub async fn bind(
        tx: Arc<Mutex<dyn ForwardDatagram>>,
        src: SocketAddrV4,
        proxy: &ProxyConfig,
    ) -> io::Result<(DatagramWorker, u16)> {
        let (mut socks_rx, mut socks_tx, local_port) = match proxy {
            ProxyConfig::Socks(remote, options) => socks::bind(*remote, options).await?,
        };

        #[allow(clippy::type_complexity)]
        let (tx_tx, mut tx_rx): (
            UnboundedSender<(Vec<u8>, SocketAddrV4)>,
            UnboundedReceiver<(Vec<u8>, SocketAddrV4)>,
        ) = mpsc::unbounded_channel();
        let a_src = Arc::new(AtomicU64::from(socket_addr_v4_to_u64(&src)));
        let a_src_cloned = Arc::clone(&a_src);
        let is_closed = Arc::new(AtomicBool::new(false));
        let is_closed_cloned = Arc::clone(&is_closed);
        let (close_tx, mut close_rx) = mpsc::channel(1);
        let (close_tx2, mut close_rx2) = mpsc::channel(1);

        // Send
        tokio::spawn(async move {
            loop {
                let is_close;

                // Select
                {
                    let tx_rx_fut = tx_rx.recv();
                    let close_rx_fut = close_rx.recv();

                    tokio::pin!(tx_rx_fut, close_rx_fut);

                    tokio::select! {
                        r = tx_rx_fut => match r {
                            Some((payload, dst)) => {
                                match socks_tx.send_to(payload.as_slice(), dst).await {
                                    Ok(size) => {
                                        debug!(
                                            "send to proxy: {}: {} -> {} ({} Bytes)",
                                            "UDP", local_port, dst, size
                                        );
                                    },
                                    Err(ref e) => {
                                        warn!("handle send: {}: {} -> {}: {}", "UDP", local_port, dst, e);
                                    }
                                }
                                is_close = false;
                            }
                            None => is_close = false
                        },
                        _ = close_rx_fut => is_close = true
                    }
                }

                if is_close {
                    // Close
                    break;
                }
            }
        });

        // Receive
        tokio::spawn(async move {
            let mut buffer = vec![0u8; u16::MAX as usize];
            loop {
                let size;
                let mut addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);

                // Select
                {
                    let socks_rx_fut = socks_rx.recv_from(&mut buffer);
                    let close_rx_fut = close_rx2.recv();

                    tokio::pin!(socks_rx_fut, close_rx_fut);

                    tokio::select! {
                        socks_rx_result = socks_rx_fut => {
                            match socks_rx_result {
                                Ok((this_size, this_addr)) => {
                                    debug!(
                                        "receive from proxy: {}: {} -> {} ({} Bytes)",
                                        "UDP", this_addr, local_port, this_size
                                    );

                                    size = this_size;
                                    addr = this_addr;
                                },
                                Err(ref e) => {
                                    if e.kind() == io::ErrorKind::TimedOut {
                                        time::sleep(Duration::from_millis(TIMEDOUT_WAIT)).await;
                                        continue;
                                    }

                                    warn!(
                                        "receive from proxy: {}: {} = {}: {}",
                                        "UDP",
                                        local_port,
                                        u64_to_socket_addr_v4(a_src_cloned.load(Ordering::Relaxed)),
                                        e
                                    );

                                    size = 0;
                                }
                            }
                        }
                        _ = close_rx_fut => size = 0
                    };
                }

                if size > 0 {
                    // Send
                    if let Err(ref e) = tx.lock().unwrap().forward(
                        addr,
                        u64_to_socket_addr_v4(a_src_cloned.load(Ordering::Relaxed)),
                        &buffer[..size],
                    ) {
                        warn!(
                            "handle receive: {}: {} -> {}: {}",
                            "UDP", addr, local_port, e
                        );
                    }
                } else {
                    is_closed_cloned.store(true, Ordering::Relaxed);
                    trace!(
                        "close datagram {} = {}",
                        local_port,
                        u64_to_socket_addr_v4(a_src_cloned.load(Ordering::Relaxed))
                    );

                    break;
                }
            }
        });

        trace!("create datagram {} = {}", src, local_port);

        Ok((
            DatagramWorker {
                src: a_src,
                local_port,
                tx_tx,
                is_closed,
                close_tx,
                close_tx2,
            },
            local_port,
        ))
    }

    /// Sends data on the proxied datagram in UDP to the destination.
    pub fn send_to(&mut self, payload: Vec<u8>, dst: SocketAddrV4) -> io::Result<()> {
        // Send
        if self.tx_tx.send((payload, dst)).is_err() {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }

        Ok(())
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
        let _ = self.close_tx2.try_send(());
        trace!("drop datagram {} = {}", self.src(), self.local_port);
    }
}

/// Represents a worker of a proxied UDP datagram. Comparing with `DatagramWorker`,
/// `DatagramWorker2` do not require the ownership of the sent payload, but have to wait until the
/// payload was sent.
pub struct DatagramWorker2 {
    src: Arc<AtomicU64>,
    local_port: u16,
    socks_tx: SocksSendHalf,
    is_closed: Arc<AtomicBool>,
    close_tx: Sender<()>,
}

impl DatagramWorker2 {
    /// Creates a new `DatagramWorker2`.
    pub async fn bind(
        tx: Arc<Mutex<dyn ForwardDatagram>>,
        src: SocketAddrV4,
        proxy: &ProxyConfig,
    ) -> io::Result<(DatagramWorker2, u16)> {
        let (mut socks_rx, socks_tx, local_port) = match proxy {
            ProxyConfig::Socks(remote, options) => socks::bind(*remote, options).await?,
        };

        let a_src = Arc::new(AtomicU64::from(socket_addr_v4_to_u64(&src)));
        let a_src_cloned = Arc::clone(&a_src);
        let is_closed = Arc::new(AtomicBool::new(false));
        let is_closed_cloned = Arc::clone(&is_closed);
        let (close_tx, mut close_rx) = mpsc::channel(1);

        // Receive
        tokio::spawn(async move {
            let mut buffer = vec![0u8; u16::MAX as usize];
            loop {
                let size;
                let mut addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);

                // Select
                {
                    let socks_rx_fut = socks_rx.recv_from(&mut buffer);
                    let close_rx_fut = close_rx.recv();

                    tokio::pin!(socks_rx_fut, close_rx_fut);

                    tokio::select! {
                        socks_rx_result = socks_rx_fut => {
                            match socks_rx_result {
                                Ok((this_size, this_addr)) => {
                                    debug!(
                                        "receive from proxy: {}: {} -> {} ({} Bytes)",
                                        "UDP", this_addr, local_port, this_size
                                    );

                                    size = this_size;
                                    addr = this_addr;
                                },
                                Err(ref e) => {
                                    if e.kind() == io::ErrorKind::TimedOut {
                                        time::sleep(Duration::from_millis(TIMEDOUT_WAIT)).await;
                                        continue;
                                    }

                                    warn!(
                                        "receive from proxy: {}: {} = {}: {}",
                                        "UDP",
                                        local_port,
                                        u64_to_socket_addr_v4(a_src_cloned.load(Ordering::Relaxed)),
                                        e
                                    );

                                    size = 0;
                                }
                            }
                        }
                        _ = close_rx_fut => size = 0
                    };
                }

                if size > 0 {
                    // Send
                    if let Err(ref e) = tx.lock().unwrap().forward(
                        addr,
                        u64_to_socket_addr_v4(a_src_cloned.load(Ordering::Relaxed)),
                        &buffer[..size],
                    ) {
                        warn!(
                            "handle receive: {}: {} -> {}: {}",
                            "UDP", addr, local_port, e
                        );
                    }
                } else {
                    is_closed_cloned.store(true, Ordering::Relaxed);
                    trace!(
                        "close datagram {} = {}",
                        local_port,
                        u64_to_socket_addr_v4(a_src_cloned.load(Ordering::Relaxed))
                    );

                    break;
                }
            }
        });

        trace!("create datagram {} = {}", src, local_port);

        Ok((
            DatagramWorker2 {
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
        // Send
        let size = self.socks_tx.send_to(payload, dst).await?;
        debug!(
            "send to proxy {}: {} -> {} ({} Bytes)",
            "UDP", self.local_port, dst, size
        );

        Ok(size)
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

impl Drop for DatagramWorker2 {
    fn drop(&mut self) {
        let _ = self.close_tx.try_send(());
        trace!("drop datagram {} = {}", self.src(), self.local_port);
    }
}

fn socket_addr_v4_to_u64(addr: &SocketAddrV4) -> u64 {
    let ip = u32::from(*addr.ip());

    ((ip as u64) << 16) + addr.port() as u64
}

fn u64_to_socket_addr_v4(v: u64) -> SocketAddrV4 {
    let port = v as u16;
    let ip = (v >> 16) as u32;
    let ip = Ipv4Addr::from(ip);

    SocketAddrV4::new(ip, port)
}
