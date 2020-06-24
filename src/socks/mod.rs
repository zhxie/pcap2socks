use log::{debug, trace, warn};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

mod socks;
use self::socks::SocksDatagram;

/// Trait for forwarding transport layer payload.
pub trait Forward: Send {
    /// Forward TCP payload.
    fn forward_tcp(&mut self, dst: SocketAddrV4, src_port: u16, payload: &[u8]) -> io::Result<()>;

    /// Forward UDP payload.
    fn forward_udp(&mut self, dst: SocketAddrV4, src_port: u16, payload: &[u8]) -> io::Result<()>;
}

/// Represents the wait time after a `TimedOut` `IoError`.
const TIMEDOUT_WAIT: u64 = 20;

/// Represents a worker of a SOCKS5 TCP stream.
pub struct StreamWorker {
    dst: SocketAddrV4,
    stream: TcpStream,
    is_finished: Arc<AtomicBool>,
    is_closed: Arc<AtomicBool>,
}

impl StreamWorker {
    /// Opens a new `StreamWorker`.
    pub fn connect(
        tx: Arc<Mutex<dyn Forward>>,
        src_port: u16,
        dst: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> io::Result<StreamWorker> {
        let stream = socks::connect(remote, dst)?;
        let mut stream_cloned = stream.try_clone()?;

        let is_finished = Arc::new(AtomicBool::new(false));
        let is_finished_cloned = Arc::clone(&is_finished);
        let is_closed = Arc::new(AtomicBool::new(false));
        let is_closed_cloned = Arc::clone(&is_closed);
        tokio::spawn(async move {
            let mut buffer = [0u8; u16::MAX as usize];
            loop {
                if is_closed_cloned.load(Ordering::Relaxed) {
                    break;
                }
                match stream_cloned.read(&mut buffer) {
                    Ok(size) => {
                        if is_closed_cloned.load(Ordering::Relaxed) {
                            break;
                        }
                        if size == 0 {
                            // Close by remote
                            if !is_finished_cloned.load(Ordering::Relaxed) {
                                warn!(
                                    "SOCKS: {}: {} -> {}: {}",
                                    "TCP",
                                    0,
                                    dst,
                                    io::Error::from(io::ErrorKind::UnexpectedEof)
                                );
                            }
                            is_closed_cloned.store(true, Ordering::Relaxed);
                            break;
                        }
                        debug!(
                            "receive from SOCKS: {}: {} -> {} ({} Bytes)",
                            "TCP", dst, 0, size
                        );

                        // Send
                        if let Err(ref e) =
                            tx.lock()
                                .unwrap()
                                .forward_tcp(dst, src_port, &buffer[..size])
                        {
                            warn!("handle {}: {}", "TCP", e);
                        }
                    }
                    Err(ref e) => {
                        if e.kind() == io::ErrorKind::TimedOut {
                            thread::sleep(Duration::from_millis(TIMEDOUT_WAIT));
                            continue;
                        }
                        warn!("SOCKS: {}: {} -> {}: {}", "TCP", 0, dst, e);
                        is_closed_cloned.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });

        trace!("open stream {} -> {}", 0, dst);

        Ok(StreamWorker {
            dst,
            stream,
            is_finished,
            is_closed: is_closed,
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

    /// Announces to finish the worker.
    pub fn finish(&mut self) {
        self.is_finished.store(true, Ordering::Relaxed);
        trace!("finish stream {} -> {}", 0, self.dst);
    }

    /// Closes the worker.
    pub fn close(&mut self) {
        self.is_closed.store(true, Ordering::Relaxed);
        trace!("close stream {} -> {}", 0, self.dst);
    }

    /// Returns if the worker is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }
}

impl Drop for StreamWorker {
    fn drop(&mut self) {
        self.close();
        if let Err(ref e) = self.stream.shutdown(Shutdown::Both) {
            warn!("handle {}: {}", "TCP", e);
        }
        trace!("drop stream {} -> {}", 0, self.dst);
    }
}

/// Represents a worker of a SOCKS5 UDP client.
pub struct DatagramWorker {
    src_port: Arc<AtomicU16>,
    local_port: u16,
    datagram: Arc<SocksDatagram>,
    is_closed: Arc<AtomicBool>,
}

impl DatagramWorker {
    /// Creates a new `DatagramWorker`.
    pub fn bind(
        tx: Arc<Mutex<dyn Forward>>,
        src_port: u16,
        local_port: u16,
        remote: SocketAddrV4,
    ) -> io::Result<DatagramWorker> {
        let datagram =
            SocksDatagram::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local_port), remote)?;

        let a_src_port = Arc::new(AtomicU16::from(src_port));
        let a_src_port_cloned = Arc::clone(&a_src_port);
        let a_datagram = Arc::new(datagram);
        let a_datagram_cloned = Arc::clone(&a_datagram);
        let is_closed = Arc::new(AtomicBool::new(false));
        let is_closed_cloned = Arc::clone(&is_closed);
        tokio::spawn(async move {
            let mut buffer = [0u8; u16::MAX as usize];
            loop {
                if is_closed_cloned.load(Ordering::Relaxed) {
                    break;
                }
                match a_datagram_cloned.recv_from(&mut buffer) {
                    Ok((size, addr)) => {
                        if is_closed_cloned.load(Ordering::Relaxed) {
                            break;
                        }
                        debug!(
                            "receive from SOCKS: {}: {} -> {} ({} Bytes)",
                            "UDP", addr, local_port, size
                        );

                        // Send
                        if let Err(ref e) = tx.lock().unwrap().forward_udp(
                            addr,
                            a_src_port_cloned.load(Ordering::Relaxed),
                            &buffer[..size],
                        ) {
                            warn!("handle {}: {}", "UDP", e);
                        }
                    }
                    Err(ref e) => {
                        if e.kind() == io::ErrorKind::TimedOut {
                            thread::sleep(Duration::from_millis(TIMEDOUT_WAIT));
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

        Ok(DatagramWorker {
            src_port: a_src_port,
            local_port,
            datagram: a_datagram,
            is_closed: is_closed,
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

    /// Sets the source port of the `DatagramWorker`.
    pub fn set_src_port(&mut self, src_port: u16) {
        self.src_port.store(src_port, Ordering::Relaxed);
        trace!("set datagram {} = {}", src_port, self.local_port);
    }

    /// Get the source port of the `DatagramWorker`.
    pub fn get_src_port(&self) -> u16 {
        self.src_port.load(Ordering::Relaxed)
    }

    /// Returns if the worker is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }
}
