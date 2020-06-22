use super::{downstreamer::Downstreamer, socks::SocksDatagram};
use log::{debug, trace, warn};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Represents a worker of a SOCKS5 UDP client.
pub struct DatagramWorker {
    src_port: Arc<AtomicU16>,
    local_port: u16,
    datagram: Arc<SocksDatagram>,
    #[allow(dead_code)]
    thread: Option<JoinHandle<()>>,
    is_closed: Arc<AtomicBool>,
}

impl DatagramWorker {
    /// Creates a new `DatagramWorker`.
    pub fn bind(
        tx: Arc<Mutex<Downstreamer>>,
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
        let is_closed = AtomicBool::new(false);
        let a_is_closed = Arc::new(is_closed);
        let a_is_closed_cloned = Arc::clone(&a_is_closed);
        let thread = thread::spawn(move || {
            let mut buffer = [0u8; u16::MAX as usize];
            loop {
                if a_is_closed_cloned.load(Ordering::Relaxed) {
                    break;
                }
                match a_datagram_cloned.recv_from(&mut buffer) {
                    Ok((size, addr)) => {
                        if a_is_closed_cloned.load(Ordering::Relaxed) {
                            break;
                        }
                        debug!(
                            "receive from SOCKS: {}: {} -> {} ({} Bytes)",
                            "UDP", addr, local_port, size
                        );

                        // Send
                        if let Err(ref e) = tx.lock().unwrap().send_udp(
                            addr,
                            a_src_port_cloned.load(Ordering::Relaxed),
                            &buffer[..size],
                        ) {
                            warn!("handle {}: {}", "UDP", e);
                        }
                    }
                    Err(ref e) => {
                        if e.kind() == io::ErrorKind::TimedOut {
                            thread::sleep(Duration::from_millis(super::TIMEDOUT_WAIT));
                            continue;
                        }
                        warn!(
                            "SOCKS: {}: {} = {}: {}",
                            "UDP",
                            local_port,
                            a_src_port_cloned.load(Ordering::Relaxed),
                            e
                        );
                        a_is_closed_cloned.store(true, Ordering::Relaxed);

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
            thread: Some(thread),
            is_closed: a_is_closed,
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
