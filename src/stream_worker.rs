use log::{debug, trace, warn};
use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddrV4, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use super::{downstreamer::Downstreamer, socks};

/// Represents the times the stream received 0 byte data continuously before close itself.
const ZEROES_BEFORE_CLOSE: usize = 3;

/// Represents a worker of a SOCKS5 TCP stream.
pub struct StreamWorker {
    dst: SocketAddrV4,
    stream: TcpStream,
    thread: Option<JoinHandle<()>>,
    is_closed: Arc<AtomicBool>,
}

impl StreamWorker {
    /// Opens a new `StreamWorker`.
    pub fn connect(
        tx: Arc<Mutex<Downstreamer>>,
        src_port: u16,
        dst: SocketAddrV4,
        remote: SocketAddrV4,
    ) -> io::Result<StreamWorker> {
        let stream = socks::connect(remote, dst)?;
        let mut stream_cloned = stream.try_clone()?;

        let is_closed = AtomicBool::new(false);
        let a_is_closed = Arc::new(is_closed);
        let a_is_closed_cloned = Arc::clone(&a_is_closed);
        let thread = thread::spawn(move || {
            let mut buffer = [0u8; u16::MAX as usize];
            let mut zero = 0;
            loop {
                if a_is_closed_cloned.load(Ordering::Relaxed) {
                    break;
                }
                match stream_cloned.read(&mut buffer) {
                    Ok(size) => {
                        if a_is_closed_cloned.load(Ordering::Relaxed) {
                            break;
                        }
                        if size == 0 {
                            zero += 1;
                            if zero >= ZEROES_BEFORE_CLOSE {
                                // TODO: a potential bug
                                /* This may happen frequently for unknown reason
                                warn!(
                                    "SOCKS: {}: {} -> {}: {}",
                                    "TCP",
                                    0,
                                    dst,
                                    io::Error::from(io::ErrorKind::UnexpectedEof)
                                );
                                */
                                a_is_closed_cloned.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                        debug!(
                            "receive from SOCKS: {}: {} -> {} ({} Bytes)",
                            "TCP", dst, 0, size
                        );

                        // Send
                        if let Err(ref e) =
                            tx.lock()
                                .unwrap()
                                .append_to_cache(dst, src_port, &buffer[..size])
                        {
                            warn!("handle {}: {}", "TCP", e);
                        }
                    }
                    Err(ref e) => {
                        if e.kind() == io::ErrorKind::TimedOut {
                            thread::sleep(Duration::from_millis(super::TIMEDOUT_WAIT));
                            continue;
                        }
                        warn!("SOCKS: {}: {} -> {}: {}", "TCP", 0, dst, e);
                        a_is_closed_cloned.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });

        trace!("open stream {} -> {}", 0, dst);

        Ok(StreamWorker {
            dst,
            stream,
            thread: Some(thread),
            is_closed: a_is_closed,
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
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        trace!("drop stream {} -> {}", 0, self.dst);
    }
}
