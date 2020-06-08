use socks::{self, TargetAddr};
use std::io;
use std::net::{SocketAddr, SocketAddrV4};

/// Represents a SOCKS5 UDP client.
#[derive(Debug)]
pub struct Socks5Datagram {
    datagram: socks::Socks5Datagram,
    src: SocketAddrV4,
}

impl Socks5Datagram {
    /// Creates a UDP socket bound to the specified address which will have its traffic routed through the specified proxy.
    pub fn bind(
        remote_src: SocketAddrV4,
        local_src: SocketAddrV4,
        dst: SocketAddrV4,
    ) -> io::Result<Socks5Datagram> {
        match socks::Socks5Datagram::bind(dst, local_src) {
            Ok(datagram) => Ok(Socks5Datagram {
                datagram,
                src: remote_src,
            }),
            Err(e) => Err(e),
        }
    }

    /// Sends data on the socket to the given address.
    pub fn send_to(&self, buffer: &[u8], dst: SocketAddrV4) -> io::Result<usize> {
        self.datagram.send_to(buffer, dst)
    }

    /// Receives a single datagram message on the socket.
    pub fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        match self.datagram.recv_from(buffer) {
            Ok((size, addr)) => match addr {
                TargetAddr::Ip(addr) => match addr {
                    SocketAddr::V4(addr) => Ok((size, addr)),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unexpected IPv6 address",
                    )),
                },
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected address type",
                )),
            },
            Err(e) => Err(e),
        }
    }

    /// Get the source of the socket.
    pub fn get_src(&self) -> SocketAddrV4 {
        self.src
    }
}
