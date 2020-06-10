use socks::{self, TargetAddr};
use socks::{Socks5Datagram, Socks5Stream};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::result;

/// Represents an error when handle SOCKS.
#[derive(Debug)]
pub enum SocksError {
    BindError(io::Error),
    SendError(io::Error),
    ReceiveError(io::Error),
}

impl Display for SocksError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match &self {
            SocksError::BindError(ref e) => write!(f, "bind: {}", e),
            SocksError::SendError(ref e) => write!(f, "send: {}", e),
            SocksError::ReceiveError(ref e) => write!(f, "receive: {}", e),
        }
    }
}

impl Error for SocksError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            SocksError::BindError(ref e) => Some(e),
            SocksError::SendError(ref e) => Some(e),
            SocksError::ReceiveError(ref e) => Some(e),
        }
    }
}

type Result<T> = result::Result<T, SocksError>;

/// Represents a SOCKS5 UDP client.
#[derive(Debug)]
pub struct SocksDatagram {
    datagram: Socks5Datagram,
}

impl SocksDatagram {
    /// Creates a UDP socket bound to the specified address which will have its traffic routed through the specified proxy.
    pub fn bind(local_src: SocketAddrV4, dst: SocketAddrV4) -> Result<SocksDatagram> {
        match Socks5Datagram::bind(dst, local_src) {
            Ok(datagram) => Ok(SocksDatagram { datagram }),
            Err(e) => Err(SocksError::BindError(e)),
        }
    }

    /// Sends data on the socket to the given address.
    pub fn send_to(&self, buffer: &[u8], dst: SocketAddrV4) -> Result<usize> {
        match self.datagram.send_to(buffer, dst) {
            Ok(size) => Ok(size),
            Err(e) => Err(SocksError::SendError(e)),
        }
    }

    /// Receives a single datagram message on the socket.
    pub fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddrV4)> {
        match self.datagram.recv_from(buffer) {
            Ok((size, addr)) => match addr {
                TargetAddr::Ip(addr) => match addr {
                    SocketAddr::V4(addr) => Ok((size, addr)),
                    _ => Err(SocksError::ReceiveError(io::Error::from(
                        io::ErrorKind::InvalidInput,
                    ))),
                },
                _ => Err(SocksError::ReceiveError(io::Error::from(
                    io::ErrorKind::InvalidInput,
                ))),
            },
            Err(e) => Err(SocksError::ReceiveError(e)),
        }
    }
}
