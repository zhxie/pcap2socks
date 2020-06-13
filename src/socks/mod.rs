use socks::{self, TargetAddr};
use socks::{Socks5Datagram, Socks5Stream};
use std::io::{self, BufReader, BufWriter};
use std::net::{SocketAddr, SocketAddrV4, TcpStream};

/// Connects to a target server through a SOCKS5 proxy.
pub fn connect(
    remote: SocketAddrV4,
    dst: SocketAddrV4,
) -> io::Result<(BufReader<TcpStream>, BufWriter<TcpStream>)> {
    let stream = Socks5Stream::connect(remote, dst)?;

    let s = stream.into_inner();
    let s_cloned = s.try_clone()?;

    let reader = BufReader::with_capacity(u16::MAX as usize, s);
    let writer = BufWriter::with_capacity(u16::MAX as usize, s_cloned);

    Ok((reader, writer))
}

/// Represents a SOCKS5 UDP client.
#[derive(Debug)]
pub struct SocksDatagram {
    datagram: Socks5Datagram,
}

impl SocksDatagram {
    /// Creates a UDP socket bound to the specified address which will have its traffic routed through the specified proxy.
    pub fn bind(local_src: SocketAddrV4, remote: SocketAddrV4) -> io::Result<SocksDatagram> {
        let datagram = Socks5Datagram::bind(remote, local_src)?;

        Ok(SocksDatagram { datagram })
    }

    /// Sends data on the socket to the given address.
    pub fn send_to(&self, buffer: &[u8], dst: SocketAddrV4) -> io::Result<usize> {
        self.datagram.send_to(buffer, dst)
    }

    /// Receives a single datagram message on the socket.
    pub fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        let (size, addr) = self.datagram.recv_from(buffer)?;

        let addr = match addr {
            TargetAddr::Ip(addr) => match addr {
                SocketAddr::V4(addr) => addr,
                _ => return Err(io::Error::new(io::ErrorKind::Other, "invalid ip version")),
            },
            _ => return Err(io::Error::new(io::ErrorKind::Other, "invalid address type")),
        };

        Ok((size, addr))
    }
}
