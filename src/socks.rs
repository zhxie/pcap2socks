use socks::{self, TargetAddr};
use std::clone::Clone;
use std::cmp::{Eq, PartialEq};
use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::net::SocketAddr;

/*
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct FromToSocketAddrV4 {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
}

impl FromToSocketAddrV4 {
    pub fn new(src: SocketAddrV4, dst: SocketAddrV4) -> FromToSocketAddrV4 {
        FromToSocketAddrV4 { src, dst }
    }

    pub fn src(&self) -> SocketAddrV4 {
        self.src
    }

    pub fn dst(&self) -> SocketAddrV4 {
        self.dst
    }
}

pub struct SocksDistributor {
    pub proxy: SocketAddrV4,
    pub tcp_map: HashMap<FromToSocketAddrV4, Socks5Stream>,
    pub udp_map: HashMap<SocketAddrV4, Socks5Datagram>,
}

impl SocksDistributor {
    pub fn new(proxy: SocketAddrV4) -> SocksDistributor {
        SocksDistributor {
            proxy,
            tcp_map: HashMap::new(),
            udp_map: HashMap::new(),
        }
    }

    pub fn dist_tcp(
        &mut self,
        src: SocketAddrV4,
        dst: SocketAddrV4,
    ) -> Result<&Socks5Stream, String> {
        let addr = FromToSocketAddrV4::new(src, dst);
        if let None = self.tcp_map.get(&addr) {
            match Socks5Stream::connect(self.proxy, dst) {
                Ok(stream) => {
                    self.tcp_map.insert(addr.clone(), stream);
                }
                Err(e) => return Err(format!("connect: {}", e)),
            };
        }

        Ok(self.tcp_map.get(&addr).unwrap())
    }

    pub fn dist_udp(&mut self, src: SocketAddrV4) -> Result<&Socks5Datagram, String> {
        if let None = self.udp_map.get(&src) {
            match Socks5Datagram::bind(self.proxy, src) {
                Ok(datagram) => {
                    self.udp_map.insert(src.clone(), datagram);
                }
                Err(e) => return Err(format!("bind: {}", e)),
            };
        }

        Ok(self.udp_map.get(&src).unwrap())
    }
}
*/

/// Represents a SOCKS5 UDP client.
#[derive(Debug)]
pub struct Socks5Datagram {
    datagram: socks::Socks5Datagram,
    src: SocketAddr,
}

impl Socks5Datagram {
    /// Creates a UDP socket bound to the specified address which will have its traffic routed through the specified proxy.
    pub fn bind(
        remote_src: SocketAddr,
        local_src: SocketAddr,
        dst: SocketAddr,
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
    pub fn send_to(&self, buffer: &[u8], dst: SocketAddr) -> io::Result<usize> {
        self.datagram.send_to(buffer, dst)
    }

    /// Receives a single datagram message on the socket.
    pub fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.datagram.recv_from(buffer) {
            Ok((size, addr)) => match addr {
                TargetAddr::Ip(addr) => Ok((size, addr)),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected address type",
                )),
            },
            Err(e) => Err(e),
        }
    }

    /// Get the source of the socket.
    pub fn get_src(&self) -> SocketAddr {
        self.src
    }
}
