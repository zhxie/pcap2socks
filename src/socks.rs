use socks::{Socks5Datagram, Socks5Stream};
use std::clone::Clone;
use std::cmp::{Eq, PartialEq};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddrV4;

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
