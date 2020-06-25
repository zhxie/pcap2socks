use async_socks5;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::io::{self, BufStream};
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::{TcpStream, UdpSocket};

/// Connects to a target server through a SOCKS5 proxy.
pub async fn connect(remote: SocketAddrV4, dst: SocketAddrV4) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(remote).await?;
    if let Err(e) = async_socks5::connect(&mut stream, dst, None).await {
        match e {
            async_socks5::Error::Io(e) => return Err(e),
            _ => return Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }

    Ok(stream)
}

const RSV_SIZE: usize = 2;
const FRAG_SIZE: usize = 1;
const ATYP_SIZE: usize = 1;
const DST_ADDR_SIZE: usize = 4;
const DST_PORT_SIZE: usize = 2;
const HEADER_SIZE: usize = RSV_SIZE + FRAG_SIZE + ATYP_SIZE + DST_ADDR_SIZE + DST_PORT_SIZE;

const ATYP_IPV4: u8 = 1;

/// Represents the send half of a SOCKS5 UDP client.
#[derive(Debug)]
pub struct SocksSendHalf {
    stream: Arc<BufStream<TcpStream>>,
    send_half: SendHalf,
}

impl SocksSendHalf {
    /// Creates a new `SocksSendHalf`.
    pub fn new(stream: Arc<BufStream<TcpStream>>, send_half: SendHalf) -> SocksSendHalf {
        SocksSendHalf { stream, send_half }
    }

    /// Sends data on the socket to the given address.
    pub async fn send_to(&mut self, buffer: &[u8], dst: SocketAddrV4) -> io::Result<usize> {
        let mut buf = vec![0u8; HEADER_SIZE + buffer.len()];
        // RSV
        // FRAG
        // ATYP
        buf[3] = ATYP_IPV4;
        // DST.ADDR
        &buf[4..8].copy_from_slice(&dst.ip().octets());
        // DST.PORT
        buf[8] = (dst.port() / 256) as u8;
        buf[9] = (dst.port() % 256) as u8;
        // Data
        &buf[10..].copy_from_slice(buffer);

        self.send_half
            .send_to(buf.as_slice(), &SocketAddr::V4(dst))
            .await
    }
}

/// Represents the receive half of a SOCKS5 UDP client.
#[derive(Debug)]
pub struct SocksRecvHalf {
    stream: Arc<BufStream<TcpStream>>,
    recv_half: RecvHalf,
    buffer: Vec<u8>,
}

impl SocksRecvHalf {
    /// Creates a new `SocksRecvHalf`.
    pub fn new(stream: Arc<BufStream<TcpStream>>, recv_half: RecvHalf) -> SocksRecvHalf {
        SocksRecvHalf {
            stream,
            recv_half,
            buffer: vec![0u8; u16::MAX as usize],
        }
    }

    /// Receives a single datagram message on the socket.
    pub async fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddrV4)> {
        let n = self.recv_half.recv(&mut self.buffer).await?;
        // ATYP and address
        match self.buffer[3] {
            ATYP_IPV4 => {}
            _ => unreachable!(),
        }
        let addr = SocketAddrV4::new(
            Ipv4Addr::new(
                self.buffer[4],
                self.buffer[5],
                self.buffer[6],
                self.buffer[7],
            ),
            self.buffer[8] as u16 * 256 + self.buffer[9] as u16,
        );
        // Buffer
        let size = n - HEADER_SIZE;
        &buffer[..size].copy_from_slice(&self.buffer[HEADER_SIZE..n]);

        Ok((size, addr))
    }
}

/// Bind a local address to a target server through a SOCKS5 proxy.
pub async fn bind(
    local: SocketAddrV4,
    remote: SocketAddrV4,
) -> io::Result<(SocksRecvHalf, SocksSendHalf)> {
    // Connect
    let stream = TcpStream::connect(remote).await?;
    let stream = BufStream::new(stream);
    let socket = UdpSocket::bind(local).await?;
    let datagram =
        match async_socks5::SocksDatagram::associate::<SocketAddrV4>(stream, socket, None, None)
            .await
        {
            Ok(datagram) => datagram,
            Err(e) => match e {
                async_socks5::Error::Io(e) => return Err(e),
                _ => return Err(io::Error::new(io::ErrorKind::Other, e)),
            },
        };

    let (stream, socket) = datagram.into_inner();
    let (socket_rx, socket_tx) = socket.split();
    let a_stream = Arc::new(stream);
    let a_stream_cloned = Arc::clone(&a_stream);

    Ok((
        SocksRecvHalf::new(a_stream, socket_rx),
        SocksSendHalf::new(a_stream_cloned, socket_tx),
    ))
}
