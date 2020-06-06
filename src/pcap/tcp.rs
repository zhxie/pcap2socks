pub use super::layer::{Layer, LayerType, LayerTypes};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use std::clone::Clone;
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;

/// Represents a TCP packet.
#[derive(Clone, Debug)]
pub struct Tcp {
    pub layer: tcp::Tcp,
    pub src: IpAddr,
    pub dst: IpAddr,
}

impl Tcp {
    /// Creates a `Tcp`.
    pub fn new(tcp: tcp::Tcp, src: IpAddr, dst: IpAddr) -> Tcp {
        Tcp {
            layer: tcp,
            src,
            dst,
        }
    }

    /// Creates a `Tcp` according to the given TCP packet, source and destination.
    pub fn parse(packet: &TcpPacket, src: IpAddr, dst: IpAddr) -> Tcp {
        Tcp {
            layer: tcp::Tcp {
                source: packet.get_source(),
                destination: packet.get_destination(),
                sequence: packet.get_sequence(),
                acknowledgement: packet.get_acknowledgement(),
                data_offset: packet.get_data_offset(),
                reserved: packet.get_reserved(),
                flags: packet.get_flags(),
                window: packet.get_window(),
                checksum: packet.get_checksum(),
                urgent_ptr: packet.get_urgent_ptr(),
                options: packet.get_options(),
                payload: vec![],
            },
            src,
            dst,
        }
    }

    fn serialize_private(
        &self,
        buffer: &mut [u8],
        fix_length: bool,
        n: usize,
        compute_checksum: bool,
    ) -> Result<usize, String> {
        let mut packet = match MutableTcpPacket::new(buffer) {
            Some(packet) => packet,
            None => return Err(format!("buffer is too small")),
        };

        packet.populate(&self.layer);

        // Fix length
        if fix_length {
            let mut data_offset = self.get_size();
            packet.set_data_offset((data_offset / 4) as u8);
        }

        // Compute checksum
        if compute_checksum {
            let checksum;
            match self.src {
                IpAddr::V4(src) => {
                    if let IpAddr::V4(dst) = self.dst {
                        checksum = tcp::ipv4_checksum(&packet.to_immutable(), &src, &dst);
                    } else {
                        return Err(format!(
                            "source and destination's IP version is not matched"
                        ));
                    }
                }
                IpAddr::V6(src) => {
                    if let IpAddr::V6(dst) = self.dst {
                        checksum = tcp::ipv6_checksum(&packet.to_immutable(), &src, &dst);
                    } else {
                        return Err(format!(
                            "source and destination's IP version is not matched"
                        ));
                    }
                }
            };
            packet.set_checksum(checksum);
        }

        Ok(self.get_size())
    }
}

impl Display for Tcp {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut flags = String::new();
        if self.layer.flags & TcpFlags::ACK != 0 {
            flags = flags + "A";
        }
        if self.layer.flags & TcpFlags::RST != 0 {
            flags = flags + "R";
        }
        if self.layer.flags & TcpFlags::SYN != 0 {
            flags = flags + "S";
        }
        if self.layer.flags & TcpFlags::FIN != 0 {
            flags = flags + "F";
        }
        if !flags.is_empty() {
            flags = String::from(" [") + &flags + "]";
        }

        write!(
            f,
            "{}: {} -> {}{}",
            LayerTypes::Tcp,
            self.layer.source,
            self.layer.destination,
            flags
        )
    }
}

impl Layer for Tcp {
    fn get_type(&self) -> LayerType {
        LayerTypes::Tcp
    }

    fn get_size(&self) -> usize {
        TcpPacket::packet_size(&self.layer)
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<usize, String> {
        self.serialize_private(buffer, false, 0, true)
    }

    fn serialize_n(&self, buffer: &mut [u8], n: usize) -> Result<usize, String> {
        self.serialize_private(buffer, true, n, true)
    }
}
