# pcap2socks

**IkaGo** is a proxy which redirect traffic to SOCKS proxy with pcap written in Rust.

_This project is currently under development._

## Usage

```
cargo run -- -s <ADDRESS> -d <ADDRESS>

# Or using proxy ARP
cargo run -- -s <ADDRESS> -p <ADDRESS> -d <ADDRESS>
```
