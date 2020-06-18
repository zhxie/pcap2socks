# pcap2socks

**pcap2socks** is a proxy which redirect traffic to SOCKS proxy with pcap written in Rust.

_This project is currently under development._

## Usage

```
cargo run -- -s <ADDRESS> -d <ADDRESS>

# Or using proxy ARP
cargo run -- -s <ADDRESS> -p <ADDRESS> -d <ADDRESS>
```

### Options

`-i, --interface <INTERFACE>`: Interface for listening.

`--mtu <VALUE>`: MTU, default as `1400`. MTU is set in traffic from local to the source.

`-s, --source <ADDRESS>`: (Required) Source.

`-p, --publish <ADDRESS>`: ARP publishing address. If this value is set, `pcap2socks` will reply ARP request as it owns the specified address which is not in the network, also called proxy ARP.

`-d, --destination <ADDRESS>`: Destination, default as `127.0.0.1:1080`.

`-h, --help`: Prints help information.

`-v, --verbose`: Prints verbose information.

`-V, --vverbose`: Prints vverbose information.

## License

pcap2socks is licensed under [the MIT License](/LICENSE).
