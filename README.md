# pcap2socks

**pcap2socks** is a proxy which redirect traffic to SOCKS proxy with pcap written in Rust.

## Features

- **Redirect Traffic**: Redirect TCP and UDP traffic to a SOCKS5 proxy.
- **Proxy ARP**: Reply ARP request as it owns the specified address which is not on the network.
- **Cross Platform**
- **Full Cone NAT**

## Dependencies

1. [Npcap](http://www.npcap.org/) or WinPcap in Windows (If using Npcap, make sure to install with the "Install Npcap in WinPcap API-compatible Mode"), libpcap in macOS, Linux and others.

## Build

### Windows

If you want to build **pcap2socks** in Windows, you must meet all the three requirements described in [libpnet](https://github.com/libpnet/libpnet#windows).

## Usage

```
cargo run -- -s <ADDRESS>

# Or a more general one using proxy ARP (recommended)
cargo run -- -s <ADDRESS> -p <ADDRESS> -d <ADDRESS>
```

### Flags

`-h, --help`: Prints help information.

`-v, --verbose`: Prints verbose information.

`--version`: Prints version information.

`-V, --vverbose`: Prints vverbose information.

### Options

`-i, --interface <INTERFACE>`: Interface for listening.

`--mtu <VALUE>`: MTU, default as `1400`. MTU is set in traffic from local to the source.

`-s, --source <ADDRESS>`: (Required) Source.

`-p, --publish <ADDRESS>`: ARP publishing address. If this value is set, `pcap2socks` will reply ARP request as it owns the specified address which is not on the network, also called proxy ARP.

`-d, --destination <ADDRESS>`: Destination, default as `127.0.0.1:1080`.

## License

pcap2socks is licensed under [the MIT License](/LICENSE).
