# pcap2socks

**pcap2socks** is a proxy which redirect traffic to a SOCKS proxy with pcap written in Rust.

_pcap2socks is designed to accelerate games in game consoles._

## Features

- **Redirect Traffic**: Redirect TCP and UDP traffic to a SOCKS proxy.
- **Proxy ARP**: Reply ARP request as it owns the specified address which is not on the network.
- **Cross Platform**
- **Full Cone NAT**

## Dependencies

1. [Npcap](http://www.npcap.org/) or WinPcap in Windows (If using Npcap, make sure to install with the "Install Npcap in WinPcap API-compatible Mode"), libpcap in macOS, Linux and others.

## Build

### Windows

If you want to build pcap2socks in Windows, you must meet all the three requirements described in [libpnet](https://github.com/libpnet/libpnet#windows).

## Usage

```
pcap2socks -s <ADDRESS>...

# Or a more general one using proxy ARP (recommended)
pcap2socks -s <ADDRESS>... -p <ADDRESS> -d <ADDRESS>
```

### Flags

`-h, --help`: Prints help information.

`-v, --verbose`: Prints verbose information (`-vv` for vverbose).

`-V, --version`: Prints version information.

`--force-associate-destination`: Force to associate with the destination. If this flag is set, pcap2socks will associate with the destination instead of the replied bind address from a SOCKS5 UDP ASSOCIATE. You have to set this flag when the SOCKS5 server is behind a NAT which will translate address `OuterIP:Port` to `InnerIP:Port`.

### Options

`-i, --interface <INTERFACE>`: Interface for listening.

`--mtu <VALUE>`: MTU. Generally, pcap2socks will automatically obtain the MTU, but you can also override by setting this option. The MTU is set in the traffic from local to the source.

`-P, --preset <PRESET>`: Preset. You can use preset source and publish of game accelerators in the market. Available values are `t`, `tencent` for [Tencent Online Game Accelerator](https://jiasu.qq.com/) and `n`, `netease`, `u`, `uu` for [Netease UU Game Accelerator](https://uu.163.com/).

`-s, --sources <ADDRESS>...`: Sources.

`-p, --publish <ADDRESS>`: ARP publishing address. If this option is set, pcap2socks will reply ARP request as it owns the specified address which is not on the network, also called proxy ARP.

`-d, --destination <ADDRESS>`: Destination, default as `127.0.0.1:1080`.

`--username <VALUE>`: Username. This value should be set only when the SOCKS5 server requires the username/password authentication.

`--password <VALUE>`: Password. This value should be set only when the SOCKS5 server requires the username/password authentication.

## Troubleshoot

1. Because the packet sent from sources should only be handled by pcap2socks, you have to disable IP forward or configure the firewall with the following command statement. For more information, please refer to the troubleshoot paragraph in [IkaGo](https://github.com/zhxie/ikago#troubleshoot).

   ```
   // Linux
   sysctl -w net.ipv4.ip_forward=0

   // macOS
   sysctl -w net.inet.ip.forwarding=0
   ```

2. pcap2socks requires root permission in some OS by default. But you can run pcap2socks in non-root by executing the following command before opening pcap2socks.
   ```
   // Linux
   setcap cap_net_raw+ep path_to_pcap2socks
   ```

## Limitations

1. IPv6 is not supported yet.

2. Because only SOCKS5 can forward UDP traffic, pcap2socks only support SOCKS5 at this point. A version with SOCKS4 support without redirecting UDP traffic will release in the future.

## Known Issues

1. Applications like VMWare Workstation on Windows may implement their own IP forwarding and forward packets which should be handled by pcap2socks, resulting in abnormal operations in pcap2socks.

## License

pcap2socks is licensed under [the MIT License](/LICENSE).
