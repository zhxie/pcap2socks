# pcap2socks

This is the development documentation of pcap2socks.

## IPv4 Implementation

### Differences with the Standard [RFC 791](https://tools.ietf.org/html/rfc791) and Its Updates

- pcap2socks ignores DSCP, ECN and all the options.

- pcap2socks will send packets with a TTL of `TTL` regardless of the TTL from the received packets.

- pcap2socks dost not support broadcasting and multicasting.

## ICMPv4 Implementation

### Differences with the Standard [RFC 792](https://tools.ietf.org/html/rfc792) and Its Updates

- pcap2socks only supports the destination unreachable (destination port unreachable and fragmentation required, and DF flag set) message.

## TCP Implementation

### Differences with the Standard [RFC 793](https://tools.ietf.org/html/rfc793) and Its Updates

- pcap2socks ignores flags NS, CWR, ECE, URG and PSH, and urgent pointers, and only support part of the options including MSS, window scale and selective acknowledgements.

- pcap2socks does not retransmit the ACK/SYN packets in handshaking since if these packets are dropped accidentally, the source will attempt to re-establish the connection.

- pcap2socks does not consider the wait time in states like `TIME_WAIT` since the source should maintain its state.

- pcap2socks does not realize Nagle's algorithm ([RFC 1122](https://tools.ietf.org/html/rfc1122)) for performance consideration.

- pcap2socks does not realize the zero window probe ([RFC 1122](https://tools.ietf.org/html/rfc1122)) and does not report its window explicitly.

- pcap2socks does not realize keep-alive ([RFC 1122](https://tools.ietf.org/html/rfc1122)) for performance consideration.

- pcap2socks does not calculate for the window scale ([RFC 7323](https://tools.ietf.org/html/rfc7323)) option and will open a same-size receive window as the source by default.

- pcap2socks does not support the timestamp ([RFC 7323](https://www.iana.org/go/rfc7323)) option. Since only the source and destination know the full information of the traffic, pcap2socks may not trace any packets and report their timestamp correctly.

## SOCKS5 Implementation

### Differences with the Standard [RFC 1928](https://tools.ietf.org/html/rfc1928) and Its Updates

- pcap2socks will associate with the destination instead of the replied bind address in UDP ASSOCIATE if the replied bind address is in the private network ([RFC 1918](https://tools.ietf.org/html/rfc1918)) by default.

- pcap2socks only supports SOCKS5 authentication methods no authentication and username/password authentication.

## Hard-Coded Options

### IPv4

`TTL`: Represents the TTL in the sent packets. Default as `128`.

### Defragmentation

`EXPIRE_TIME`: Represents the expire time of each group of fragments. The timer will be updated when a new fragment arrived, and all the fragments in the group will be dropped if it reaches the expire time. Default as `10000` ms.

### pcap

`BUFFER_SIZE`: Represents the buffer size of pcap channels. If the buffer size is too small, some frames may arrive out of order or may be dropped, if the buffer size is too big, it may lead to a [bufferbloat](https://en.wikipedia.org/wiki/Bufferbloat), so set with a reasonable value. Default as `262144` Bytes, or 256 kB.

### SOCKS

`TIMEOUT_WAIT`: Represents the wait time after a `TimedOut` `IoError`. If the I/O timed out, the thread will sleep for a certain time before a retry. Default as `20` ms.

`QUEUE_FULL_WAIT`: Represents the wait time after a queue full event. Default as `200` ms.

`RECV_ZERO_WAIT`: Represents the wait time after receiving 0 byte from the stream. A receiving zero indicates the stream is either be closed, or is just a temporary spurious wake up. The thread will sleep for a certain time before a retry. Default as `100` ms.

`MAX_RECV_ZERO`: Represents the maximum count of receiving 0 byte from the stream before closing it. After an amount of receiving zeroes, the stream is likely to be closed. The stream will be recognized as closed and trigger a FIN. Default as `3`.

`TICK_INTERVAL`: Represents the interval of a tick. The timed event will force retransmitting timed out data in a TCP connection. Default as `500` ms.

### Cache

`MAX_U32_WINDOW_SIZE`: Represents the maximum distance of u32 values between packets in an u32 window. Data with sequence `1000` and sequence `101000` may be recognized as increment but discontinuous, but data with sequence `101000` and `1000` may be recognized as expired or out of order. The former example's seconds data will be pushed into the cache, while the latter's will be dropped. Default as `16777216` Bytes, or 16 MB.

`ALLOC_IN_INITIAL`: Represents if the buffer should be allocated in the initial constructor of caches. Allocating the full buffer in the constructor may reduce the time overhead in future expansion of the vector, but will also lead to take more memory consumption. Default as `false`.

### TCP

`MAX_U32_WINDOW_SIZE`: Same as above. Default as `16777216` Bytes, or 16 MB.

`INITIAL_SSTHRESH_RATE`: Represents the initial slow start threshold rate for congestion window in a TCP connection. Default as `100` (100 MSS).

`RECV_WINDOW`: Represents the receive window size. The actual window will be multiplied by `wscale`. Default as `65535` Bytes.

`MAX_QUEUE`: Represents the maximum size of extra cache in a TCP connection. Default as `16777216` Bytes, or 16 MB. You may turn off the limitation of the queue by set the value to `usize::MAX`.

`ENABLE_RTO_COMPUTE`: Represents if the RTO computation ([RFC 6298](https://tools.ietf.org/html/rfc6298)) is enabled. Default as `true`.

`INITIAL_RTO`: Represents the initial timeout for a retransmission in a TCP connection. Default as `1000` ms.

`MIN_RTO`: Represents the minimum timeout for a retransmission in a TCP connection. Default as `1000` ms.

`MAX_RTO`: Represents the maximum timeout for a retransmission in a TCP connection. Default as `60000` ms.

`ENABLE_CC`: Represents if the congestion control ([RFC 5681](https://tools.ietf.org/html/rfc5681)) is enabled. The algorithm used currently is Reno (without the fast recovery). Default as `true`.

`CC_ALGORITHM`: Represents the congestion control algorithm. Available values are `Tahoe` for TCP Tahoe, `Reno` for TCP Reno and `Cubic` for TCP CUBIC ([RFC 8312](https://tools.ietf.org/html/rfc8312)) congestion control algorithm. Default as `Reno`.

### Forwarder & Redirector

`MAX_U32_WINDOW_SIZE`: Same as above. Default as `16777216` Bytes, or 16 MB.

`TIMEOUT_WAIT`: Same as above. Default as `20` ms.

`ENABLE_RECV_SWS_AVOID`: Represents if the receive-side silly window syndrome avoidance, Clark's algorithm, ([RFC 1122](https://tools.ietf.org/html/rfc1122)) is enabled. Default as `true`.

`ENABLE_SEND_SWS_AVOID`: Represents if the send-side silly window syndrome avoidance, Clark's algorithm, ([RFC 896](https://tools.ietf.org/html/rfc896)) is enabled. Default as `true`.

`ENABLE_DELAYED_ACK`: Represents if the delayed ACK ([RFC 1122](https://tools.ietf.org/html/rfc1122)) is enabled. Default as `true`.

`ENABLE_MSS`: Represents if the TCP MSS ([RFC 793](https://www.iana.org/go/rfc793)) option is enabled. Default as `true`.

`ENABLE_WSCALE`: Represents if the TCP window scale ([RFC 7323](https://tools.ietf.org/html/rfc7323)) option is enabled. Enable window scale may lead to a bufferbloat described above, and the `MAX_U32_WINDOW_SIZE` must be set at a reasonable value. Default as `true`.

`MAX_RECV_WSCALE`: Represents the max window scale of the receive window. pcap2socks will open a same-size receive window as the source by default unless the window scale is over the limitation. Default as `8` (x256), or 16MB.

`ENABLE_SACK`: Represents if the TCP selective acknowledgment ([RFC 7323](https://tools.ietf.org/html/rfc7323)) option is enabled. Default as `true`.

`DUPLICATES_THRESHOLD`: Represents the threshold of TCP ACK duplicates before trigger a fast retransmission, also recognized as fast retransmission. Default as `3`.

`RETRANS_COOL_DOWN`: Represents the cool down time between 2 retransmissions. Default as `200` ms.

`MAX_UDP_PORT`: Represents the max limit of UDP port for binding in local. If the value is too small, rebind will happen frequently and the previous UDP "connection" will be dropped, and may not able to connect to other peer. If the value is too big, the system resource may be largely consumed, so set with a reasonable value. Default as `256`.

## Defects

pcap2socks has some defects in the view of engineering.

- pcap2socks does not have any accurate timers, timeout event like retransmission will only be triggered by `TICK_INTERVAL` or specific event like ACK received, extra latency in retransmission may be included.

- Because pcap2socks does not meet all [RFC 1122](https://tools.ietf.org/html/rfc1122) TCP musts and shoulds, the performance may be defected. However, since pcap2socks is mainly used in LANs, the actual impact may be minimal.

- pcap2socks ignores checksums, lengths and some other fields in headers to support non-standard systems and LRO (large receive offload), but will also bring security issues.

- pcap2socks works like a router but will redirect all traffic including local traffic, so local connections via pcap2socks, multicastings and broadcastings will not work properly.

- The structure of the `Redirector`, the `StreamWorker` & `DatagramWorker` and the `Forwarder` looks like a chaos. Caches and states should be located in the `StreamWorker` & `DatagramWorker` instead of the `Redirector` and the `Forwarder`.

- pcap2socks cannot close gracefully, all the data in the receive and send cache will be dropped. The connections will be closed (or shutdown, depending on the kernel or the OS) immediately for performance consideration. This is limited by the crate [pnet](https://crates.io/crates/pnet) which only supports synchronous methods.

- pcap2socks is waiting for Rust's updates, including the asynchronous methods in traits, to enhance the commonality of the system.
