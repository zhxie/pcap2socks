# pcap2socks

This is the development documentation of pcap2socks.

## TCP Implementation

### Differences with the Standard [RFC 793](https://tools.ietf.org/html/rfc793) and Its Updates

- pcap2socks does not resend TCP data after not receiving ACK for a certain time, which is also recognized as MSL, since pcap2socks does not own the send timestamp and the timer in its send cache.

- pcap2socks does not consider the wait time in states like `TIME_WAIT` since the source should maintain its state.

- pcap2socks does not realize MSS ([RFC 793](https://tools.ietf.org/html/rfc793)) option since the way getting interface's MSS in difference kernels and systems are totally different, and one workable dependency crate [interfaces](https://crates.io/crates/interfaces) cannot be compiled in Windows successfully with MSVC.

- pcap2socks does not calculate for window scale ([RFC 7323](https://tools.ietf.org/html/rfc7323)) option and will open a same-size receive window as the source by default.

- pcap2socks sends all TCP data in `TCP_NODELAY` since pcap2socks owns no timers.

## Hard-Coded Options

### Defragmentation

`EXPIRE_TIME`: Represents the expire time of each group of fragments. The timer will be updated when a new fragment arrived, and all the fragments in the group will be dropped if it reaches the expire time. Default as `10000` ms.

### pcap

`BUFFER_SIZE`: Represents the buffer size of pcap channels. If the buffer size is too small, some packets may arrive out of order or may be dropped, if the buffer size is too big, it may lead to a [bufferbloat](https://en.wikipedia.org/wiki/Bufferbloat), so set with a reasonable value. Default as `262144` Bytes, or 256 kB.

### SOCKS

`TIMEOUT_WAIT`: Represents the wait time after a `TimedOut` `IoError`. If the I/O timed out, the thread will sleep for a certain time before a retry. Default as `20` ms.

`RECV_ZERO_WAIT`: Represents the wait time after receiving 0 byte from the stream. A receiving zero indicates the stream is either be closed, or is just a temporary spurious wake up. The thread will sleep for a certain time before a retry. Default as `100` ms.

`MAX_RECV_ZERO`: Represents the maximum count of receiving 0 byte from the stream before closing it. After an amount of receiving zeroes, the stream is likely to be closed. The stream will be recognized as closed and trigger a FIN. Default as `3`.

### Cache

`INITIAL_SIZE` Represents the initial size of cache. Default as `65536` Bytes, or 64 kB.

`EXPANSION_FACTOR`: Represents the expansion factor of the cache. The cache will be expanded by the factor if it is full. An expansion factor between 1 and 2 is reasonable. Default as `1.5`.

`MAX_U32_WINDOW_SIZE`: Represents the max distance of u32 values between packets in an u32 window. Data with sequence `1000` and sequence `101000` may be recognized as increment but discontinuous, but data with sequence `101000` and `1000` may be recognized as expired out of order data. The previous second data will be pushed into the cache, while the latter will be dropped. Default as `4194304` Bytes, or 4 MB.

### Forwarder & Redirector

`TIMEOUT_WAIT`: Same as above. Default as `20` ms.

`MAX_U32_WINDOW_SIZE`: Same as above. Default as `262144` Bytes, or 256 kB.

`ENABLE_TIMESTAMP`: Represents if the TCP timestamp ([RFC 7323](https://tools.ietf.org/html/rfc7323)) option is enabled. The timestamp is useful in "long, fat network" but will also bring performance overhead. Default as `false`.

`TIMESTAMP_RATE`: Represents the frequency of the update of the timestamp. The [RFC 7323](https://tools.ietf.org/html/rfc7323) describes the timestamp clock may not match the system clock and must not be "too fast". And a reasonable value is 1 ms to 1 sec per tick. 1 represents 1 ms and 1000 represents 1 sec per tick. Default as `1` (ms).

`PREFER_SEND_MSS`: Represents if the received send MSS should be preferred instead of manually set MTU in TCP. Default as `true`.

`DUPLICATES_BEFORE_FAST_RETRANSMISSION`: Represents the TCP ACK duplicates before trigger a fast retransmission, also recognized as fast retransmission. Default as `3`.

`RETRANSMISSION_COOL_DOWN`: Represents the cool down time between 2 retransmissions. Default as `200` ms.

`ENABLE_WSCALE`: Represents if the TCP window scale ([RFC 7323](https://tools.ietf.org/html/rfc7323)) option is enabled. Default as `true`.

`MAX_RECV_WSCALE`: Represents the max window scale of the receive window. pcap2socks will open a same-size receive window as the source by default unless the window scale is over the limitation. Default as `8` (x256), or 16MB.

`ENABLE_SACK`: Represents if the TCP selective acknowledgment ([RFC 7323](https://tools.ietf.org/html/rfc7323)) option is enabled. Default as `true`.

`PORT_COUNT`: Represents the max limit of UDP port for binding in local. If the value is too small, rebind will happen frequently and the previous UDP "connection" will be dropped, and may not able to connect to other peer. If the value is too big, the system resource may be largely consumed, so set with a reasonable value. Default as `64`.

## Defects

pcap2socks has some defects in the view of engineering.

- Without timers, some data may be left in the cache and cannot be send out.

- The structure of the `Redirector`, the `SocksStream` & `SocksDatagram` and the `Forwarder` looks like a chaos. Caches and states should be located in the `SocksStream` & `SocksDatagram` instead of the `Redirector` and the `Forwarder`.

- pcap2socks cannot close gracefully, all the data in the receive and send cache will be dropped. The connections will be closed (or shutdown, depending on the kernel or the system) immediately.
