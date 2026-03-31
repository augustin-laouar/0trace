# 0trace

A Go implementation of the 0trace technique, published as a reusable module.

## What is 0trace?

0trace is a network path measurement technique that piggybacks on an existing TCP connection to perform a traceroute-like hop enumeration — without being blocked by stateful firewalls.

Classic traceroute sends standalone UDP or ICMP packets. Stateful firewalls drop these because they belong to no known connection. 0trace instead injects TCP probe packets that share the **5-tuple** (src IP, dst IP, src port, dst port, protocol) of a legitimate established connection. Because the probes look like traffic from a real session, they are forwarded by firewalls and NAT devices just like normal traffic.

Each probe has an incrementing TTL. When a router decrements the TTL to zero, it discards the packet and sends back an **ICMP Time Exceeded** message. That ICMP reply contains the original probe's IP header, including its IP ID, which is used to correlate the response with the original probe and measure the RTT.

The technique was originally described in the paper:
> *0trace — a zero-hop traceroute* — Michał Zalewski, 2007

## What this module implements

- `Traceroute(conn net.Conn) ([]Hop, error)` — performs a 0trace on an established TCP connection and returns one `Hop` per TTL level up to the last responding router. Hops that received no ICMP reply have `IP == nil` and `RTT == 0`.
- `MeasureRTT(conn net.Conn) (rttMs uint32, error)` — convenience wrapper that returns only the RTT of the last responding hop, as an approximation of the end-to-end RTT.

```go
type Hop struct {
    TTL int
    IP  net.IP
    RTT time.Duration
}
```

Platform support:

| OS    | Status |
|-------|--------|
| Linux | supported (requires `CAP_NET_RAW` or root) |
| macOS | supported (requires root) |
| Windows | not implemented |

No external dependencies — stdlib only.

## Limitations

0trace relies on routers sending ICMP Time Exceeded replies. On the public internet many routers rate-limit or drop these replies for TCP probes, so results are best-effort. The technique works most reliably on controlled networks or from a host with a direct public IP (no NAT).

## Installation

```bash
go get github.com/augustin-laouar/zerotrace
```

## Usage

```go
import "github.com/augustin-laouar/zerotrace"

// conn must be an established *net.TCPConn (or *tls.Conn wrapping one)
hops, err := zerotrace.Traceroute(conn)
if err != nil {
    log.Fatal(err)
}
for _, h := range hops {
    if h.IP == nil {
        fmt.Printf("%3d  * * *\n", h.TTL)
    } else {
        fmt.Printf("%3d  %-15s  %d ms\n", h.TTL, h.IP, h.RTT.Milliseconds())
    }
}
```

## Example: cmd/measure

`cmd/measure` is a minimal CLI that opens an HTTP or HTTPS connection to a target and runs a 0trace on it.

```bash
# build
go build -o measure ./cmd/measure/

# run (requires root)
sudo ./measure https://example.com
sudo ./measure http://example.com:8080
```

Example output:

```
traceroute to https://example.com
  1  192.168.1.1      1 ms
  2  * * *
  3  10.0.0.1         5 ms
  4  * * *
  5  198.51.100.4     18 ms
```

The binary sends a `GET` request on the connection before probing, to ensure NAT mappings stay alive for the duration of the measurement.
