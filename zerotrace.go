// Package zerotrace measures the network path to a remote host by injecting
// TCP probe packets with increasing TTL values into an established TCP
// connection.
//
// Unlike ICMP ping or classic traceroute, the probes share the 5-tuple of a
// legitimate connection, so they pass through stateful firewalls and NAT
// devices that would otherwise drop unsolicited packets.
//
// Requires root privileges (or CAP_NET_RAW on Linux).
package zerotrace

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"syscall"
	"time"
)

const (
	maxTTL  = 30
	timeout = 2 * time.Second
	stagger = 1 * time.Millisecond
)

// Hop represents a single network hop in a traceroute.
// IP is nil and RTT is 0 if no ICMP response was received for that TTL.
type Hop struct {
	TTL int
	IP  net.IP
	RTT time.Duration
}

type probe struct {
	sentAt time.Time
	ttl    int
}

// Traceroute sends a burst of TCP probes with increasing TTL (1..maxTTL) on
// the established connection's 5-tuple, then collects ICMP Time Exceeded
// responses. Returns one Hop per TTL level up to the last responding hop;
// hops with no response have IP==nil and RTT==0.
//
// The probes use the ACK flag with zeroed sequence numbers: they match the
// connection's 5-tuple so stateful firewalls pass them through, but the wrong
// sequence number ensures the local kernel's TCP state is unaffected.
//
// Returns (nil, nil) for non-TCP or IPv6 connections.
func Traceroute(conn net.Conn) ([]Hop, error) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, nil
	}

	local := tcpConn.LocalAddr().(*net.TCPAddr)
	remote := tcpConn.RemoteAddr().(*net.TCPAddr)
	return TracerouteAddr(local, remote)
}

// TracerouteAddr is like Traceroute but takes an explicit source and
// destination address instead of a net.Conn. Use this when you already know
// the 5-tuple of an established connection (e.g. from another process or from
// netstat output) and do not hold the connection object.
//
// Both addresses must be IPv4; IPv6 is not supported.
func TracerouteAddr(src, dst *net.TCPAddr) ([]Hop, error) {
	srcIP, dstIP := src.IP.To4(), dst.IP.To4()
	if srcIP == nil || dstIP == nil {
		return nil, nil // IPv6 not supported
	}
	return traceroute(srcIP, dstIP, uint16(src.Port), uint16(dst.Port))
}

func traceroute(srcIP, dstIP net.IP, srcPort, dstPort uint16) ([]Hop, error) {
	// Raw socket for sending — IP_HDRINCL lets us set the full IP header,
	// including TTL and IP ID, without kernel interference.
	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(sendFd)
	if err := syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return nil, err
	}

	// Raw ICMP socket for receiving Time Exceeded responses.
	recvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(recvFd)
	// Poll every 100 ms so the receive loop can check its deadline.
	tv := syscall.NsecToTimeval(int64(100 * time.Millisecond))
	syscall.SetsockoptTimeval(recvFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Random base IP ID to avoid collisions with concurrent sessions.
	var idBuf [2]byte
	rand.Read(idBuf[:])
	baseID := binary.BigEndian.Uint16(idBuf[:])

	type hopResult struct {
		rtt time.Duration
		ip  net.IP
	}

	var mu sync.Mutex
	probes := make(map[uint16]probe, maxTTL)
	results := make(map[int]hopResult, maxTTL)

	// Receive goroutine: collect ICMP Time Exceeded until the global deadline.
	//
	// ICMP buffer layout (Linux and macOS 15+):
	//   buf[0:20]  outer IP header
	//   buf[20]    ICMP type  (11 = Time Exceeded)
	//   buf[21]    ICMP code  (0 = TTL exceeded in transit)
	//   buf[28:48] embedded IP header of the original probe
	//   buf[32:34] IP ID of the probe — used to correlate with the sent probe
	done := make(chan struct{})
	go func() {
		defer close(done)
		const minSize = 56 // 20 outer IP + 8 ICMP + 20 embedded IP + 8 TCP
		buf := make([]byte, 1500)
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			n, from, err := syscall.Recvfrom(recvFd, buf, 0)
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			if err != nil || n < minSize {
				continue
			}
			if buf[20] != 11 || buf[21] != 0 {
				continue
			}
			embeddedID := binary.BigEndian.Uint16(buf[32:34])

			var fromIP net.IP
			if sa, ok := from.(*syscall.SockaddrInet4); ok {
				fromIP = net.IP(sa.Addr[:]).To4()
			}

			mu.Lock()
			if p, ok := probes[embeddedID]; ok {
				results[p.ttl] = hopResult{rtt: time.Since(p.sentAt), ip: fromIP}
				delete(probes, embeddedID)
			}
			mu.Unlock()
		}
	}()

	// Send loop: fire all probes in rapid succession (1 ms stagger).
	dst := &syscall.SockaddrInet4{}
	copy(dst.Addr[:], dstIP)

	for ttl := 1; ttl <= maxTTL; ttl++ {
		id := baseID + uint16(ttl)
		pkt := buildProbePacket(srcIP, dstIP, srcPort, dstPort, id, uint8(ttl))
		preparePacket(pkt) // platform-specific IP header adjustments

		mu.Lock()
		probes[id] = probe{sentAt: time.Now(), ttl: ttl}
		mu.Unlock()

		syscall.Sendto(sendFd, pkt, 0, dst)
		time.Sleep(stagger)
	}

	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(results) == 0 {
		return nil, nil
	}

	lastTTL := 0
	for ttl := range results {
		if ttl > lastTTL {
			lastTTL = ttl
		}
	}

	hops := make([]Hop, lastTTL)
	for i := range hops {
		ttl := i + 1
		hops[i] = Hop{TTL: ttl}
		if r, ok := results[ttl]; ok {
			hops[i].IP = r.ip
			hops[i].RTT = r.rtt
		}
	}
	return hops, nil
}

// MeasureRTT is a convenience wrapper around Traceroute that returns the RTT
// in milliseconds of the last responding hop — an approximation of the RTT to
// the remote host. Returns (0, nil) when no hops respond.
func MeasureRTT(conn net.Conn) (rttMs uint32, err error) {
	hops, err := Traceroute(conn)
	if err != nil || len(hops) == 0 {
		return 0, err
	}
	last := hops[len(hops)-1]
	return uint32(last.RTT.Milliseconds()), nil
}

// MeasureRTTAddr is like MeasureRTT but takes an explicit 5-tuple.
func MeasureRTTAddr(src, dst *net.TCPAddr) (rttMs uint32, err error) {
	hops, err := TracerouteAddr(src, dst)
	if err != nil || len(hops) == 0 {
		return 0, err
	}
	last := hops[len(hops)-1]
	return uint32(last.RTT.Milliseconds()), nil
}

// buildProbePacket builds a 40-byte raw IP+TCP probe packet.
// The TCP segment uses the ACK flag with zeroed seq/ack numbers: it matches
// the connection's 5-tuple so stateful firewalls pass it through, but the
// wrong sequence number ensures the local kernel TCP state is unaffected.
func buildProbePacket(src, dst net.IP, srcPort, dstPort, id uint16, ttl uint8) []byte {
	pkt := make([]byte, 40) // 20 IP + 20 TCP

	// IP header
	pkt[0] = 0x45 // version=4, IHL=5
	// pkt[1] = 0   DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:], 40) // total length
	binary.BigEndian.PutUint16(pkt[4:], id) // identification — used for correlation
	// pkt[6:8] = 0  flags + fragment offset
	pkt[8] = ttl // TTL
	pkt[9] = 6   // protocol: TCP
	// pkt[10:12]   checksum — filled below
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[10:], ipChecksum(pkt[:20]))

	// TCP header
	binary.BigEndian.PutUint16(pkt[20:], srcPort)
	binary.BigEndian.PutUint16(pkt[22:], dstPort)
	// pkt[24:32] = 0  seq=0, ack=0
	pkt[32] = 0x50 // data offset=5 (20 bytes), reserved=0
	pkt[33] = 0x10 // flags: ACK
	binary.BigEndian.PutUint16(pkt[34:], 1024) // window
	// pkt[36:38]   checksum — filled below
	// pkt[38:40] = 0  urgent pointer
	binary.BigEndian.PutUint16(pkt[36:], tcpChecksum(src, dst, pkt[20:40]))

	return pkt
}

// ipChecksum computes the Internet checksum (RFC 1071).
func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum using the IPv4 pseudo-header.
func tcpChecksum(src, dst net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	// pseudo[8] = 0  zero byte
	pseudo[9] = 6 // protocol: TCP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	return ipChecksum(pseudo)
}
