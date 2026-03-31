//go:build darwin

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

// Traceroute sends a burst of TCP probes with increasing TTL (1..maxTTL) on
// the established connection's 5-tuple, then collects ICMP Time Exceeded
// responses. Returns one Hop per TTL level up to the last responding hop;
// hops with no response have IP==nil and RTT==0.
//
// On Darwin (macOS 15+), raw ICMP sockets include the outer IP header:
//
//	buf[0:20]  = outer IP header  (source IP at [12:16])
//	buf[20:28] = ICMP header  (type at [20], code at [21])
//	buf[28:48] = embedded IP header  (probe IP ID at [32:34])
//	buf[48:56] = first 8 bytes of original TCP header
//
// Requires root or the com.apple.security.network.packet-filtering entitlement.
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
	srcIP, dstIP := local.IP.To4(), remote.IP.To4()
	if srcIP == nil || dstIP == nil {
		return nil, nil // IPv6 not supported
	}
	srcPort, dstPort := uint16(local.Port), uint16(remote.Port)

	// Raw socket for sending with full IP header control.
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

	done := make(chan struct{})
	go func() {
		defer close(done)
		const minSize = 56 // 20 outer IP + 8 ICMP + 20 embedded IP + 8 TCP
		buf := make([]byte, 1500)
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			n, _, err := syscall.Recvfrom(recvFd, buf, 0)
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			if err != nil || n < minSize {
				continue
			}
			if buf[20] != 11 || buf[21] != 0 { // ICMP type=11 (Time Exceeded), code=0
				continue
			}
			// Embedded IP header starts at offset 28; IP ID at offset 28+4=32.
			embeddedID := binary.BigEndian.Uint16(buf[32:34])
			// Source IP of the responding router is in the outer IP header at buf[12:16].
			routerIP := make(net.IP, 4)
			copy(routerIP, buf[12:16])

			mu.Lock()
			if p, ok := probes[embeddedID]; ok {
				results[p.ttl] = hopResult{rtt: time.Since(p.sentAt), ip: routerIP}
				delete(probes, embeddedID)
			}
			mu.Unlock()
		}
	}()

	dst := &syscall.SockaddrInet4{}
	copy(dst.Addr[:], dstIP)

	for ttl := 1; ttl <= maxTTL; ttl++ {
		id := baseID + uint16(ttl)
		pkt := buildProbePacket(srcIP, dstIP, srcPort, dstPort, id, uint8(ttl))
		fixIPHeaderForDarwin(pkt)

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

// MeasureRTT returns the RTT in milliseconds of the last responding hop.
// It is a convenience wrapper around Traceroute.
func MeasureRTT(conn net.Conn) (rttMs uint32, err error) {
	hops, err := Traceroute(conn)
	if err != nil || len(hops) == 0 {
		return 0, err
	}
	return uint32(hops[len(hops)-1].RTT.Milliseconds()), nil
}

// fixIPHeaderForDarwin adjusts the IP header for macOS with IP_HDRINCL.
//
// macOS requires ip_len in host byte order (little-endian) and validates it
// against the actual buffer size — sending big-endian causes EINVAL.
// ip_id is sent as-is on the wire (no kernel conversion), so it stays in
// network byte order (big-endian) to match the embedded header in ICMP replies.
// ip_sum is zeroed so the kernel recomputes it correctly after its ip_len swap.
func fixIPHeaderForDarwin(pkt []byte) {
	v := binary.BigEndian.Uint16(pkt[2:4])
	binary.LittleEndian.PutUint16(pkt[2:4], v) // ip_len: little-endian for macOS
	pkt[10], pkt[11] = 0, 0                     // ip_sum: kernel recomputes
}
