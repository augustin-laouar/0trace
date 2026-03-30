//go:build linux

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
// responses. Returns one Hop per TTL level that responded; hops with no
// response have IP==nil and RTT==0.
//
// On Linux, raw ICMP sockets include the outer IP header in received data:
//
//	buf[0:20]  = outer IP header  (source IP at [12:16])
//	buf[20:28] = ICMP header  (type at [20], code at [21])
//	buf[28:48] = embedded IP header  (probe IP ID at [32:34])
//	buf[48:56] = first 8 bytes of original TCP header
//
// Requires CAP_NET_RAW or root. Returns (nil, nil) for non-TCP or IPv6 connections.
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

	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(sendFd)
	if err := syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return nil, err
	}

	recvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(recvFd)
	tv := syscall.NsecToTimeval(int64(100 * time.Millisecond))
	syscall.SetsockoptTimeval(recvFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

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
			n, from, err := syscall.Recvfrom(recvFd, buf, 0)
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			if err != nil || n < minSize {
				continue
			}
			if buf[20] != 11 || buf[21] != 0 { // ICMP type=11 (Time Exceeded), code=0
				continue
			}
			embeddedID := binary.BigEndian.Uint16(buf[32:34])

			var fromIP net.IP
			if sa, ok := from.(*syscall.SockaddrInet4); ok {
				fromIP = net.IP(sa.Addr[:]).To4()
			}

			mu.Lock()
			p, ok := probes[embeddedID]
			if ok {
				results[p.ttl] = hopResult{rtt: time.Since(p.sentAt), ip: fromIP}
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

// MeasureRTT sends a burst of TCP probes with increasing TTL (1..maxTTL) on
// the established connection's 5-tuple, then collects ICMP Time Exceeded
// responses. Returns the RTT in milliseconds of the last (highest TTL)
// responding hop, which approximates the RTT to the remote host.
//
// Requires CAP_NET_RAW or root. Returns (0, nil) for non-TCP or IPv6
// connections so callers can treat this as a best-effort measurement.
func MeasureRTT(conn net.Conn) (rttMs uint32, err error) {
	hops, err := Traceroute(conn)
	if err != nil || len(hops) == 0 {
		return 0, err
	}
	last := hops[len(hops)-1]
	return uint32(last.RTT.Milliseconds()), nil
}
