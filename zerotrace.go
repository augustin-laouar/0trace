// Package zerotrace measures the RTT to a remote host by injecting TCP probe
// packets with increasing TTL values into an established TCP connection.
//
// Unlike ICMP ping, this technique works through stateful firewalls because
// the probe packets share the 5-tuple of a legitimate connection.
//
// Requires root privileges (or CAP_NET_RAW on Linux).
package zerotrace

import (
	"encoding/binary"
	"net"
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
	binary.BigEndian.PutUint16(pkt[10:], onesComplement(pkt[:20]))

	// TCP header
	binary.BigEndian.PutUint16(pkt[20:], srcPort)
	binary.BigEndian.PutUint16(pkt[22:], dstPort)
	// pkt[24:32] = 0  seq=0, ack=0
	pkt[32] = 0x50 // data offset=5 (20 bytes), reserved=0
	pkt[33] = 0x10 // flags: ACK
	binary.BigEndian.PutUint16(pkt[34:], 1024) // window
	// pkt[36:38]   checksum — filled below
	// pkt[38:40] = 0  urgent pointer
	binary.BigEndian.PutUint16(pkt[36:], tcpOnesComplement(src, dst, pkt[20:40]))

	return pkt
}

// onesComplement computes the Internet checksum (RFC 1071).
func onesComplement(b []byte) uint16 {
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

// tcpOnesComplement computes the TCP checksum using the IPv4 pseudo-header.
func tcpOnesComplement(src, dst net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	// pseudo[8] = 0  zero byte
	pseudo[9] = 6 // protocol: TCP
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	return onesComplement(pseudo)
}
