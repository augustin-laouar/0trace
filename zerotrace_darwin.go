//go:build darwin

package zerotrace

import "encoding/binary"

// preparePacket adjusts the IP header for macOS with IP_HDRINCL.
//
// macOS requires ip_len in host byte order (little-endian) and validates it
// against the actual buffer size — sending big-endian causes EINVAL.
// ip_id is sent as-is on the wire (no kernel conversion), so it stays in
// network byte order (big-endian) to match the embedded header in ICMP replies.
// ip_sum is zeroed so the kernel recomputes it correctly after its ip_len swap.
func preparePacket(pkt []byte) {
	v := binary.BigEndian.Uint16(pkt[2:4])
	binary.LittleEndian.PutUint16(pkt[2:4], v) // ip_len: little-endian for macOS
	pkt[10], pkt[11] = 0, 0                     // ip_sum: kernel recomputes
}
