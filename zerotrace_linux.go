//go:build linux

package zerotrace

// preparePacket is a no-op on Linux: the kernel sends IP_HDRINCL packets
// with the header exactly as provided (big-endian ip_len, big-endian ip_id).
func preparePacket(pkt []byte) {}
