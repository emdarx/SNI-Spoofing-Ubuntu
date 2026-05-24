package packet

import (
	"encoding/binary"
	"net"
)

// RecalculateIPv4AndTCPChecksums sets IPv4 header and TCP segment checksums for a raw IPv4+TCP packet.
func RecalculateIPv4AndTCPChecksums(raw []byte) {
	ipv4HeaderChecksum(raw)
	tcpChecksumIPv4(raw)
}

func ipv4HeaderChecksum(raw []byte) {
	ipHdrLen := IPHeaderLen(raw)
	if ipHdrLen < 20 || len(raw) < ipHdrLen {
		return
	}
	raw[10] = 0
	raw[11] = 0
	sum := checksumRFC1071(raw[:ipHdrLen])
	binary.BigEndian.PutUint16(raw[10:12], sum)
}

func tcpChecksumIPv4(raw []byte) {
	ipHdrLen := IPHeaderLen(raw)
	if ipHdrLen < 20 || len(raw) < ipHdrLen+20 {
		return
	}
	srcIP := net.IP(raw[12:16]).To4()
	dstIP := net.IP(raw[16:20]).To4()
	if srcIP == nil || dstIP == nil {
		return
	}
	tcpSegment := raw[ipHdrLen:]
	if len(tcpSegment) < 20 {
		return
	}
	tcpLen := len(tcpSegment)

	tcpSegment[16] = 0
	tcpSegment[17] = 0

	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[8] = 0
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))

	data := make([]byte, 0, len(pseudo)+tcpLen)
	data = append(data, pseudo...)
	data = append(data, tcpSegment...)

	sum := checksumRFC1071(data)
	binary.BigEndian.PutUint16(tcpSegment[16:18], sum)
}

func checksumRFC1071(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
