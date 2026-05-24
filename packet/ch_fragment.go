package packet

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"time"
)

const maxTLSPlaintextRecord = 1<<14 + 2048

const DefaultSNIChunkBytes = 3

func ReadFirstTLSRecord(r io.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 22 {
		return nil, fmt.Errorf("packet: want TLS handshake record (22), got type %d", hdr[0])
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n <= 0 || n > maxTLSPlaintextRecord {
		return nil, fmt.Errorf("packet: invalid TLS record length %d", n)
	}
	out := make([]byte, 5+n)
	copy(out, hdr[:])
	if _, err := io.ReadFull(r, out[5:]); err != nil {
		return nil, err
	}
	return out, nil
}

func sniValueRange(record []byte) (start, end int, ok bool) {
	if len(record) < 5 || record[0] != 22 {
		return 0, 0, false
	}
	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if recordLen <= 0 || len(record) < 5+recordLen {
		return 0, 0, false
	}
	hs := record[5 : 5+recordLen]
	if len(hs) < 4 || hs[0] != 1 {
		return 0, 0, false
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if hsLen <= 0 || len(hs) < 4+hsLen {
		return 0, 0, false
	}
	body := hs[4 : 4+hsLen]
	pos := 2 + 32 // legacy_version + random
	if len(body) < pos+1 {
		return 0, 0, false
	}
	sessionLen := int(body[pos])
	pos++
	if len(body) < pos+sessionLen+2 {
		return 0, 0, false
	}
	pos += sessionLen
	cipherLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if len(body) < pos+cipherLen+1 {
		return 0, 0, false
	}
	pos += cipherLen
	compressionLen := int(body[pos])
	pos++
	if len(body) < pos+compressionLen {
		return 0, 0, false
	}
	pos += compressionLen
	if len(body) == pos {
		return 0, 0, false
	}
	if len(body) < pos+2 {
		return 0, 0, false
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if len(body) < pos+extensionsLen {
		return 0, 0, false
	}
	extensionsEnd := pos + extensionsLen
	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		extDataStart := pos + 4
		extDataEnd := extDataStart + extLen
		if extDataEnd > extensionsEnd {
			return 0, 0, false
		}
		if extType == 0 {
			s, e, ok := sniNameRangeInExtension(body[extDataStart:extDataEnd])
			if !ok {
				return 0, 0, false
			}
			abs := 5 + 4 + extDataStart
			return abs + s, abs + e, true
		}
		pos = extDataEnd
	}
	return 0, 0, false
}

func sniNameRangeInExtension(ext []byte) (start, end int, ok bool) {
	if len(ext) < 2 {
		return 0, 0, false
	}
	listLen := int(binary.BigEndian.Uint16(ext[:2]))
	pos := 2
	if listLen <= 0 || len(ext) < pos+listLen {
		return 0, 0, false
	}
	listEnd := pos + listLen
	for pos+3 <= listEnd {
		nameType := ext[pos]
		nameLen := int(binary.BigEndian.Uint16(ext[pos+1 : pos+3]))
		nameStart := pos + 3
		nameEnd := nameStart + nameLen
		if nameEnd > listEnd {
			return 0, 0, false
		}
		if nameType == 0 && nameLen > 0 {
			return nameStart, nameEnd, true
		}
		pos = nameEnd
	}
	return 0, 0, false
}

func SplitClientHelloRecord(record []byte, sniChunkBytes int) [][]byte {
	if sniChunkBytes < 0 {
		sniChunkBytes = 0
	}
	if len(record) == 0 {
		return nil
	}
	s, e, ok := sniValueRange(record)
	if !ok || e <= s {
		return [][]byte{record}
	}
	var out [][]byte
	if s > 0 {
		out = append(out, record[:s])
	}
	if sniChunkBytes <= 0 {
		out = append(out, record[s:e])
	} else {
		for i := s; i < e; i += sniChunkBytes {
			j := i + sniChunkBytes
			if j > e {
				j = e
			}
			out = append(out, record[i:j])
		}
	}
	if e < len(record) {
		out = append(out, record[e:])
	}
	if len(out) == 0 {
		return [][]byte{record}
	}
	return out
}

func WriteClientHelloFragments(w io.Writer, frags [][]byte, delay time.Duration, tcp interface{ SetNoDelay(bool) error }, logEachFragment bool) error {
	if tcp != nil {
		_ = tcp.SetNoDelay(true)
		defer func() { _ = tcp.SetNoDelay(false) }()
	}
	nFrag := 0
	for _, p := range frags {
		if len(p) > 0 {
			nFrag++
		}
	}
	sent := 0
	for _, p := range frags {
		if len(p) == 0 {
			continue
		}
		if sent > 0 && delay > 0 {
			time.Sleep(delay)
		}
		sent++
		if _, err := w.Write(p); err != nil {
			return err
		}
		if logEachFragment {
			log.Printf("ClientHello fragment %d/%d sent (%d bytes)", sent, nFrag, len(p))
		}
	}
	return nil
}
