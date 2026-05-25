package packet

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestBuildClientHelloRecord_ChromeAuto(t *testing.T) {
	host := "auth.vercel.com"
	record, err := BuildClientHelloRecord(host, utls.HelloChrome_Auto)
	if err != nil {
		t.Fatalf("BuildClientHelloRecord: %v", err)
	}
	if len(record) < 200 {
		t.Fatalf("unexpected ClientHello length: %d", len(record))
	}
	if record[0] != 0x16 {
		t.Errorf("expected TLS record type 0x16, got 0x%02x", record[0])
	}
	if record[1] != 0x03 || record[2] != 0x03 {
		t.Errorf("expected record version 0x0303 (VersionTLS12), got 0x%02x%02x", record[1], record[2])
	}
	if !bytes.Contains(record, []byte(host)) {
		t.Errorf("record does not contain SNI hostname %q", host)
	}
	t.Logf("ClientHello length: %d bytes", len(record))
	t.Logf("ClientHello (first 32 bytes): %s", hex.EncodeToString(record[:32]))
}

func TestBuildClientHelloRecord_EmptyServerName(t *testing.T) {
	_, err := BuildClientHelloRecord("", utls.HelloChrome_Auto)
	if err == nil {
		t.Fatal("expected error for empty server name")
	}
}

func TestBuildLegacyClientHelloRecord(t *testing.T) {
	host := "auth.vercel.com"
	record, err := BuildLegacyClientHelloRecord(host)
	if err != nil {
		t.Fatalf("BuildLegacyClientHelloRecord: %v", err)
	}
	if len(record) != 517 {
		t.Fatalf("legacy ClientHello length = %d, want 517", len(record))
	}
	if record[0] != 0x16 {
		t.Errorf("expected TLS record type 0x16, got 0x%02x", record[0])
	}
	if !bytes.Contains(record, []byte(host)) {
		t.Errorf("record does not contain SNI hostname %q", host)
	}
}

func TestBuildLegacyClientHelloRecord_TooLongServerName(t *testing.T) {
	_, err := BuildLegacyClientHelloRecord(strings.Repeat("a", MaxLegacyFakeSNILen+1))
	if err == nil {
		t.Fatal("expected error for too-long server name")
	}
}

func TestParseClientHelloID(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want utls.ClientHelloID
	}{
		{"", utls.HelloFirefox_Auto},
		{"chrome_133", utls.HelloChrome_133},
		{"chrome", utls.HelloChrome_Auto},
		{"Firefox-120", utls.HelloFirefox_120},
		{"firefox_120", utls.HelloFirefox_120},
		{"firefox", utls.HelloFirefox_Auto},
	} {
		got, err := ParseClientHelloID(tc.in)
		if err != nil {
			t.Fatalf("ParseClientHelloID(%q): %v", tc.in, err)
		}
		if got.Str() != tc.want.Str() {
			t.Fatalf("ParseClientHelloID(%q): got %v want %v", tc.in, got.Str(), tc.want.Str())
		}
	}
	if _, err := ParseClientHelloID("no_such_preset_xyz"); err == nil {
		t.Fatal("expected error for unknown preset")
	}
	if _, err := ParseClientHelloID("chrome_auto"); err == nil {
		t.Fatal("expected error for removed *_auto alias")
	}
	if _, err := ParseClientHelloID("hellofirefox_120"); err == nil {
		t.Fatal("expected error for hello* form")
	}
	if _, err := ParseClientHelloID("none"); err == nil {
		t.Fatal("expected error for legacy none preset")
	}
}

func TestIsLegacyUTLS(t *testing.T) {
	for _, s := range []string{"none", " None ", "NONE"} {
		if !IsLegacyUTLS(s) {
			t.Fatalf("IsLegacyUTLS(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "chrome", "none_"} {
		if IsLegacyUTLS(s) {
			t.Fatalf("IsLegacyUTLS(%q) = true, want false", s)
		}
	}
}

func TestUTLSHelpGroupedCSV(t *testing.T) {
	s := UTLSHelpGroupedCSV()
	if len(s) < 100 || !strings.Contains(s, "none") || !strings.Contains(s, "chrome_120") || !strings.Contains(s, "chrome,") {
		t.Fatalf("unexpected grouped help: len=%d", len(s))
	}
}

func TestCanonicalUTLSKeysUnique(t *testing.T) {
	seen := make(map[string]string)
	for _, id := range presetClientHelloIDs {
		k := canonicalUTLSKey(id)
		if prev, ok := seen[k]; ok {
			t.Fatalf("duplicate canonical key %q for %s and %s", k, prev, id.Str())
		}
		seen[k] = id.Str()
	}
}

func TestCanonicalUTLSKey_noPlaceholderZero(t *testing.T) {
	if canonicalUTLSKey(utls.HelloGolang) != "golang" {
		t.Fatalf("golang: got %q", canonicalUTLSKey(utls.HelloGolang))
	}
	if canonicalUTLSKey(utls.HelloRandomizedALPN) != "randomized_alpn" {
		t.Fatalf("randomized alpn: got %q", canonicalUTLSKey(utls.HelloRandomizedALPN))
	}
	if canonicalUTLSKey(utls.HelloSafari_16_0) != "safari_16_0" {
		t.Fatalf("safari 16.0 must keep _0 in version: got %q", canonicalUTLSKey(utls.HelloSafari_16_0))
	}
}

func TestTCPHeaderParsing(t *testing.T) {
	raw := make([]byte, 40)

	raw[0] = 0x45
	raw[2] = 0x00
	raw[3] = 40
	raw[4] = 0x12
	raw[5] = 0x34
	raw[9] = 6
	raw[12] = 192
	raw[13] = 168
	raw[14] = 1
	raw[15] = 1
	raw[16] = 10
	raw[17] = 0
	raw[18] = 0
	raw[19] = 1

	raw[20] = 0x1F
	raw[21] = 0x40
	raw[22] = 0x01
	raw[23] = 0xBB
	raw[24] = 0x12
	raw[25] = 0x34
	raw[26] = 0x56
	raw[27] = 0x78
	raw[28] = 0x9A
	raw[29] = 0xBC
	raw[30] = 0xDE
	raw[31] = 0xF0
	raw[32] = 0x50
	raw[33] = 0x12

	if v := IPVersion(raw); v != 4 {
		t.Errorf("IPVersion: got %d, want 4", v)
	}

	if l := IPHeaderLen(raw); l != 20 {
		t.Errorf("IPHeaderLen: got %d, want 20", l)
	}

	srcIP := IPv4SrcAddr(raw)
	if srcIP.String() != "192.168.1.1" {
		t.Errorf("SrcIP: got %s, want 192.168.1.1", srcIP)
	}

	dstIP := IPv4DstAddr(raw)
	if dstIP.String() != "10.0.0.1" {
		t.Errorf("DstIP: got %s, want 10.0.0.1", dstIP)
	}

	if l := IPv4TotalLen(raw); l != 40 {
		t.Errorf("IPv4TotalLen: got %d, want 40", l)
	}

	if id := IPv4Ident(raw); id != 0x1234 {
		t.Errorf("IPv4Ident: got 0x%04x, want 0x1234", id)
	}

	if p := TCPSrcPort(raw); p != 8000 {
		t.Errorf("TCPSrcPort: got %d, want 8000", p)
	}
	if p := TCPDstPort(raw); p != 443 {
		t.Errorf("TCPDstPort: got %d, want 443", p)
	}

	if s := TCPSeqNum(raw); s != 0x12345678 {
		t.Errorf("TCPSeqNum: got 0x%08x, want 0x12345678", s)
	}
	if a := TCPAckNum(raw); a != 0x9ABCDEF0 {
		t.Errorf("TCPAckNum: got 0x%08x, want 0x9ABCDEF0", a)
	}

	flags := GetTCPFlags(raw)
	if !flags.SYN {
		t.Error("expected SYN flag set")
	}
	if !flags.ACK {
		t.Error("expected ACK flag set")
	}
	if flags.RST {
		t.Error("expected RST flag clear")
	}
	if flags.FIN {
		t.Error("expected FIN flag clear")
	}
	if flags.PSH {
		t.Error("expected PSH flag clear")
	}

	if l := TCPPayloadLen(raw); l != 0 {
		t.Errorf("TCPPayloadLen: got %d, want 0", l)
	}

	SetTCPSeqNum(raw, 0xDEADBEEF)
	if s := TCPSeqNum(raw); s != 0xDEADBEEF {
		t.Errorf("after SetTCPSeqNum: got 0x%08x, want 0xDEADBEEF", s)
	}

	SetTCPFlag(raw, "psh", true)
	flags = GetTCPFlags(raw)
	if !flags.PSH {
		t.Error("expected PSH flag set after SetTCPFlag")
	}
	if !flags.SYN {
		t.Error("SYN flag should still be set")
	}

	SetTCPFlag(raw, "syn", false)
	flags = GetTCPFlags(raw)
	if flags.SYN {
		t.Error("SYN flag should be cleared")
	}
	if !flags.ACK {
		t.Error("ACK flag should still be set")
	}

	payload := []byte("Hello, World!")
	newRaw := SetTCPPayload(raw, payload)
	if l := IPv4TotalLen(newRaw); l != uint16(40+len(payload)) {
		t.Errorf("after SetTCPPayload, total len: got %d, want %d", l, 40+len(payload))
	}
	if l := TCPPayloadLen(newRaw); l != len(payload) {
		t.Errorf("after SetTCPPayload, payload len: got %d, want %d", l, len(payload))
	}
	if string(TCPPayload(newRaw)) != "Hello, World!" {
		t.Errorf("payload content mismatch: got %q", string(TCPPayload(newRaw)))
	}

	t.Logf("TCP header parsing tests passed")
}
