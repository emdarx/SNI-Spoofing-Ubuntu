package packet

import (
	"bytes"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestSplitClientHelloRecord_Reassembles(t *testing.T) {
	host := "example.com"
	rec, err := BuildClientHelloRecord(host, utls.HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	frags := SplitClientHelloRecord(rec, DefaultSNIChunkBytes)
	var got []byte
	for _, f := range frags {
		got = append(got, f...)
	}
	if !bytes.Equal(got, rec) {
		t.Fatalf("fragments do not reassemble: len got %d want %d", len(got), len(rec))
	}
	s, e, ok := sniValueRange(rec)
	if !ok {
		t.Fatal("sni not found")
	}
	if s > 0 {
		if len(frags) < 1 || !bytes.Equal(frags[0], rec[:s]) {
			t.Fatalf("first fragment must be prefix rec[:s], got len %d", len(frags[0]))
		}
	}
	fi := 0
	if s > 0 {
		fi = 1
	}
	for pos := s; pos < e; fi++ {
		if fi >= len(frags) {
			t.Fatalf("missing hostname chunk at offset %d", pos)
		}
		n := DefaultSNIChunkBytes
		if pos+n > e {
			n = e - pos
		}
		if !bytes.Equal(frags[fi], rec[pos:pos+n]) {
			t.Fatalf("hostname chunk @%d: got %d bytes want %d", pos, len(frags[fi]), n)
		}
		pos += n
	}
	if e < len(rec) {
		if fi >= len(frags) {
			t.Fatal("missing suffix fragment")
		}
		if !bytes.Equal(frags[fi], rec[e:]) {
			t.Fatal("suffix fragment mismatch")
		}
		fi++
	}
	if fi != len(frags) {
		t.Fatalf("fragment count mismatch: consumed %d frags, have %d", fi, len(frags))
	}
}

func TestSplitClientHelloRecord_SNIChunkZero_OneHostnameWrite(t *testing.T) {
	host := "example.com"
	rec, err := BuildClientHelloRecord(host, utls.HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	frags := SplitClientHelloRecord(rec, 0)
	var got []byte
	for _, f := range frags {
		got = append(got, f...)
	}
	if !bytes.Equal(got, rec) {
		t.Fatal("reassemble")
	}
	s, e, ok := sniValueRange(rec)
	if !ok {
		t.Fatal("sni")
	}
	fi := 0
	if s > 0 {
		if !bytes.Equal(frags[0], rec[:s]) {
			t.Fatal("prefix")
		}
		fi = 1
	}
	if !bytes.Equal(frags[fi], rec[s:e]) {
		t.Fatalf("hostname should be one write, got len %d want %d", len(frags[fi]), e-s)
	}
	fi++
	if e < len(rec) {
		if !bytes.Equal(frags[fi], rec[e:]) {
			t.Fatal("suffix")
		}
		fi++
	}
	if fi != len(frags) {
		t.Fatalf("frag count: %d vs %d", fi, len(frags))
	}
}

func TestSplitClientHelloRecord_NegativeChunkLikeZero(t *testing.T) {
	host := "example.com"
	rec, err := BuildClientHelloRecord(host, utls.HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	a := SplitClientHelloRecord(rec, 0)
	b := SplitClientHelloRecord(rec, -3)
	if len(a) != len(b) {
		t.Fatalf("len mismatch: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			t.Fatalf("frag %d differs", i)
		}
	}
}

func TestSNIValueRangeIgnoresEarlierHostnameBytes(t *testing.T) {
	host := "example.com"
	rec, err := BuildClientHelloRecord(host, utls.HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}
	s, e, ok := sniValueRange(rec)
	if !ok {
		t.Fatal("sni not found")
	}
	mutated := append([]byte(nil), rec...)
	copy(mutated[11:], host) // TLS random area, before the extensions block.
	gotS, gotE, ok := sniValueRange(mutated)
	if !ok {
		t.Fatal("sni not found after mutation")
	}
	if gotS != s || gotE != e {
		t.Fatalf("sni range moved to wrong occurrence: got %d:%d want %d:%d", gotS, gotE, s, e)
	}
}
