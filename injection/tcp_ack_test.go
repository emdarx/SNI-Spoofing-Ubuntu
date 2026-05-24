//go:build linux || windows

package injection

import "testing"

func TestAckAcceptsPostFakeInboundWraparound(t *testing.T) {
	const fakeLen = 8
	synSeq := int64(0xfffffffc)

	if !ackAcceptsPostFakeInbound(0xfffffffd, synSeq, fakeLen) {
		t.Fatalf("expected duplicate ACK before wrap to be accepted")
	}
	if !ackAcceptsPostFakeInbound(0x00000003, synSeq, fakeLen) {
		t.Fatalf("expected ACK after wrap to be accepted")
	}
	if ackAcceptsPostFakeInbound(0x00000006, synSeq, fakeLen) {
		t.Fatalf("expected ACK outside wrapped fake window to be rejected")
	}
}
