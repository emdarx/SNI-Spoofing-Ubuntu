package injection

import "testing"

func TestValidateWinDivertFilterExpr_tcp(t *testing.T) {
	if err := ValidateWinDivertFilterExpr("tcp"); err != nil {
		t.Fatal(err)
	}
}

// Regression: local godivert had makeVar() binary-search table out of order, so tcp.SrcPort failed to compile.
func TestValidateWinDivertFilterExpr_tcpSrcPort(t *testing.T) {
	if err := ValidateWinDivertFilterExpr("tcp and tcp.SrcPort == 443"); err != nil {
		t.Fatal(err)
	}
}

func TestBuildConnectWinDivertFilter_Compiles(t *testing.T) {
	f := BuildConnectWinDivertFilter("104.19.229.21", 443)
	const want = "tcp and ((outbound and ip.DstAddr == 104.19.229.21 and tcp.DstPort == 443) or (inbound and ip.SrcAddr == 104.19.229.21 and tcp.SrcPort == 443))"
	if f != want {
		t.Fatalf("filter string\ngot  %q\nwant %q", f, want)
	}
	if err := ValidateWinDivertFilterExpr(f); err != nil {
		t.Fatalf("filter %q: %v", f, err)
	}
}

func TestBuildConnectWinDivertFilterAny_Compiles(t *testing.T) {
	f := BuildConnectWinDivertFilterAny([]string{"104.19.229.21", "104.19.230.21"}, 443)
	const want = "(tcp and ((outbound and ip.DstAddr == 104.19.229.21 and tcp.DstPort == 443) or (inbound and ip.SrcAddr == 104.19.229.21 and tcp.SrcPort == 443)) or tcp and ((outbound and ip.DstAddr == 104.19.230.21 and tcp.DstPort == 443) or (inbound and ip.SrcAddr == 104.19.230.21 and tcp.SrcPort == 443)))"
	if f != want {
		t.Fatalf("filter string\ngot  %q\nwant %q", f, want)
	}
	if err := ValidateWinDivertFilterExpr(f); err != nil {
		t.Fatalf("filter %q: %v", f, err)
	}
}
