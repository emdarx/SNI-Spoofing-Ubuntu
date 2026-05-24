package injection

import (
	"fmt"
	"strings"

	"github.com/one-api/godivert/compile"
	"github.com/one-api/godivert/types"
)

// BuildConnectWinDivertFilter is the WinDivert filter for one upstream IPv4:port (dial target).
// Outbound: dst IP and dst port. Inbound from server: src IP and src port.
func BuildConnectWinDivertFilter(connectIP string, port uint16) string {
	return fmt.Sprintf(
		"tcp and ((outbound and ip.DstAddr == %s and tcp.DstPort == %d) or (inbound and ip.SrcAddr == %s and tcp.SrcPort == %d))",
		connectIP, port, connectIP, port,
	)
}

// BuildConnectWinDivertFilterAny is the WinDivert filter for any configured upstream IPv4:port.
func BuildConnectWinDivertFilterAny(connectIPs []string, port uint16) string {
	if len(connectIPs) == 0 {
		return "false"
	}
	parts := make([]string, 0, len(connectIPs))
	for _, ip := range connectIPs {
		parts = append(parts, BuildConnectWinDivertFilter(ip, port))
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// ValidateWinDivertFilterExpr checks that a filter string compiles for the network layer.
func ValidateWinDivertFilterExpr(filter string) error {
	_, err := compile.CompileFilter(filter, types.LayerNetwork)
	return err
}
