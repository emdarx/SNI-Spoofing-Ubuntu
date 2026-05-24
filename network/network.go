// Package network provides utilities for detecting local network interface addresses.
package network

import (
	"net"
)

// IsIPv4 reports whether s is a valid IPv4 address literal (not IPv6).
// This application only supports IPv4; use this to validate config fields.
func IsIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// GetDefaultInterfaceIPv4 discovers the local IPv4 address that would be used
// to reach the given remote address. It uses the UDP "connect" trick:
// connecting a UDP socket to a remote address reveals the local source IP
// without actually sending any data.
func GetDefaultInterfaceIPv4(remoteAddr string) string {
	if remoteAddr == "" {
		remoteAddr = "8.8.8.8"
	}
	conn, err := net.Dial("udp4", net.JoinHostPort(remoteAddr, "53"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
