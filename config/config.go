// Package config holds runtime settings built from CLI flags.
package config

// Config is the proxy and injection settings for one run (filled from CLI flags in main).
type Config struct {
	ListenHost      string
	ListenPort      int
	ConnectIP       string   // first IPv4 for upstream dial (same as ConnectIPv4s[0] when host has multiple A records)
	ConnectIPv4s    []string // all distinct IPv4 addresses resolved for -connect (order preserved from DNS)
	ConnectPort     int
	FakeSNI         string
	UTLSClientHello string // uTLS preset name; empty means default (HelloChrome_Auto)
}
