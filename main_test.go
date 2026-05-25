package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"sni-spoofing-go/config"
	"sni-spoofing-go/packet"
)

func TestConfigPathFromArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-config", "custom.ini"}, "custom.ini"},
		{[]string{"--config", "custom.ini"}, "custom.ini"},
		{[]string{"-config=custom.ini"}, "custom.ini"},
		{[]string{"--config=custom.ini"}, "custom.ini"},
	} {
		got, ok, err := configPathFromArgs(tc.args)
		if err != nil {
			t.Fatalf("configPathFromArgs(%v): %v", tc.args, err)
		}
		if !ok || got != tc.want {
			t.Fatalf("configPathFromArgs(%v) = %q, %v; want %q, true", tc.args, got, ok, tc.want)
		}
	}
}

func TestApplyOptionDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.ini")
	if err := os.WriteFile(path, []byte(`
listen = 127.0.0.1:8080
connect = example.com:443
utls = none
fake-delay = 0s
enable-fragment = true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	fileOpts, err := config.LoadFileOptions(path)
	if err != nil {
		t.Fatal(err)
	}

	var listen, connect, fakeSNI, utls string
	var fakeRepeat, sniChunk int
	var fakeDelay, ackTimeout, fragmentDelay time.Duration
	var enableFragment bool

	applyOptionDefaults(fileOpts, &listen, &connect, &fakeSNI, &utls, &fakeRepeat, &fakeDelay, &ackTimeout, &enableFragment, &fragmentDelay, &sniChunk)

	if listen != "127.0.0.1:8080" || connect != "example.com:443" || utls != "none" {
		t.Fatalf("string defaults = %q %q %q", listen, connect, utls)
	}
	if fakeRepeat != 1 || fakeDelay != 0 || ackTimeout != 2*time.Second {
		t.Fatalf("numeric defaults repeat=%d fakeDelay=%v ackTimeout=%v", fakeRepeat, fakeDelay, ackTimeout)
	}
	if !enableFragment || fragmentDelay != 500*time.Millisecond || sniChunk != packet.DefaultSNIChunkBytes {
		t.Fatalf("fragment defaults enable=%v delay=%v chunk=%d", enableFragment, fragmentDelay, sniChunk)
	}
}
