// TLS proxy: fake ClientHello injection (wrong-seq) + optional real CH fragmentation. IPv4 only; needs admin/root.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"

	"sni-spoofing-go/config"
	"sni-spoofing-go/injection"
	"sni-spoofing-go/network"
	"sni-spoofing-go/packet"
)

const firstClientHelloTimeout = 10 * time.Second

func usage() {
	exe := os.Args[0]
	w := os.Stderr
	fmt.Fprintf(w, "SNI-Spoofing — fake TLS ClientHello (SNI) injection proxy. IPv4 only; run as Administrator / root.\n\n")
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  %s -listen <addr> -connect <addr> [options]\n\n", exe)
	fmt.Fprintf(w, "Required:\n")
	fmt.Fprintf(w, "  -listen <host:port>   listen address (host optional, e.g. :8080)\n")
	fmt.Fprintf(w, "  -connect <host:port>  upstream; hostname (SNI from host) or IPv4 (needs -fake-sni)\n\n")
	fmt.Fprintf(w, "Optional:\n")
	fmt.Fprintf(w, "  -fake-sni <hostname>  SNI in the injected ClientHello (overrides -connect hostname)\n")
	fmt.Fprintf(w, "  -fake-repeat <n>      fake ClientHello injections before real traffic (default 1)\n")
	fmt.Fprintf(w, "  -fake-delay          delay after fake injection (default 2ms)\n")
	fmt.Fprintf(w, "  -ack-timeout         max wait for server ACK after fake injection (default 2s)\n")
	fmt.Fprintf(w, "  -utls <name>         TLS fingerprint (default: chrome); list below\n")
	fmt.Fprintf(w, "  -enable-fragment     fragment real ClientHello (prefix / SNI chunks / suffix); default false\n")
	fmt.Fprintf(w, "  -fragment-delay      delay between TCP segments when ClientHello is split (default 500ms)\n")
	fmt.Fprintf(w, "  -sni-chunk            SNI bytes per TCP write after prefix (default 3; 0 = whole name in one write)\n")
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "Examples:\n")
	fmt.Fprintf(w, "  %s -listen 127.0.0.1:8080 -connect example.com:443\n", exe)
	fmt.Fprintf(w, "  %s -listen 127.0.0.1:8080 -connect 198.51.100.2:443 -fake-sni allowed.example.com\n\n", exe)
	fmt.Fprintf(w, "Valid -utls names:\n\n")
	fmt.Fprintf(w, "%s", packet.UTLSHelpGroupedCSV())
	fmt.Fprintf(w, "\nDefault when -utls is omitted: %s.\n\n", packet.DefaultUTLSSummary())
	fmt.Fprintf(w, "Options:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	var optListen, optConnect, optFakeSNI, optUTLS string
	var enableFragment bool
	var fragmentDelay time.Duration
	var sniChunk int
	var fakeRepeat int
	var ackTimeout time.Duration
	var fakeDelay time.Duration
	flag.StringVar(&optListen, "listen", "", "listen address host:port (required)")
	flag.StringVar(&optConnect, "connect", "", "upstream host:port (required)")
	flag.StringVar(&optFakeSNI, "fake-sni", "", "injected ClientHello SNI (optional if -connect uses a hostname)")
	flag.IntVar(&fakeRepeat, "fake-repeat", 1, "number of wrong-seq fake ClientHello injections before real traffic")
	flag.DurationVar(&fakeDelay, "fake-delay", 2*time.Millisecond, "delay after fake injection (0 = none)")
	flag.StringVar(&optUTLS, "utls", "", "TLS fingerprint preset (see usage above; e.g. chrome_120, firefox)")
	flag.BoolVar(&enableFragment, "enable-fragment", false, "after fake SNI, read real ClientHello: send prefix, then SNI chunks, then suffix")
	flag.DurationVar(&fragmentDelay, "fragment-delay", 500*time.Millisecond, "delay between TCP segments when fake or real ClientHello is split (MSS / chunking)")
	flag.IntVar(&sniChunk, "sni-chunk", packet.DefaultSNIChunkBytes, "SNI hostname bytes per TCP write (0 = entire hostname in one write)")
	flag.DurationVar(&ackTimeout, "ack-timeout", 2*time.Second, "timeout waiting for server ACK after fake injection")
	flag.Parse()

	cliListen, cliConnect := false, false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "listen":
			cliListen = true
		case "connect":
			cliConnect = true
		}
	})

	fakeSNIArg := strings.TrimSpace(optFakeSNI)

	args := flag.Args()
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected arguments: %q\n", args)
		fmt.Fprintln(os.Stderr)
		usage()
		os.Exit(2)
	}
	if !cliListen || !cliConnect {
		log.Fatal("required flags: -listen and -connect")
	}
	if fakeRepeat < 1 {
		log.Fatal("-fake-repeat must be at least 1")
	}
	if sniChunk < 0 {
		log.Fatal("-sni-chunk must be >= 0 (0 = whole hostname in one write)")
	}
	if ackTimeout <= 0 {
		log.Fatal("-ack-timeout must be positive (e.g. 2s, 5s, 1m)")
	}

	cfg, err := config.ConnectFromCLI(optListen, optConnect, fakeSNIArg)
	if err != nil {
		log.Fatal("Invalid configuration: ", err)
	}

	if strings.TrimSpace(optUTLS) != "" {
		cfg.UTLSClientHello = optUTLS
	}
	clientHelloID, err := packet.ParseClientHelloID(cfg.UTLSClientHello)
	if err != nil {
		log.Fatal("Invalid -utls: ", err)
	}

	if !network.IsIPv4(cfg.ConnectIP) {
		log.Fatalf("upstream must resolve to IPv4 (IPv6 is not supported): %q", cfg.ConnectIP)
	}
	if len(cfg.ConnectIPv4s) == 0 {
		log.Fatal("internal error: no ConnectIPv4s after resolve")
	}
	if cfg.ListenHost != "" && !network.IsIPv4(cfg.ListenHost) {
		log.Fatalf("LISTEN host must be IPv4 or empty (IPv6 is not supported): %q", cfg.ListenHost)
	}
	interfaceIPv4 := network.GetDefaultInterfaceIPv4(cfg.ConnectIP)
	if interfaceIPv4 == "" {
		log.Fatal("Failed to detect local interface IPv4 address")
	}
	fmt.Printf("Local interface: %s\n", interfaceIPv4)

	fakeInjector, err := injection.NewFakeTcpInjector(interfaceIPv4, cfg.ConnectIPv4s, uint16(cfg.ConnectPort))
	if err != nil {
		log.Fatal("Failed to create injector: ", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		fakeInjector.Close()
		os.Exit(0)
	}()

	go func() {
		if err := fakeInjector.Start(); err != nil {
			log.Printf("injector: %v", err)
			fakeInjector.Close()
			os.Exit(1)
		}
	}()
	if err := fakeInjector.WaitInjectorReady(); err != nil {
		fakeInjector.Close()
		log.Fatal("injector: ", err)
	}

	listenAddr := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(cfg.ListenPort))
	listener, err := net.Listen("tcp4", listenAddr)
	if err != nil {
		fakeInjector.Close()
		log.Fatal("Failed to listen: ", err)
	}
	defer listener.Close()
	fmt.Printf("Listening on %s\n", listenAddr)

	for {
		incomingSock, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		if tc, ok := incomingSock.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(11 * time.Second)
		}

		go handleConnection(incomingSock, cfg, interfaceIPv4, cfg.FakeSNI, clientHelloID, fakeInjector, fakeRepeat, fakeDelay, enableFragment, fragmentDelay, sniChunk, ackTimeout)
	}
}

func handleConnection(
	incomingSock net.Conn,
	cfg *config.Config,
	interfaceIPv4 string,
	fakeSNI string,
	clientHelloID utls.ClientHelloID,
	fakeInjector *injection.FakeTcpInjector,
	fakeRepeat int,
	fakeDelay time.Duration,
	enableFragment bool,
	fragmentDelay time.Duration,
	sniChunk int,
	ackTimeout time.Duration,
) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in handle: %v", r)
		}
	}()

	fakeData, err := packet.BuildClientHelloRecord(fakeSNI, clientHelloID)
	if err != nil {
		log.Printf("ClientHello: %v", err)
		incomingSock.Close()
		return
	}

	outgoingSock, conn, _, err := dialOutgoing(
		interfaceIPv4, cfg.ConnectIP, cfg.ConnectPort,
		fakeData, "wrong_seq", fakeRepeat, fakeDelay, fragmentDelay, incomingSock, fakeInjector,
	)
	if err != nil {
		log.Printf("Failed to connect to %s:%d: %v", cfg.ConnectIP, cfg.ConnectPort, err)
		incomingSock.Close()
		return
	}

	conn.Mu.Lock()
	conn.Sock = outgoingSock
	conn.Mu.Unlock()

	if tc, ok := outgoingSock.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(11 * time.Second)
	}

	select {
	case msg := <-conn.T2aChan:
		if msg == "unexpected_close" {
			log.Printf("proxy: injector aborted handshake (unexpected TCP); closing client connection")
			stopMonitoring(fakeInjector, conn)
			closePair(outgoingSock, incomingSock)
			return
		}
		if msg != "fake_data_ack_recv" {
			log.Printf("unexpected t2a msg: %q", msg)
			stopMonitoring(fakeInjector, conn)
			closePair(outgoingSock, incomingSock)
			return
		}
	case <-time.After(ackTimeout):
		log.Printf("proxy: timed out after %v waiting for post-injection ACK (injector path); closing client connection", ackTimeout)
		stopMonitoring(fakeInjector, conn)
		closePair(outgoingSock, incomingSock)
		return
	}

	stopMonitoring(fakeInjector, conn)

	if fakeDelay > 0 {
		time.Sleep(fakeDelay)
	}

	if enableFragment {
		if err := forwardFragmentedClientHello(incomingSock, outgoingSock, fragmentDelay, sniChunk, true); err != nil {
			log.Printf("ClientHello fragment: %v", err)
			closePair(outgoingSock, incomingSock)
			return
		}
	}

	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		relay(outgoingSock, incomingSock)
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		relay(incomingSock, outgoingSock)
	}()

	<-done
	closePair(outgoingSock, incomingSock)
	<-done
}

func stopMonitoring(fakeInjector *injection.FakeTcpInjector, conn *injection.FakeInjectiveConnection) {
	conn.Mu.Lock()
	conn.Monitor = false
	conn.Mu.Unlock()
	fakeInjector.UnregisterConn(conn)
}

func closePair(a, b net.Conn) {
	a.Close()
	b.Close()
}

func forwardFragmentedClientHello(incoming, outgoing net.Conn, delay time.Duration, sniChunkBytes int, logEachFragment bool) error {
	if err := incoming.SetReadDeadline(time.Now().Add(firstClientHelloTimeout)); err != nil {
		return err
	}
	rec, err := packet.ReadFirstTLSRecord(incoming)
	_ = incoming.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	frags := packet.SplitClientHelloRecord(rec, sniChunkBytes)
	var tcpFrag *net.TCPConn
	if tc, ok := outgoing.(*net.TCPConn); ok {
		tcpFrag = tc
	}
	return packet.WriteClientHelloFragments(outgoing, frags, delay, tcpFrag, logEachFragment)
}

func relay(dst, src net.Conn) {
	const bufSize = 65575
	buf := make([]byte, bufSize)
	_, _ = io.CopyBuffer(dst, src, buf)
}
