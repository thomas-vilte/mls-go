package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// startServer builds the interop server binary and starts it with args.
// The process is killed when the test ends.
func startServer(t *testing.T, args ...string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "mls-go-server")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	cmd := exec.CommandContext(t.Context(), bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
}

// freePort returns a TCP port on 127.0.0.1 that was free when called.
func freePort(t *testing.T) int {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// dialTCP connects to addr, giving up after timeout.
func dialTCP(addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// waitForPort fails the test if addr does not accept connections in time.
func waitForPort(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := dialTCP(addr, 200*time.Millisecond); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s does not accept connections", addr)
}

// isOpenFor reports whether addr accepts a TCP connection at any point during window.
func isOpenFor(addr string, window time.Duration) bool {
	deadline := time.Now().Add(window)
	for {
		if c, err := dialTCP(addr, 100*time.Millisecond); err == nil {
			_ = c.Close()
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// nonLoopbackIPv4 returns the first non-loopback IPv4 address of the host, or "".
func nonLoopbackIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
			return ipn.IP.String()
		}
	}
	return ""
}

// TestPprofDisabledByDefault checks that the server does not open a pprof
// endpoint when started without -pprof-port. Before the fix, pprof was always
// enabled on port+1000 and listened on all interfaces. The gRPC port, the one the
// container image exposes, must not answer /debug/pprof/ in that configuration either.
func TestPprofDisabledByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the interop server")
	}
	port := freePort(t)
	startServer(t, "-port", strconv.Itoa(port))
	grpcAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	waitForPort(t, grpcAddr)

	pprofAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port+1000))
	if isOpenFor(pprofAddr, time.Second) {
		t.Fatalf("pprof accepts connections on %s without -pprof-port; it must be disabled by default", pprofAddr)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+grpcAddr+"/debug/pprof/", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("the gRPC port %s serves /debug/pprof/ (200) without -pprof-port", grpcAddr)
		}
	}
}

// TestPprofLoopbackOnly checks that -pprof-port serves pprof on 127.0.0.1 and
// that the endpoint is not reachable through a non-loopback address.
func TestPprofLoopbackOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the interop server")
	}
	port := freePort(t)
	pprofPort := freePort(t)
	startServer(t, "-port", strconv.Itoa(port), "-pprof-port", strconv.Itoa(pprofPort))
	waitForPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))

	loopback := net.JoinHostPort("127.0.0.1", strconv.Itoa(pprofPort))
	waitForPort(t, loopback)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+loopback+"/debug/pprof/", http.NoBody)
	if err != nil {
		t.Fatalf("build pprof request: %v", err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /debug/pprof/ on loopback: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /debug/pprof/ on loopback = %d, want 200", resp.StatusCode)
	}

	ip := nonLoopbackIPv4()
	if ip == "" {
		t.Log("no non-loopback IPv4 address on this host; skipping the bind address check")
		return
	}
	external := net.JoinHostPort(ip, strconv.Itoa(pprofPort))
	if isOpenFor(external, 200*time.Millisecond) {
		t.Fatalf("pprof reachable on %s; it must only listen on 127.0.0.1", external)
	}
}

// TestPprofListenAddr checks that pprof is disabled for port 0 and that an
// enabled port is always bound to loopback.
func TestPprofListenAddr(t *testing.T) {
	if got := pprofListenAddr(0); got != "" {
		t.Errorf("pprofListenAddr(0) = %q, want \"\" (disabled)", got)
	}
	if got := pprofListenAddr(6060); got != "127.0.0.1:6060" {
		t.Errorf("pprofListenAddr(6060) = %q, want %q", got, "127.0.0.1:6060")
	}
}
