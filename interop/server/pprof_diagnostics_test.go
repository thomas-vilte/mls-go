//go:build diagnostics

package main

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Additional diagnostics for pprof listener isolation.

// TestPprofListenAddrAlwaysLoopback checks that positive ports always produce
// a loopback address and nonpositive ports disable the endpoint.
func TestPprofListenAddrAlwaysLoopback(t *testing.T) {
	for _, port := range []int{-1, 0, 1, 6060, 65535, 65536, 1<<31 - 1, -(1 << 31)} {
		addr := pprofListenAddr(port)
		if port <= 0 {
			if addr != "" {
				t.Errorf("pprofListenAddr(%d) = %q, want disabled", port, addr)
			}
			continue
		}
		if !strings.HasPrefix(addr, "127.0.0.1:") {
			t.Errorf("pprofListenAddr(%d) = %q, not bound to 127.0.0.1", port, addr)
		}
	}
}

// TestPprofNotServedOnGRPCPort checks that enabling pprof does not expose
// its handlers on the gRPC service port.
func TestPprofNotServedOnGRPCPort(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the interop server")
	}
	port := freePort(t)
	pprofPort := freePort(t)
	startServer(t, "-port", strconv.Itoa(port), "-pprof-port", strconv.Itoa(pprofPort))
	waitForPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(port))+"/debug/pprof/", http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("pprof answers 200 on the gRPC port %d", port)
		}
	}
}

// TestPprofDefaultLeavesDebugPortsClosed checks that the legacy debug port
// and port 6060 remain closed when pprof is disabled.
func TestPprofDefaultLeavesDebugPortsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and starts the interop server")
	}
	port := freePort(t)
	startServer(t, "-port", strconv.Itoa(port))
	waitForPort(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	for _, p := range []int{port + 1000, 6060} {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(p))
		if isOpenFor(addr, 300*time.Millisecond) {
			t.Errorf("%s accepts connections although -pprof-port is not set", addr)
		}
	}
}
