package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // intentional pprof endpoint for profiling
	"runtime/debug"
	"time"

	"google.golang.org/grpc"

	"github.com/thomas-vilte/mls-go/interop/server/proto"
)

func main() {
	port := flag.Int("port", 50051, "Port to listen on")
	pprofPort := flag.Int("pprof-port", 0, "Port for the pprof debug endpoint, bound to 127.0.0.1 only (0 = disabled)")
	memLimit := flag.Int("memlimit", 2048, "Memory limit in MB (GOMEMLIMIT)")
	flag.Parse()

	// Set memory limit to prevent OOM kills
	limit := int64(*memLimit) * 1024 * 1024
	debug.SetMemoryLimit(limit)

	// pprof is opt-in and loopback-only, so profiling data is never exposed to
	// other hosts or containers on the network.
	if addr := pprofListenAddr(*pprofPort); addr != "" {
		go func() {
			log.Printf("pprof on %s", addr)
			srv := &http.Server{
				Addr:              addr,
				ReadHeaderTimeout: 10 * time.Second,
			}
			if err := srv.ListenAndServe(); err != nil {
				log.Printf("pprof: %v", err)
			}
		}()
	}

	lc := net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	server := NewServer()
	proto.RegisterMLSClientServer(s, server)

	log.Printf("mls-go interop server listening on :%d", *port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

// pprofListenAddr returns the address for the pprof endpoint, or "" when pprof
// is disabled (port 0). The address is always on loopback.
func pprofListenAddr(port int) string {
	if port <= 0 {
		return ""
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}
