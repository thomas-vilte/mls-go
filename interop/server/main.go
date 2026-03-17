package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"runtime/debug"

	"google.golang.org/grpc"

	"github.com/thomas-vilte/mls-go/interop/server/proto"
)

func main() {
	port := flag.Int("port", 50051, "Port to listen on")
	memLimit := flag.Int("memlimit", 2048, "Memory limit in MB (GOMEMLIMIT)")
	flag.Parse()

	// Set memory limit to prevent OOM kills
	limit := int64(*memLimit) * 1024 * 1024
	debug.SetMemoryLimit(limit)

	// pprof on port+1000
	go func() {
		pprofPort := *port + 1000
		log.Printf("pprof on :%d", pprofPort)
		http.ListenAndServe(fmt.Sprintf(":%d", pprofPort), nil)
	}()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
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
