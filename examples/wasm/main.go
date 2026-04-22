// Package main provides a minimal WASM example for mls-go.
//
// This demonstrates using mls-go in a WebAssembly environment.
//
// # Building
//
//	GOOS=js GOARCH=wasm go build -o static/mls-go.wasm ./examples/wasm/
//
// # Using from JavaScript
//
//	const wasm = await WebAssembly.instantiateStreaming(
//	  fetch('static/mls-go.wasm'),
//	);
package main

import (
	"context"
	"log"

	mls "github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
)

func main() {
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	client, err := mls.NewClient([]byte("wasm-user"), cs)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}

	groupID, err := client.CreateGroup(ctx)
	if err != nil {
		log.Fatalf("CreateGroup: %v", err)
	}

	kp, err := client.FreshKeyPackageBytes(ctx)
	if err != nil {
		log.Fatalf("FreshKeyPackage: %v", err)
	}

	_ = groupID
	_ = kp
	log.Println("WASM: MLS works in browser!")
}
