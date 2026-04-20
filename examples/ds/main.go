// Package main provides a minimal MLS Delivery Service reference implementation.
//
// This is a demonstration implementation for learning and testing purposes.
// It is NOT suitable for production use.
//
// # Features
//
//   - Group creation and key package registration
//   - Welcome message delivery via SSE (Server-Sent Events)
//   - Commit/proposal message submission
//   - In-memory storage (no persistence)
//
// # Running
//
//	go run ./examples/ds/
//
// # API Endpoints
//
//	POST /groups              - Create a new group
//	POST /groups/{id}/keypackages - Register a KeyPackage
//	GET  /groups/{id}/keypackages - Get registered KeyPackages
//	POST /groups/{id}/messages - Submit a Commit, Proposal, or Application message
//	GET  /groups/{id}/events   - SSE stream of messages for a member
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"sync"
	"time"

	mls "github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
)

var addr = flag.String("addr", ":8080", "HTTP server address")

type deliveryService struct {
	mu          sync.RWMutex
	groups      map[string]*groupState
	keyPackages map[string][]string
	sseClients  map[string]map[chan []byte]struct{}
	sseMu       sync.Mutex
}

type groupState struct {
	client *mls.Client
}

func newDeliveryService() *deliveryService {
	return &deliveryService{
		groups:      make(map[string]*groupState),
		keyPackages: make(map[string][]string),
		sseClients:  make(map[string]map[chan []byte]struct{}),
	}
}

type CreateGroupRequest struct {
	CipherSuite ciphersuite.CipherSuite `json:"cipher_suite"`
}

type CreateGroupResponse struct {
	GroupID    string `json:"group_id"`
	KeyPackage string `json:"key_package"`
}

type RegisterKPRequest struct {
	KeyPackage string `json:"key_package"`
}

type SubmitMessageRequest struct {
	Message string `json:"message"`
}

func (ds *deliveryService) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req CreateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	client, err := mls.NewClient([]byte("ds-user"), req.CipherSuite,
		mls.WithLogger(slog.Default()),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	groupID, err := client.CreateGroup(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	kp, err := client.FreshKeyPackageBytes(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	gidStr := string(groupID)
	ds.mu.Lock()
	ds.groups[gidStr] = &groupState{client: client}
	ds.keyPackages[gidStr] = []string{string(kp)}
	ds.sseClients[gidStr] = make(map[chan []byte]struct{})
	ds.mu.Unlock()

	resp := CreateGroupResponse{GroupID: gidStr, KeyPackage: string(kp)}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Encode error: %v", err)
	}
}

func (ds *deliveryService) handleRegisterKP(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")

	var req RegisterKPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ds.mu.RLock()
	state, ok := ds.groups[groupID]
	ds.mu.RUnlock()
	if !ok {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}

	kp, err := state.client.FreshKeyPackageBytes(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ds.mu.Lock()
	ds.keyPackages[groupID] = append(ds.keyPackages[groupID], string(kp))
	ds.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
}

func (ds *deliveryService) handleGetKeyPackages(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")

	ds.mu.RLock()
	kps, ok := ds.keyPackages[groupID]
	ds.mu.RUnlock()
	if !ok {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string][]string{"key_packages": kps}); err != nil {
		log.Printf("Encode error: %v", err)
	}
}

func (ds *deliveryService) handleSubmitMessage(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")

	var req SubmitMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ds.mu.RLock()
	state, ok := ds.groups[groupID]
	ds.mu.RUnlock()
	if !ok {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}

	msg, err := framing.UnmarshalMLSMessage([]byte(req.Message))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ds.sseMu.Lock()
	for ch := range ds.sseClients[groupID] {
		select {
		case ch <- []byte(req.Message):
		default:
		}
	}
	ds.sseMu.Unlock()

	if _, ok := msg.AsPublic(); ok {
		if err := state.client.ProcessPublicMessage(context.Background(), []byte(groupID), []byte(req.Message)); err != nil {
			log.Printf("ProcessPublicMessage error: %v", err)
		}
	}

	w.WriteHeader(http.StatusAccepted)
}

func (ds *deliveryService) handleSSE(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")

	ds.mu.RLock()
	if _, ok := ds.groups[groupID]; !ok {
		ds.mu.RUnlock()
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	ds.mu.RUnlock()

	ch := make(chan []byte, 10)
	ds.sseMu.Lock()
	ds.sseClients[groupID][ch] = struct{}{}
	ds.sseMu.Unlock()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.(http.Flusher).Flush()

	defer func() {
		ds.sseMu.Lock()
		delete(ds.sseClients[groupID], ch)
		ds.sseMu.Unlock()
		close(ch)
	}()

	for msg := range ch {
		_, err := fmt.Fprintf(w, "data: %s\n\n", msg)
		if err != nil {
			break
		}
		w.(http.Flusher).Flush()
	}
}

func main() {
	flag.Parse()

	ds := newDeliveryService()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /groups", ds.handleCreateGroup)
	mux.HandleFunc("POST /groups/{id}/keypackages", ds.handleRegisterKP)
	mux.HandleFunc("GET /groups/{id}/keypackages", ds.handleGetKeyPackages)
	mux.HandleFunc("POST /groups/{id}/messages", ds.handleSubmitMessage)
	mux.HandleFunc("GET /groups/{id}/events", ds.handleSSE)

	log.Printf("Starting MLS Delivery Service on %s", *addr)
	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
