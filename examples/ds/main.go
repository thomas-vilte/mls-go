package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"
)

var addr = flag.String("addr", ":8080", "HTTP server address")

type deliveryService struct {
	mu         sync.RWMutex
	groups     map[string]*groupState
	sseMu      sync.Mutex
	sseClients map[string]map[chan sseEvent]struct{}
}

type groupState struct {
	keyPackages map[string][]byte
}

type sseEvent struct {
	Sender  string `json:"sender"`
	Message []byte `json:"message"`
}

type createGroupRequest struct {
	GroupID string `json:"group_id"`
}

type createGroupResponse struct {
	GroupID string `json:"group_id"`
}

type listGroupsResponse struct {
	Groups []string `json:"groups"`
}

type registerKeyPackageRequest struct {
	User       string `json:"user"`
	KeyPackage []byte `json:"key_package"`
}

type keyPackageResponse struct {
	User       string `json:"user"`
	KeyPackage []byte `json:"key_package"`
}

type keyPackageUsersResponse struct {
	Users []string `json:"users"`
}

type submitMessageRequest struct {
	Sender  string `json:"sender"`
	Message []byte `json:"message"`
}

func newDeliveryService() *deliveryService {
	return &deliveryService{
		groups:     make(map[string]*groupState),
		sseClients: make(map[string]map[chan sseEvent]struct{}),
	}
}

func randomGroupID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (ds *deliveryService) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req createGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	groupID := req.GroupID
	if groupID == "" {
		var err error
		groupID, err = randomGroupID()
		if err != nil {
			http.Error(w, fmt.Sprintf("generating group id: %v", err), http.StatusInternalServerError)
			return
		}
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()
	if _, exists := ds.groups[groupID]; exists {
		http.Error(w, "group already exists", http.StatusConflict)
		return
	}
	ds.groups[groupID] = &groupState{keyPackages: make(map[string][]byte)}
	ds.sseClients[groupID] = make(map[chan sseEvent]struct{})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(createGroupResponse{GroupID: groupID})
}

func (ds *deliveryService) handleListGroups(w http.ResponseWriter, _ *http.Request) {
	ds.mu.RLock()
	ids := make([]string, 0, len(ds.groups))
	for id := range ds.groups {
		ids = append(ids, id)
	}
	ds.mu.RUnlock()
	sort.Strings(ids)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(listGroupsResponse{Groups: ids})
}

func (ds *deliveryService) handleRegisterKeyPackage(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")

	var req registerKeyPackageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.User == "" {
		http.Error(w, "user is required", http.StatusBadRequest)
		return
	}
	if len(req.KeyPackage) == 0 {
		http.Error(w, "key_package is required", http.StatusBadRequest)
		return
	}

	ds.mu.Lock()
	state, ok := ds.groups[groupID]
	if !ok {
		ds.mu.Unlock()
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	state.keyPackages[req.User] = append([]byte(nil), req.KeyPackage...)
	ds.mu.Unlock()

	w.WriteHeader(http.StatusCreated)
}

func (ds *deliveryService) handleListKeyPackageUsers(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	ds.mu.RLock()
	state, ok := ds.groups[groupID]
	if !ok {
		ds.mu.RUnlock()
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	users := make([]string, 0, len(state.keyPackages))
	for user := range state.keyPackages {
		users = append(users, user)
	}
	ds.mu.RUnlock()
	sort.Strings(users)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(keyPackageUsersResponse{Users: users})
}

func (ds *deliveryService) handleGetKeyPackageByUser(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	user := r.PathValue("user")

	ds.mu.RLock()
	state, ok := ds.groups[groupID]
	if !ok {
		ds.mu.RUnlock()
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	kp, ok := state.keyPackages[user]
	ds.mu.RUnlock()
	if !ok {
		http.Error(w, "key package not found for user", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(keyPackageResponse{User: user, KeyPackage: kp})
}

func (ds *deliveryService) broadcast(groupID string, event sseEvent) {
	ds.sseMu.Lock()
	defer ds.sseMu.Unlock()
	clients := ds.sseClients[groupID]
	for ch := range clients {
		select {
		case ch <- event:
		default:
		}
	}
}

func (ds *deliveryService) handleSubmitMessage(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")

	var req submitMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Sender == "" {
		http.Error(w, "sender is required", http.StatusBadRequest)
		return
	}
	if len(req.Message) == 0 {
		http.Error(w, "message is required", http.StatusBadRequest)
		return
	}

	ds.mu.RLock()
	_, ok := ds.groups[groupID]
	ds.mu.RUnlock()
	if !ok {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}

	ds.broadcast(groupID, sseEvent(req))
	w.WriteHeader(http.StatusAccepted)
}

func (ds *deliveryService) handleSSE(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")

	ds.mu.RLock()
	_, ok := ds.groups[groupID]
	ds.mu.RUnlock()
	if !ok {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ch := make(chan sseEvent, 32)
	ds.sseMu.Lock()
	ds.sseClients[groupID][ch] = struct{}{}
	ds.sseMu.Unlock()

	defer func() {
		ds.sseMu.Lock()
		delete(ds.sseClients[groupID], ch)
		ds.sseMu.Unlock()
		close(ch)
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-ch:
			payload, err := json.Marshal(event)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func main() {
	flag.Parse()

	ds := newDeliveryService()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /groups", ds.handleListGroups)
	mux.HandleFunc("POST /groups", ds.handleCreateGroup)
	mux.HandleFunc("POST /groups/{id}/keypackages", ds.handleRegisterKeyPackage)
	mux.HandleFunc("GET /groups/{id}/keypackages", ds.handleListKeyPackageUsers)
	mux.HandleFunc("GET /groups/{id}/keypackages/{user}", ds.handleGetKeyPackageByUser)
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
