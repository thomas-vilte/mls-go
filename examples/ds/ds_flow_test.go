package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	mls "github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// startTestDS starts a real DS server and returns its URL + a cleanup func.
func startTestDS(t *testing.T) string {
	t.Helper()
	ds := newDeliveryService()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /groups", ds.handleListGroups)
	mux.HandleFunc("POST /groups", ds.handleCreateGroup)
	mux.HandleFunc("POST /groups/{id}/keypackages", ds.handleRegisterKeyPackage)
	mux.HandleFunc("GET /groups/{id}/keypackages", ds.handleListKeyPackageUsers)
	mux.HandleFunc("GET /groups/{id}/keypackages/{user}", ds.handleGetKeyPackageByUser)
	mux.HandleFunc("POST /groups/{id}/messages", ds.handleSubmitMessage)
	mux.HandleFunc("GET /groups/{id}/events", ds.handleSSE)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func dsPost(t *testing.T, client *http.Client, url string, body, out any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s: %d %s", url, resp.StatusCode, raw)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
}

func dsGet(t *testing.T, client *http.Client, url string, out any) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func TestDSFullFlow(t *testing.T) {
	srvURL := startTestDS(t)
	hc := &http.Client{}
	ctx := context.Background()
	cs := ciphersuite.MLS128DHKEMP256

	// create MLS clients
	alice, err := mls.NewClient([]byte("alice-ds-test"), cs)
	if err != nil {
		t.Fatalf("NewClient alice: %v", err)
	}
	bob, err := mls.NewClient([]byte("bob-ds-test"), cs)
	if err != nil {
		t.Fatalf("NewClient bob: %v", err)
	}

	// 1. create group on DS
	var createResp struct {
		GroupID string `json:"group_id"`
	}
	dsPost(t, hc, srvURL+"/groups", map[string]any{}, &createResp)
	gidText := createResp.GroupID
	t.Logf("DS group: %s", gidText)

	// 2. alice creates MLS group
	aliceGroupID, err := alice.CreateGroup(ctx)
	if err != nil {
		t.Fatalf("alice.CreateGroup: %v", err)
	}

	// 3. bob registers key package on DS
	bobKP, err := bob.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("bob.FreshKeyPackageBytes: %v", err)
	}
	dsPost(t, hc, fmt.Sprintf("%s/groups/%s/keypackages", srvURL, gidText),
		map[string]any{"user": "bob", "key_package": bobKP}, nil)

	// 4. alice fetches bob's key package and invites him
	var kpResp struct {
		KeyPackage []byte `json:"key_package"`
	}
	dsGet(t, hc, fmt.Sprintf("%s/groups/%s/keypackages/bob", srvURL, gidText), &kpResp)

	_, welcome, err := alice.InviteMember(ctx, aliceGroupID, kpResp.KeyPackage)
	if err != nil {
		t.Fatalf("alice.InviteMember: %v", err)
	}

	// 5. bob joins from welcome (out-of-band delivery simulated)
	bobGroupID, err := bob.JoinGroup(ctx, welcome)
	if err != nil {
		t.Fatalf("bob.JoinGroup: %v", err)
	}
	t.Log("Bob joined the group")

	// 6. alice sends message, posts ciphertext to DS
	ct, err := alice.SendMessage(ctx, aliceGroupID, []byte("hello bob from alice"))
	if err != nil {
		t.Fatalf("alice.SendMessage: %v", err)
	}
	dsPost(t, hc, fmt.Sprintf("%s/groups/%s/messages", srvURL, gidText),
		map[string]any{"sender": "alice", "message": ct}, nil)

	// 7. bob decrypts
	msg, err := bob.ReceiveMessage(ctx, bobGroupID, ct)
	if err != nil {
		t.Fatalf("bob.ReceiveMessage: %v", err)
	}
	if string(msg.Plaintext) != "hello bob from alice" {
		t.Fatalf("bob got %q, want %q", msg.Plaintext, "hello bob from alice")
	}
	t.Logf("Bob received: %q", msg.Plaintext)

	// 8. bob replies
	ct2, err := bob.SendMessage(ctx, bobGroupID, []byte("hello alice from bob"))
	if err != nil {
		t.Fatalf("bob.SendMessage: %v", err)
	}
	msg2, err := alice.ReceiveMessage(ctx, aliceGroupID, ct2)
	if err != nil {
		t.Fatalf("alice.ReceiveMessage: %v", err)
	}
	if string(msg2.Plaintext) != "hello alice from bob" {
		t.Fatalf("alice got %q, want %q", msg2.Plaintext, "hello alice from bob")
	}
	t.Logf("Alice received: %q", msg2.Plaintext)
}
