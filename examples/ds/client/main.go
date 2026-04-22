package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	mls "github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
)

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

type submitMessageRequest struct {
	Sender  string `json:"sender"`
	Message []byte `json:"message"`
}

type sseEvent struct {
	Sender  string `json:"sender"`
	Message []byte `json:"message"`
}

type dsClient struct {
	baseURL string
	http    *http.Client
}

func (d *dsClient) postJSON(ctx context.Context, path string, reqBody, respBody any) error {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	if respBody != nil {
		return json.NewDecoder(resp.Body).Decode(respBody)
	}
	return nil
}

func (d *dsClient) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+path, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func main() {
	var (
		serverURL = flag.String("server", "http://localhost:8080", "Delivery Service URL")
		groupHint = flag.String("group", "", "Group ID (base64url). If empty: create when no groups exist, otherwise join the single available group")
	)
	flag.Parse()
	if flag.NArg() != 1 {
		log.Fatalf("usage: go run ./examples/ds/client <user> [-server URL] [-group GROUP_ID]")
	}
	user := flag.Arg(0)

	ctx := context.Background()
	ds := &dsClient{baseURL: strings.TrimRight(*serverURL, "/"), http: &http.Client{Timeout: 20 * time.Second}}
	mlsClient, err := mls.NewClient([]byte(user), ciphersuite.MLS128DHKEMP256)
	if err != nil {
		log.Fatalf("creating MLS client: %v", err)
	}

	groupID, groupIDText, joined, err := bootstrapGroup(ctx, ds, mlsClient, *groupHint)
	if err != nil {
		log.Fatalf("group bootstrap failed: %v", err)
	}

	kp, err := mlsClient.FreshKeyPackageBytes(ctx)
	if err != nil {
		log.Fatalf("creating key package: %v", err)
	}
	if err := ds.postJSON(ctx, fmt.Sprintf("/groups/%s/keypackages", groupIDText), registerKeyPackageRequest{User: user, KeyPackage: kp}, nil); err != nil {
		log.Fatalf("registering key package: %v", err)
	}

	state := &runtimeState{
		user:        user,
		ds:          ds,
		client:      mlsClient,
		groupID:     groupID,
		groupIDText: groupIDText,
		joined:      joined,
	}

	log.Printf("ready: user=%s group=%s joined=%v", user, groupIDText, joined)
	log.Printf("commands: /invite <user>, /members, /help")

	go state.consumeEvents(ctx)
	state.repl(ctx)
}

type runtimeState struct {
	user        string
	ds          *dsClient
	client      *mls.Client
	groupID     []byte
	groupIDText string
	joined      bool
}

func bootstrapGroup(ctx context.Context, ds *dsClient, client *mls.Client, groupHint string) (groupID []byte, groupIDText string, joined bool, err error) {
	if groupHint != "" {
		gid, err := base64.RawURLEncoding.DecodeString(groupHint)
		if err != nil {
			return nil, "", false, fmt.Errorf("invalid -group value: %w", err)
		}
		return gid, groupHint, false, nil
	}

	var groups listGroupsResponse
	if err := ds.getJSON(ctx, "/groups", &groups); err != nil {
		return nil, "", false, err
	}

	switch len(groups.Groups) {
	case 0:
		gid, err := client.CreateGroup(ctx)
		if err != nil {
			return nil, "", false, fmt.Errorf("creating local group: %w", err)
		}
		gidText := base64.RawURLEncoding.EncodeToString(gid)
		var resp createGroupResponse
		if err := ds.postJSON(ctx, "/groups", createGroupRequest{GroupID: gidText}, &resp); err != nil {
			return nil, "", false, fmt.Errorf("registering group in DS: %w", err)
		}
		return gid, gidText, true, nil
	case 1:
		gid, err := base64.RawURLEncoding.DecodeString(groups.Groups[0])
		if err != nil {
			return nil, "", false, fmt.Errorf("decoding DS group id: %w", err)
		}
		return gid, groups.Groups[0], false, nil
	default:
		return nil, "", false, fmt.Errorf("multiple groups in DS (%d), pass -group", len(groups.Groups))
	}
}

func (s *runtimeState) consumeEvents(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/groups/%s/events", s.ds.baseURL, s.groupIDText), http.NoBody)
	if err != nil {
		log.Printf("events request build failed: %v", err)
		return
	}
	resp, err := s.ds.http.Do(req)
	if err != nil {
		log.Printf("events stream failed: %v", err)
		return
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		log.Printf("events stream failed: %s: %s", resp.Status, strings.TrimSpace(string(b)))
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var event sseEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			log.Printf("invalid SSE event: %v", err)
			continue
		}
		if event.Sender == s.user {
			continue
		}
		if err := s.handleIncomingMLSMessage(context.Background(), event.Message); err != nil {
			log.Printf("processing incoming message failed: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("events scanner error: %v", err)
	}
}

func (s *runtimeState) handleIncomingMLSMessage(ctx context.Context, msgBytes []byte) error {
	msg, err := framing.UnmarshalMLSMessage(msgBytes)
	if err != nil {
		return fmt.Errorf("unmarshal MLS message: %w", err)
	}

	if msg.Welcome != nil {
		if s.joined {
			return nil
		}
		joinedID, joinErr := s.client.JoinGroup(ctx, msgBytes)
		if joinErr != nil {
			return fmt.Errorf("join from welcome: %w", joinErr)
		}
		s.groupID = joinedID
		s.groupIDText = base64.RawURLEncoding.EncodeToString(joinedID)
		s.joined = true
		log.Printf("joined group %s", s.groupIDText)
		return nil
	}

	if !s.joined {
		return nil
	}

	if pub, ok := msg.AsPublic(); ok {
		if pub.Content.ContentType() == framing.ContentTypeCommit {
			if err := s.client.ProcessCommit(ctx, s.groupID, msgBytes); err != nil {
				return fmt.Errorf("process commit: %w", err)
			}
			log.Printf("processed commit")
			return nil
		}
		if err := s.client.ProcessPublicMessage(ctx, s.groupID, msgBytes); err != nil {
			return fmt.Errorf("process public message: %w", err)
		}
		log.Printf("processed proposal")
		return nil
	}

	if _, ok := msg.AsPrivate(); ok {
		received, recvErr := s.client.ReceiveMessage(ctx, s.groupID, msgBytes)
		if recvErr != nil {
			return fmt.Errorf("receive message: %w", recvErr)
		}
		log.Printf("[%s] %s", string(received.SenderIdentity), string(received.Plaintext))
	}

	return nil
}

func (s *runtimeState) repl(ctx context.Context) {
	reader := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !reader.Scan() {
			return
		}
		line := strings.TrimSpace(reader.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/") {
			if err := s.runCommand(ctx, line); err != nil {
				log.Printf("command failed: %v", err)
			}
			continue
		}

		if !s.joined {
			log.Printf("not joined yet, wait for Welcome")
			continue
		}
		msgBytes, err := s.client.SendMessage(ctx, s.groupID, []byte(line))
		if err != nil {
			log.Printf("send message failed: %v", err)
			continue
		}
		if err := s.ds.postJSON(ctx, fmt.Sprintf("/groups/%s/messages", s.groupIDText), submitMessageRequest{Sender: s.user, Message: msgBytes}, nil); err != nil {
			log.Printf("publish message failed: %v", err)
		}
	}
}

func (s *runtimeState) runCommand(ctx context.Context, line string) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}

	switch fields[0] {
	case "/help":
		log.Printf("/invite <user>  invite member")
		log.Printf("/members        list local active members")
		log.Printf("/help           show this help")
		return nil
	case "/members":
		if !s.joined {
			log.Printf("not joined yet")
			return nil
		}
		members, err := s.client.ListMembers(ctx, s.groupID)
		if err != nil {
			return err
		}
		for _, member := range members {
			log.Printf("member leaf=%d identity=%s", member.LeafIndex, string(member.Identity))
		}
		return nil
	case "/invite":
		if len(fields) != 2 {
			return errors.New("usage: /invite <user>")
		}
		if !s.joined {
			return errors.New("not joined yet")
		}
		targetUser := fields[1]
		var kpResp keyPackageResponse
		if err := s.ds.getJSON(ctx, fmt.Sprintf("/groups/%s/keypackages/%s", s.groupIDText, targetUser), &kpResp); err != nil {
			return err
		}
		commit, welcome, err := s.client.InviteMember(ctx, s.groupID, kpResp.KeyPackage)
		if err != nil {
			return err
		}
		if err := s.ds.postJSON(ctx, fmt.Sprintf("/groups/%s/messages", s.groupIDText), submitMessageRequest{Sender: s.user, Message: commit}, nil); err != nil {
			return fmt.Errorf("publishing commit: %w", err)
		}
		if len(welcome) > 0 {
			if err := s.ds.postJSON(ctx, fmt.Sprintf("/groups/%s/messages", s.groupIDText), submitMessageRequest{Sender: s.user, Message: welcome}, nil); err != nil {
				return fmt.Errorf("publishing welcome: %w", err)
			}
		}
		log.Printf("invited %s", targetUser)
		return nil
	default:
		return fmt.Errorf("unknown command: %s", fields[0])
	}
}
