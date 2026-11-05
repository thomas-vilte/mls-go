package group

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/keypackages"
	"github.com/thomas-vilte/mls-go/treesync"
)

// TestRejectedCommitLeavesGroupUnchanged checks that a commit rejected for an invalid confirmation_tag leaves
// the group exactly as it was, so the legitimate commit that follows is still accepted.
//
// RFC 9420 §12.4.2: a commit is applied only when its confirmation_tag is valid. Processing a commit changes the
// path private keys, the epoch, the tree and the group context before the tag is checked, so a rejection has to
// restore all of them.
func TestRejectedCommitLeavesGroupUnchanged(t *testing.T) {
	alice, bob, alicePriv, _ := setupTwoMemberGroup(t)
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)

	assertRejectedCommitLeavesGroupUnchanged(t, alice, bob, sigPriv)
}

// TestRejectedCommitLeavesGroupUnchangedThreeMembers checks the same rejection with a third member. The
// UpdatePath then has more filtered levels, and a rejected commit stores more path private keys.
func TestRejectedCommitLeavesGroupUnchangedThreeMembers(t *testing.T) {
	alice, bob, alicePriv, _ := setupTwoMemberGroup(t)
	sigPriv := ciphersuite.NewSignaturePrivateKey(alicePriv.SignatureKey)

	charlieCred, _, err := credentials.GenerateCredentialWithKey([]byte("Charlie"))
	if err != nil {
		t.Fatalf("GenerateCredentialWithKey(Charlie): %v", err)
	}
	charlieKP, _, err := keypackages.Generate(charlieCred, keypackages.MLS128DHKEMP256)
	if err != nil {
		t.Fatalf("Generate KeyPackage(Charlie): %v", err)
	}
	if _, err := alice.AddMember(charlieKP); err != nil {
		t.Fatalf("SETUP: AddMember(Charlie): %v", err)
	}
	addStaged, err := alice.Commit(sigPriv, sigPriv.PublicKey(), nil)
	if err != nil {
		t.Fatalf("SETUP: commit adding Charlie: %v", err)
	}
	if err := alice.MergeCommit(addStaged); err != nil {
		t.Fatalf("SETUP: alice merges the add commit: %v", err)
	}
	if err := bob.ProcessReceivedCommit(addStaged.AuthenticatedContent(), treesync.LeafIndex(alice.ownLeafIndex), bob.MyLeafEncryptionKey()); err != nil {
		t.Fatalf("SETUP: bob processes the add commit: %v", err)
	}
	if got := bob.MemberCount(); got != 3 {
		t.Fatalf("SETUP: bob sees %d members, want 3", got)
	}

	assertRejectedCommitLeavesGroupUnchanged(t, alice, bob, sigPriv)
}

// assertRejectedCommitLeavesGroupUnchanged has committer create a commit and receiver reject a copy of it whose
// confirmation_tag is flipped. The group must be unchanged after the rejection, and then the original
// commit must be accepted. The whole state is compared, not only MarshalState, so the fields that MarshalState
// does not serialize are checked too.
func assertRejectedCommitLeavesGroupUnchanged(t *testing.T, committer, receiver *Group, sigPriv *ciphersuite.SignaturePrivateKey) {
	t.Helper()

	// An empty commit with an UpdatePath is valid under RFC 9420.
	staged, err := committer.Commit(sigPriv, sigPriv.PublicKey(), nil)
	if err != nil {
		t.Fatalf("SETUP: creating commit: %v", err)
	}
	if staged.commit == nil || staged.commit.Path == nil || staged.authenticatedContent == nil {
		t.Fatal("SETUP: expected a commit with an UpdatePath and authenticated content")
	}

	legit := *staged.authenticatedContent
	sender := treesync.LeafIndex(legit.Content.Sender.LeafIndex)

	// Flip one bit of a copy of the tag. The tag is outside FramedContentTBS, so the signature
	// still verifies and only the confirmation_tag check can reject the commit.
	tampered := legit
	tampered.Auth.ConfirmationTag = append([]byte(nil), legit.Auth.ConfirmationTag...)
	if len(tampered.Auth.ConfirmationTag) == 0 {
		t.Fatal("SETUP: missing confirmation tag")
	}
	tampered.Auth.ConfirmationTag[0] ^= 0x01

	before, err := receiver.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState before rejected commit: %v", err)
	}
	epochBefore := receiver.Epoch()
	stateBefore := groupStateLines(receiver)

	err = receiver.ProcessReceivedCommit(&tampered, sender, receiver.MyLeafEncryptionKey())
	if !errors.Is(err, ErrConfirmationTagMismatch) {
		t.Fatalf("commit with a tampered confirmation_tag: err = %v, want ErrConfirmationTagMismatch", err)
	}

	after, err := receiver.MarshalState()
	if err != nil {
		t.Fatalf("MarshalState after rejected commit: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected commit changed the serialized group state")
	}
	if receiver.Epoch() != epochBefore {
		t.Fatalf("epoch after rejected commit = %d, want %d", receiver.Epoch(), epochBefore)
	}
	// MarshalState leaves out the epoch history, the proposal refs, the pending leaf key, the last committed
	// proposals and the key schedule. The comparison below covers them, with every other field of the group.
	if diff, changed := firstStateDiff(stateBefore, groupStateLines(receiver)); changed {
		t.Fatalf("rejected commit changed the group state: %s", diff)
	}

	// The legitimate commit must be accepted from the unchanged state.
	if err := receiver.ProcessReceivedCommit(&legit, sender, receiver.MyLeafEncryptionKey()); err != nil {
		t.Fatalf("legitimate commit after rejected commit: %v", err)
	}
	if got, want := receiver.Epoch().AsUint64(), epochBefore.AsUint64()+1; got != want {
		t.Fatalf("epoch after legitimate commit = %d, want %d", got, want)
	}
	// Control: the accepted commit changes the full state, so the comparison above can detect a change.
	if _, changed := firstStateDiff(stateBefore, groupStateLines(receiver)); !changed {
		t.Fatal("control failed: an accepted commit left the full state unchanged")
	}
}

// groupStateLines returns one line per value reachable from g, so two states are equal only if every field is
// equal. Besides the fields that MarshalState does not serialize (epochHistory, proposalByRef, pendingLeafKey,
// lastCommittedProposals, keySchedule, pendingCommit and the proposal store), it covers the private keys of the
// path. Fields are read by reflection, so a field added to Group later is compared too. Sync primitives are
// skipped, and a pointer that repeats on the current walk is written as a cycle.
func groupStateLines(g *Group) []string {
	var lines []string
	walkStateLines(reflect.ValueOf(g), "group", &lines, map[uintptr]bool{})
	return lines
}

// walkStateLines appends one line per value reachable from v. Each line is a field path, a tab and the value.
// Map entries are sorted, so equal states give equal lines.
func walkStateLines(v reflect.Value, path string, lines *[]string, onPath map[uintptr]bool) {
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			*lines = append(*lines, path+"\tnil")
			return
		}
		walkStateLines(v.Elem(), path, lines, onPath)
	case reflect.Pointer:
		if v.IsNil() {
			*lines = append(*lines, path+"\tnil")
			return
		}
		if onPath[v.Pointer()] {
			*lines = append(*lines, path+"\tcycle")
			return
		}
		onPath[v.Pointer()] = true
		walkStateLines(v.Elem(), path, lines, onPath)
		delete(onPath, v.Pointer())
	case reflect.Struct:
		if strings.HasPrefix(v.Type().PkgPath(), "sync") {
			return // a lock holds no state that a commit leaves behind
		}
		for i := 0; i < v.NumField(); i++ {
			walkStateLines(v.Field(i), path+"."+v.Type().Field(i).Name, lines, onPath)
		}
	case reflect.Map:
		if v.IsNil() {
			*lines = append(*lines, path+"\tnil")
			return
		}
		if onPath[v.Pointer()] {
			*lines = append(*lines, path+"\tcycle")
			return
		}
		onPath[v.Pointer()] = true
		var entries []string
		iter := v.MapRange()
		for iter.Next() {
			walkStateLines(iter.Value(), path+"["+stateMapKey(iter.Key())+"]", &entries, onPath)
		}
		delete(onPath, v.Pointer())
		sort.Strings(entries)
		*lines = append(*lines, fmt.Sprintf("%s\tlen=%d", path, v.Len()))
		*lines = append(*lines, entries...)
	case reflect.Slice:
		if v.IsNil() {
			*lines = append(*lines, path+"\tnil")
			return
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			*lines = append(*lines, fmt.Sprintf("%s\t%x", path, v.Bytes()))
			return
		}
		*lines = append(*lines, fmt.Sprintf("%s\tlen=%d", path, v.Len()))
		for i := 0; i < v.Len(); i++ {
			walkStateLines(v.Index(i), fmt.Sprintf("%s[%d]", path, i), lines, onPath)
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walkStateLines(v.Index(i), fmt.Sprintf("%s[%d]", path, i), lines, onPath)
		}
	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		*lines = append(*lines, fmt.Sprintf("%s\tnil=%t", path, v.IsNil()))
	default:
		*lines = append(*lines, fmt.Sprintf("%s\t%v", path, v))
	}
}

// stateMapKey formats a map key for a state line. String keys are hex-encoded, so binary keys stay printable.
func stateMapKey(k reflect.Value) string {
	if k.Kind() == reflect.String {
		return fmt.Sprintf("%x", k.String())
	}
	return fmt.Sprintf("%v", k)
}

// firstStateDiff reports the first state line that differs between before and after, by field path, so that
// a failure does not print key material.
func firstStateDiff(before, after []string) (string, bool) {
	for i := 0; i < len(before) || i < len(after); i++ {
		var b, a string
		if i < len(before) {
			b = before[i]
		}
		if i < len(after) {
			a = after[i]
		}
		if b == a {
			continue
		}
		if pb, pa := stateLinePath(b), stateLinePath(a); pb != pa {
			return fmt.Sprintf("entry %d: %s before, %s after", i, pb, pa), true
		}
		return fmt.Sprintf("entry %d: value of %s differs", i, stateLinePath(b)), true
	}
	return "", false
}

// stateLinePath returns the field path of a state line, without its value.
func stateLinePath(line string) string {
	path, _, _ := strings.Cut(line, "\t")
	return path
}
