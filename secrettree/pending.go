package secrettree

import (
	"fmt"

	"github.com/thomas-vilte/mls-go/ciphersuite"
)

// PendingDecryption is the key material for decrypting one generation, derived without changing
// the LeafSecret. A message that fails authentication then leaves the ratchet and the
// past-generation cache as they were. Commit moves the ratchet to the generation after the message
// is authenticated (RFC 9420 §6.1, §9.2). Discard wipes the derived secrets when it is rejected.
//
// A PendingDecryption is valid only until the next call that changes the LeafSecret, so it must be
// used under the same lock that protects the tree.
type PendingDecryption struct {
	ls  *LeafSecret
	gen uint32
	// application and handshake hold the secrets of generation gen.
	application *ciphersuite.Secret
	handshake   *ciphersuite.Secret
	// steps holds the secrets of generations [ls.generation, gen), oldest first. Commit moves
	// them into the cache.
	steps []pendingStep
	// fromCache is set when gen was already cached. Commit then changes nothing.
	fromCache bool
	// current is set when gen is the current generation. Its secrets belong to the ratchet, so
	// Discard must not wipe them, and Commit has nothing to advance.
	current bool
	done    bool
}

type pendingStep struct {
	gen         uint32
	application *ciphersuite.Secret
	handshake   *ciphersuite.Secret
}

// BeginDecryption prepares the keys for generation gen. A generation behind the current position
// is served from the cache. A later one is derived from the current ratchet, within the forward
// limit (DefaultMaxForwardDistance), and the ratchet does not move until Commit.
func (ls *LeafSecret) BeginDecryption(gen uint32) (*PendingDecryption, error) {
	if err := ls.checkForwardDistance(gen); err != nil {
		return nil, err
	}
	if uint64(gen) < ls.generation {
		cached, ok := ls.secretCache[gen]
		if !ok {
			return nil, fmt.Errorf("generation %d already advanced past (current: %d)", gen, ls.generation)
		}
		return &PendingDecryption{
			ls:          ls,
			gen:         gen,
			application: cached.application,
			handshake:   cached.handshake,
			fromCache:   true,
		}, nil
	}
	if uint64(gen) == ls.generation {
		return &PendingDecryption{
			ls:          ls,
			gen:         gen,
			application: ls.applicationRatchetSecret,
			handshake:   ls.handshakeRatchetSecret,
			current:     true,
		}, nil
	}

	p := &PendingDecryption{ls: ls, gen: gen}
	nh := ls.cs.HashLength()
	app, hs := ls.applicationRatchetSecret, ls.handshakeRatchetSecret
	for g := ls.generation; g < uint64(gen); g++ {
		genBytes := uint32ToBytes(uint32(g))
		stepApp, stepHs := app, hs
		if g == ls.generation {
			// The live ratchet is wiped on Commit, so the first step keeps its own copy.
			stepApp, stepHs = app.Clone(), hs.Clone()
		}
		p.steps = append(p.steps, pendingStep{gen: uint32(g), application: stepApp, handshake: stepHs})

		next, err := app.KdfExpandLabel("secret", genBytes, nh)
		if err != nil {
			p.Discard()
			return nil, fmt.Errorf("advance application ratchet (gen %d): %w", g, err)
		}
		nextHs, err := hs.KdfExpandLabel("secret", genBytes, nh)
		if err != nil {
			next.SecureZero()
			p.Discard()
			return nil, fmt.Errorf("advance handshake ratchet (gen %d): %w", g, err)
		}
		app, hs = next, nextHs
	}
	p.application, p.handshake = app, hs
	return p, nil
}

// Key returns the AEAD key of the generation, taken from the handshake ratchet when handshake is
// set and from the application ratchet otherwise. It matches HandshakeKey and ApplicationKey.
func (p *PendingDecryption) Key(handshake bool) ([]byte, error) {
	key, err := p.secret(handshake).KdfExpandLabel("key", uint32ToBytes(p.gen), p.ls.cs.AEADKeyLength())
	if err != nil {
		return nil, fmt.Errorf("deriving content key: %w", err)
	}
	return key.AsSlice(), nil
}

// Nonce returns the AEAD nonce of the generation, before the reuse guard is applied. It matches
// HandshakeNonce and ApplicationNonce.
func (p *PendingDecryption) Nonce(handshake bool) ([]byte, error) {
	nonce, err := p.secret(handshake).KdfExpandLabel("nonce", uint32ToBytes(p.gen), p.ls.cs.AEADNonceLength())
	if err != nil {
		return nil, fmt.Errorf("deriving content nonce: %w", err)
	}
	return nonce.AsSlice(), nil
}

func (p *PendingDecryption) secret(handshake bool) *ciphersuite.Secret {
	if handshake {
		return p.handshake
	}
	return p.application
}

// Commit moves the LeafSecret to the generation: the skipped generations go into the cache and
// the ratchet is set to gen. It is a no-op for a cached or current generation, and after Discard.
func (p *PendingDecryption) Commit() {
	if p.done {
		return
	}
	p.done = true
	if p.fromCache || p.current {
		return
	}
	ls := p.ls
	for _, s := range p.steps {
		ls.storeCachedSecret(s.gen, s.application, s.handshake)
	}
	p.steps = nil

	ls.applicationRatchetSecret.SecureZero()
	ls.applicationRatchetSecret = p.application
	ls.handshakeRatchetSecret.SecureZero()
	ls.handshakeRatchetSecret = p.handshake
	ls.generation = uint64(p.gen)
	p.application, p.handshake = nil, nil
}

// Discard wipes the secrets derived for a message that was rejected. It is a no-op after Commit.
// A cached or current generation owns no secrets of its own, so nothing is wiped for it.
func (p *PendingDecryption) Discard() {
	if p.done {
		return
	}
	p.done = true
	if p.fromCache || p.current {
		return
	}
	for _, s := range p.steps {
		s.application.SecureZero()
		s.handshake.SecureZero()
	}
	p.steps = nil
	p.application.SecureZero()
	p.handshake.SecureZero()
	p.application, p.handshake = nil, nil
}
