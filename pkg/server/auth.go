package server

import (
	"fmt"

	"github.com/takehaya/goisis/pkg/packet"
)

// authSpec is the resolved HMAC configuration for one authentication scope (a
// hello circuit, or a level's LSPs/SNPs). A zero spec (nil key) means the scope
// is unauthenticated. key signs; acceptKeys are additional keys honored on
// receive, which is what lets a key be rotated without every node switching at
// the same instant (RFC 5304/5310 leave key management to the operator).
type authSpec struct {
	algo       packet.AuthAlgorithm
	keyID      uint16
	key        []byte
	acceptKeys [][]byte
}

// on reports whether authentication is configured for the scope.
func (a authSpec) on() bool { return len(a.key) > 0 }

// verify reports whether a PDU carries a valid digest for the signing key or
// for any accept key.
func (a authSpec) verify(pdu []byte, tlvOffset int, isLSP bool) bool {
	if packet.VerifyAuth(pdu, tlvOffset, a.algo, a.keyID, a.key, isLSP) {
		return true
	}
	for _, k := range a.acceptKeys {
		if packet.VerifyAuth(pdu, tlvOffset, a.algo, a.keyID, k, isLSP) {
			return true
		}
	}
	return false
}

// acceptKeys converts configured accept-list passwords to keys. An empty entry
// is dropped rather than turned into an empty HMAC key, which would accept any
// PDU an attacker signed with the empty key.
func acceptKeys(passwords []string) [][]byte {
	var keys [][]byte
	for _, pw := range passwords {
		if pw == "" {
			continue
		}
		keys = append(keys, []byte(pw))
	}
	return keys
}

// requirePrimaryPassword rejects an accept list configured without a signing
// password. Such a scope signs nothing and, since acceptKeys drops the empty
// entries the missing password would otherwise produce, verifies nothing
// either: it silently degrades to unauthenticated. That is the shape a
// mistyped key rotation (docs/configuration.md) takes, so it is a
// configuration error rather than a warning.
func requirePrimaryPassword(scope, primary string, accept []string) error {
	if primary == "" && len(accept) > 0 {
		return fmt.Errorf("%s: accept passwords require a primary password", scope)
	}
	return nil
}

// authKey returns the LSP/SNP authentication spec for a level (zero if none).
func (s *IsisServer) authKey(level packet.Level) authSpec { return s.authKeys[level] }

// helloSpec returns the circuit's hello authentication spec (zero if none).
func (c *circuit) helloSpec() authSpec {
	if c.cfg.HelloPassword == "" {
		return authSpec{}
	}
	return authSpec{
		algo:       c.cfg.HelloAuthAlgorithm,
		keyID:      c.cfg.HelloKeyID,
		key:        []byte(c.cfg.HelloPassword),
		acceptKeys: acceptKeys(c.cfg.HelloAcceptPasswords),
	}
}

// authTLVPlaceholder builds a zeroed Authentication TLV for a spec; the digest
// is filled after serialization.
func authTLVPlaceholder(spec authSpec) packet.TLV {
	return packet.AuthTLV(spec.algo, spec.keyID)
}

// serializeLSP serializes an own LSP and, when its level is authenticated,
// fills the HMAC digest and recomputes the Fletcher checksum. The LSP's TLVs
// must already include the auth placeholder when the level is keyed.
func (s *IsisServer) serializeLSP(lsp *packet.LSP) ([]byte, error) {
	raw, err := lsp.Serialize()
	if err != nil {
		return nil, err
	}
	if spec := s.authKey(lsp.Level); spec.on() {
		if err := packet.FinalizeLSPAuth(raw, spec.algo, spec.keyID, spec.key); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

// pduAuthOK verifies a received PDU's authentication for its level. With no key
// configured for the level every PDU passes.
func (s *IsisServer) pduAuthOK(c *circuit, raw []byte, pt packet.PDUType, level packet.Level, isLSP bool) bool {
	spec := s.authKey(level)
	if !spec.on() {
		return true
	}
	if !spec.verify(raw, packet.HeaderLen(pt), isLSP) {
		s.logger.Debug("drop PDU failing authentication", "type", pt, "level", level)
		s.metrics.PDUDrop(c.cfg.Name, dropAuth)
		return false
	}
	return true
}
