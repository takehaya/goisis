package server

import "github.com/takehaya/goisis/pkg/packet"

// authSpec is the resolved HMAC configuration for one authentication scope (a
// hello circuit, or a level's LSPs/SNPs). A zero spec (nil key) means the scope
// is unauthenticated.
type authSpec struct {
	algo  packet.AuthAlgorithm
	keyID uint16
	key   []byte
}

// on reports whether authentication is configured for the scope.
func (a authSpec) on() bool { return len(a.key) > 0 }

// authKey returns the LSP/SNP authentication spec for a level (zero if none).
func (s *IsisServer) authKey(level packet.Level) authSpec { return s.authKeys[level] }

// helloSpec returns the circuit's hello authentication spec (zero if none).
func (c *circuit) helloSpec() authSpec {
	if c.cfg.HelloPassword == "" {
		return authSpec{}
	}
	return authSpec{algo: c.cfg.HelloAuthAlgorithm, keyID: c.cfg.HelloKeyID, key: []byte(c.cfg.HelloPassword)}
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
func (s *IsisServer) pduAuthOK(raw []byte, pt packet.PDUType, level packet.Level, isLSP bool) bool {
	spec := s.authKey(level)
	if !spec.on() {
		return true
	}
	if !packet.VerifyAuth(raw, packet.HeaderLen(pt), spec.algo, spec.keyID, spec.key, isLSP) {
		s.logger.Debug("drop PDU failing authentication", "type", pt, "level", level)
		return false
	}
	return true
}
