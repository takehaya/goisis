package server

import "github.com/takehaya/goisis/pkg/packet"

// authKey returns the HMAC-MD5 key for LSPs/SNPs at a level (RFC 5304), or nil
// when the level is not authenticated.
func (s *IsisServer) authKey(level packet.Level) []byte { return s.authKeys[level] }

// authTLVPlaceholder is an HMAC-MD5 Authentication TLV with a zeroed digest; the
// digest is filled after serialization (when the whole PDU is known).
func authTLVPlaceholder() packet.TLV {
	return &packet.AuthenticationTLV{AuthType: packet.AuthTypeHMACMD5, Value: make([]byte, 16)}
}

// serializeLSP serializes an own LSP and, when its level is authenticated,
// fills the HMAC-MD5 digest and recomputes the Fletcher checksum. The LSP's
// TLVs must already include the auth placeholder when the level is keyed.
func (s *IsisServer) serializeLSP(lsp *packet.LSP) ([]byte, error) {
	raw, err := lsp.Serialize()
	if err != nil {
		return nil, err
	}
	if key := s.authKey(lsp.Level); key != nil {
		if err := packet.FinalizeLSPAuth(raw, key); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

// pduAuthOK verifies a received PDU's HMAC-MD5 authentication for its level.
// With no key configured for the level every PDU passes.
func (s *IsisServer) pduAuthOK(raw []byte, pt packet.PDUType, level packet.Level, isLSP bool) bool {
	key := s.authKey(level)
	if key == nil {
		return true
	}
	if !packet.VerifyHMACMD5(raw, packet.HeaderLen(pt), key, isLSP) {
		s.logger.Debug("drop PDU failing authentication", "type", pt, "level", level)
		return false
	}
	return true
}
