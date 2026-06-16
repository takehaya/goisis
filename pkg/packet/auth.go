package packet

import (
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // HMAC-MD5 is mandated by RFC 5304 for IS-IS auth interop
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is an RFC 5310 option for IS-IS auth interop
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
)

// AuthAlgorithm selects an IS-IS HMAC authentication algorithm. MD5 is RFC 5304
// (Authentication TLV auth-type 54, no key ID); the SHA family is RFC 5310
// generic cryptographic authentication (auth-type 3, with a 2-octet key ID).
type AuthAlgorithm uint8

// Authentication algorithms.
const (
	AuthMD5 AuthAlgorithm = iota
	AuthSHA1
	AuthSHA256
	AuthSHA384
	AuthSHA512
)

// newHash returns the hash constructor for the algorithm.
func (a AuthAlgorithm) newHash() (func() hash.Hash, bool) {
	switch a {
	case AuthMD5:
		return md5.New, true
	case AuthSHA1:
		return sha1.New, true
	case AuthSHA256:
		return sha256.New, true
	case AuthSHA384:
		return sha512.New384, true
	case AuthSHA512:
		return sha512.New, true
	default:
		return nil, false
	}
}

// digestLen is the HMAC output length for the algorithm.
func (a AuthAlgorithm) digestLen() int {
	switch a {
	case AuthMD5:
		return 16
	case AuthSHA1:
		return 20
	case AuthSHA256:
		return 32
	case AuthSHA384:
		return 48
	case AuthSHA512:
		return 64
	default:
		return 0
	}
}

// authType is the Authentication TLV auth-type byte for the algorithm: 54 for
// HMAC-MD5 (RFC 5304), 3 for the SHA family (RFC 5310 generic crypto auth).
func (a AuthAlgorithm) authType() AuthType {
	if a == AuthMD5 {
		return AuthTypeHMACMD5
	}
	return AuthTypeGeneric
}

// AuthTLV builds a zeroed Authentication TLV placeholder for an algorithm; the
// digest is filled in by PatchAuth/FinalizeLSPAuth after serialization. For the
// SHA family the value is keyID(2) + zeroed digest; for MD5 it is just the
// zeroed digest (no key ID).
func AuthTLV(algo AuthAlgorithm, keyID uint16) *AuthenticationTLV {
	if algo == AuthMD5 {
		return &AuthenticationTLV{AuthType: AuthTypeHMACMD5, Value: make([]byte, algo.digestLen())}
	}
	v := make([]byte, 2+algo.digestLen())
	binary.BigEndian.PutUint16(v[0:2], keyID)
	return &AuthenticationTLV{AuthType: AuthTypeGeneric, Value: v}
}

// HeaderLen returns the fixed-header length (the TLV-area offset) for a PDU
// type, or 0 if the type is unknown.
func HeaderLen(t PDUType) int {
	switch t {
	case PDUTypeL1LANHello, PDUTypeL2LANHello:
		return lanHelloHeaderLen
	case PDUTypeP2PHello:
		return p2pHelloHeaderLen
	case PDUTypeL1LSP, PDUTypeL2LSP:
		return lspHeaderLen
	case PDUTypeL1CSNP, PDUTypeL2CSNP:
		return csnpHeaderLen
	case PDUTypeL1PSNP, PDUTypeL2PSNP:
		return psnpHeaderLen
	default:
		return 0
	}
}

// authDigestRange locates the HMAC digest inside a serialized PDU's
// Authentication TLV matching algo (and, for the SHA family, keyID). tlvOffset
// is where the TLV area begins. It returns the digest's byte range.
func authDigestRange(pdu []byte, tlvOffset int, algo AuthAlgorithm, keyID uint16) (start, end int, ok bool) {
	at := byte(algo.authType())
	dl := algo.digestLen()
	for i := tlvOffset; i+2 <= len(pdu); {
		typ, l := pdu[i], int(pdu[i+1])
		if i+2+l > len(pdu) {
			break
		}
		v := i + 2 // value start: the auth-type byte
		if TLVType(typ) == TLVTypeAuthentication && l >= 1 && pdu[v] == at {
			if algo == AuthMD5 {
				if l == 1+dl {
					return v + 1, v + 1 + dl, true
				}
			} else if l == 3+dl && uint16(pdu[v+1])<<8|uint16(pdu[v+2]) == keyID {
				return v + 3, v + 3 + dl, true
			}
		}
		i += 2 + l
	}
	return 0, 0, false
}

// hmacOver computes the HMAC over pdu with the digest field (and, for an LSP,
// the remaining-lifetime and checksum fields) zeroed, as RFC 5304/5310 require.
func hmacOver(pdu []byte, digestStart, digestEnd int, isLSP bool, key []byte, hf func() hash.Hash) []byte {
	buf := make([]byte, len(pdu))
	copy(buf, pdu)
	for j := digestStart; j < digestEnd; j++ {
		buf[j] = 0
	}
	if isLSP {
		buf[10], buf[11] = 0, 0 // remaining lifetime
		buf[24], buf[25] = 0, 0 // Fletcher checksum
	}
	m := hmac.New(hf, key)
	m.Write(buf)
	return m.Sum(nil)
}

// PatchAuth fills the HMAC digest of a serialized PDU whose Authentication TLV
// holds a zeroed digest for algo. isLSP zeroes the LSP lifetime/checksum before
// hashing (the caller must (re)compute the Fletcher checksum afterwards).
func PatchAuth(pdu []byte, tlvOffset int, algo AuthAlgorithm, keyID uint16, key []byte, isLSP bool) error {
	hf, ok := algo.newHash()
	if !ok {
		return fmt.Errorf("packet: unsupported auth algorithm %d", algo)
	}
	s, e, ok := authDigestRange(pdu, tlvOffset, algo, keyID)
	if !ok {
		return fmt.Errorf("packet: no matching authentication TLV to patch")
	}
	copy(pdu[s:e], hmacOver(pdu, s, e, isLSP, key, hf))
	return nil
}

// VerifyAuth reports whether a serialized PDU carries a valid HMAC digest for
// algo/keyID/key. It returns false if no matching authentication TLV is present.
func VerifyAuth(pdu []byte, tlvOffset int, algo AuthAlgorithm, keyID uint16, key []byte, isLSP bool) bool {
	hf, ok := algo.newHash()
	if !ok {
		return false
	}
	s, e, ok := authDigestRange(pdu, tlvOffset, algo, keyID)
	if !ok {
		return false
	}
	// hmacOver hashes a copy, so pdu[s:e] still holds the received digest.
	return hmac.Equal(pdu[s:e], hmacOver(pdu, s, e, isLSP, key, hf))
}

// FinalizeLSPAuth fills the HMAC digest in a serialized LSP's Authentication TLV
// and then recomputes the Fletcher checksum over the LSP (the digest is part of
// the checksum coverage, so it must be set first).
func FinalizeLSPAuth(pdu []byte, algo AuthAlgorithm, keyID uint16, key []byte) error {
	if err := PatchAuth(pdu, lspHeaderLen, algo, keyID, key, true); err != nil {
		return err
	}
	pdu[24], pdu[25] = 0, 0
	sum := fletcherChecksum(pdu[12:], 12)
	binary.BigEndian.PutUint16(pdu[24:26], sum)
	return nil
}

// PatchHMACMD5 / VerifyHMACMD5 are RFC 5304 (HMAC-MD5) shortcuts over the
// algorithm-generic functions.
func PatchHMACMD5(pdu []byte, tlvOffset int, key []byte, isLSP bool) error {
	return PatchAuth(pdu, tlvOffset, AuthMD5, 0, key, isLSP)
}

// VerifyHMACMD5 verifies an HMAC-MD5 digest (RFC 5304).
func VerifyHMACMD5(pdu []byte, tlvOffset int, key []byte, isLSP bool) bool {
	return VerifyAuth(pdu, tlvOffset, AuthMD5, 0, key, isLSP)
}
