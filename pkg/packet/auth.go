package packet

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // HMAC-MD5 is mandated by RFC 5304 for IS-IS auth interop
	"fmt"
)

// hmacMD5DigestLen is the fixed HMAC-MD5 digest length (RFC 5304).
const hmacMD5DigestLen = 16

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

// findHMACMD5Digest locates the 16-octet HMAC-MD5 digest inside a serialized
// PDU's Authentication TLV (type 10, auth-type 54). tlvOffset is where the TLV
// area begins. It returns the digest's byte range and whether it was found.
func findHMACMD5Digest(pdu []byte, tlvOffset int) (start, end int, ok bool) {
	for i := tlvOffset; i+2 <= len(pdu); {
		typ, l := pdu[i], int(pdu[i+1])
		if i+2+l > len(pdu) {
			break
		}
		if TLVType(typ) == TLVTypeAuthentication && l == 1+hmacMD5DigestLen && pdu[i+2] == byte(AuthTypeHMACMD5) {
			return i + 3, i + 3 + hmacMD5DigestLen, true
		}
		i += 2 + l
	}
	return 0, 0, false
}

// hmacMD5Over computes the HMAC-MD5 over pdu with the digest field (and, for an
// LSP, the remaining-lifetime and checksum fields) zeroed, as RFC 5304 requires.
func hmacMD5Over(pdu []byte, digestStart, digestEnd int, isLSP bool, key []byte) [hmacMD5DigestLen]byte {
	buf := make([]byte, len(pdu))
	copy(buf, pdu)
	for j := digestStart; j < digestEnd; j++ {
		buf[j] = 0
	}
	if isLSP {
		buf[10], buf[11] = 0, 0 // remaining lifetime
		buf[24], buf[25] = 0, 0 // Fletcher checksum
	}
	m := hmac.New(md5.New, key)
	m.Write(buf)
	var out [hmacMD5DigestLen]byte
	copy(out[:], m.Sum(nil))
	return out
}

// PatchHMACMD5 fills the HMAC-MD5 digest of a serialized PDU whose Authentication
// TLV holds a zeroed 16-octet digest. isLSP zeroes the LSP lifetime/checksum
// before hashing (and the caller must (re)compute the Fletcher checksum after).
func PatchHMACMD5(pdu []byte, tlvOffset int, key []byte, isLSP bool) error {
	s, e, ok := findHMACMD5Digest(pdu, tlvOffset)
	if !ok {
		return fmt.Errorf("packet: no HMAC-MD5 authentication TLV to patch")
	}
	d := hmacMD5Over(pdu, s, e, isLSP, key)
	copy(pdu[s:e], d[:])
	return nil
}

// VerifyHMACMD5 reports whether a serialized PDU carries a valid HMAC-MD5
// digest for key. It returns false if no HMAC-MD5 authentication TLV is present.
func VerifyHMACMD5(pdu []byte, tlvOffset int, key []byte, isLSP bool) bool {
	s, e, ok := findHMACMD5Digest(pdu, tlvOffset)
	if !ok {
		return false
	}
	want := make([]byte, e-s)
	copy(want, pdu[s:e])
	got := hmacMD5Over(pdu, s, e, isLSP, key)
	return hmac.Equal(want, got[:])
}
