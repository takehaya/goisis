package packet

import "errors"

// Sentinel errors. Decode errors wrap one of these; use errors.Is to
// classify them when counting drops.
var (
	// ErrTruncated reports input shorter than a length field promised.
	ErrTruncated = errors.New("truncated")
	// ErrUnknownPDUType reports a PDU type this package cannot decode.
	ErrUnknownPDUType = errors.New("unknown PDU type")
	// ErrTooLong reports a value that does not fit its length field.
	ErrTooLong = errors.New("value too long")

	errBadDiscriminator = errors.New("bad protocol discriminator")
	errBadVersion       = errors.New("unsupported protocol version")
	errBadIDLength      = errors.New("unsupported ID length")
	errBadFixedHeader   = errors.New("bad fixed header")
	errBadTLV           = errors.New("malformed TLV")
)
