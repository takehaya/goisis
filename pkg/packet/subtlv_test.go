package packet

import (
	"bytes"
	"testing"
)

// TestSubTLVDecoderErrorStaysOpaque pins the containment where it is decided —
// decodeSubTLVs, not any one decoder. RFC 5305 §2 has a reader skip a sub-TLV
// it cannot use, and skipping is not rejecting the PDU that carries it; a
// value a registered decoder refuses is therefore preserved opaquely, exactly
// as an unregistered code point is. Walking the registry rather than a list of
// code points means a decoder added later inherits the rule.
func TestSubTLVDecoderErrorStaysOpaque(t *testing.T) {
	// One octet is a value every decoder that validates a length refuses; one
	// that accepts it says nothing about containment, so it is skipped.
	wire := []byte{0, 1, 0xff}
	pinned := 0
	for ctx, decoders := range subTLVDecoders {
		for typ, dec := range decoders {
			if _, err := dec(wire[2:]); err == nil {
				continue
			}
			pinned++
			wire[0] = typ
			subs, err := decodeSubTLVs(ctx, wire)
			if err != nil {
				t.Errorf("context %d sub-TLV %d: decodeSubTLVs = %v, want no error", ctx, typ, err)
				continue
			}
			if len(subs) != 1 {
				t.Errorf("context %d sub-TLV %d: got %d sub-TLVs, want 1", ctx, typ, len(subs))
				continue
			}
			if _, ok := subs[0].(*UnknownSubTLV); !ok {
				t.Errorf("context %d sub-TLV %d: decoded as %T, want it left opaque", ctx, typ, subs[0])
				continue
			}
			out, err := serializeSubTLVs(subs)
			if err != nil || !bytes.Equal(out, wire) {
				t.Errorf("context %d sub-TLV %d: re-encode = %x, %v; want %x", ctx, typ, out, err, wire)
			}
		}
	}
	if pinned == 0 {
		t.Fatal("no registered decoder refused the value, so nothing was pinned")
	}
}
