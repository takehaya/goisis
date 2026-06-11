package packet

import (
	"errors"
	"testing"
)

func TestAreaAddressesTLVDecode(t *testing.T) {
	// Two areas: 49.0001 (3 octets) and 49 (1 octet).
	wire := mustHex(t, "01 06 03 49 00 01 01 49")
	tlvs := checkTLVRoundtrip(t, wire)
	if len(tlvs) != 1 {
		t.Fatalf("got %d TLVs, want 1", len(tlvs))
	}
	tlv, ok := tlvs[0].(*AreaAddressesTLV)
	if !ok {
		t.Fatalf("got %T, want *AreaAddressesTLV", tlvs[0])
	}
	if len(tlv.Addresses) != 2 {
		t.Fatalf("got %d addresses, want 2", len(tlv.Addresses))
	}
	if got, want := tlv.Addresses[0].String(), "49.0001"; got != want {
		t.Errorf("address 0 = %q, want %q", got, want)
	}
	if got, want := tlv.Addresses[1].String(), "49"; got != want {
		t.Errorf("address 1 = %q, want %q", got, want)
	}
}

func TestAreaAddressesTLVDecodeErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
		want error
	}{
		{"truncated address", "01 03 03 49 00", ErrTruncated},
		{"zero-length address", "01 01 00", errBadTLV},
		{"oversized address", "01 0f 0e 0000000000000000000000000000", errBadTLV},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeTLVs(mustHex(t, tc.wire))
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAreaAddressesTLVSerializeErrors(t *testing.T) {
	tlv := &AreaAddressesTLV{Addresses: []AreaAddress{make(AreaAddress, 14)}}
	if _, err := tlv.Serialize(); !errors.Is(err, errBadTLV) {
		t.Errorf("err = %v, want %v", err, errBadTLV)
	}
}
