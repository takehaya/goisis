package packet

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestGoldenFRR decodes real PDUs captured from FRR isisd (see
// test/fixturegen) and asserts that re-serializing reproduces FRR's bytes
// exactly. This is the codec's primary interop guarantee: byte-for-byte
// agreement with the de-facto reference implementation, including the
// Fletcher checksum on LSPs.
func TestGoldenFRR(t *testing.T) {
	matches, err := filepath.Glob("testdata/frr_pdu_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("no golden fixtures found under testdata/")
	}
	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			wire, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			pdu, err := DecodePDU(wire)
			if err != nil {
				t.Fatalf("DecodePDU: %v", err)
			}

			// Filename encodes the expected PDU type as leading digits:
			// frr_pdu_NN.bin or frr_pdu_NN_<suffix>.bin.
			base := strings.TrimPrefix(filepath.Base(path), "frr_pdu_")
			base, _, _ = strings.Cut(base, ".")
			digits, _, _ := strings.Cut(base, "_")
			wantType, err := strconv.Atoi(digits)
			if err != nil {
				t.Fatalf("bad fixture name %q: %v", path, err)
			}
			if int(pdu.PDUType()) != wantType {
				t.Errorf("PDUType = %d, want %d", pdu.PDUType(), wantType)
			}

			out, err := pdu.Serialize()
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}
			if !bytes.Equal(out, wire) {
				t.Fatalf("re-serialize differs from FRR bytes:\n got %x\nwant %x", out, wire)
			}

			if lsp, ok := pdu.(*LSP); ok {
				valid, err := lsp.ChecksumValid()
				if err != nil {
					t.Fatalf("ChecksumValid: %v", err)
				}
				if !valid {
					t.Errorf("FRR LSP checksum %04x failed verification", lsp.Checksum())
				}
			}
		})
	}
}

// TestGoldenCoverage asserts the golden corpus exercises every PDU type the
// codec implements, so a regression in any one decoder is caught.
func TestGoldenCoverage(t *testing.T) {
	matches, _ := filepath.Glob("testdata/frr_pdu_*.bin")
	have := map[PDUType]bool{}
	for _, path := range matches {
		wire, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		pdu, err := DecodePDU(wire)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		have[pdu.PDUType()] = true
	}
	for _, want := range []PDUType{
		PDUTypeL1LANHello, PDUTypeL2LANHello, PDUTypeP2PHello,
		PDUTypeL1LSP, PDUTypeL2LSP,
		PDUTypeL1CSNP, PDUTypeL2CSNP,
		PDUTypeL1PSNP, PDUTypeL2PSNP,
	} {
		if !have[want] {
			t.Errorf("no golden fixture for %v", want)
		}
	}
}
