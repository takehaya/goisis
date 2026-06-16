package server

import (
	"context"
	"net/netip"
	"testing"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/fib"
	"github.com/takehaya/goisis/pkg/packet"
)

// hasLocatorTLV reports whether this node's own LSP advertises the given
// locator prefix in an SRv6 Locator TLV.
func hasLocatorTLV(t *testing.T, s *IsisServer, p netip.Prefix) bool {
	t.Helper()
	for _, tlv := range ownLSPTLVs(t, s) {
		lt, ok := tlv.(*packet.SRv6LocatorTLV)
		if !ok {
			continue
		}
		for _, l := range lt.Locators {
			if l.Locator.Masked() == p.Masked() {
				return true
			}
		}
	}
	return false
}

// hasSRAlgo reports whether this node's own LSP advertises participation in the
// given algorithm in its SR-Algorithm sub-TLV.
func hasSRAlgo(t *testing.T, s *IsisServer, algo uint8) bool {
	t.Helper()
	for _, tlv := range ownLSPTLVs(t, s) {
		rc, ok := tlv.(*packet.RouterCapabilityTLV)
		if !ok {
			continue
		}
		for _, st := range rc.SubTLVs {
			sa, ok := st.(*packet.SRAlgorithmSubTLV)
			if !ok {
				continue
			}
			for _, a := range sa.Algorithms {
				if a == algo {
					return true
				}
			}
		}
	}
	return false
}

// mutateServer returns a single running server with a recording FIB.
func mutateServer(t *testing.T) (*IsisServer, *recordFIB, context.CancelFunc) {
	t.Helper()
	cfg := CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}
	fastHello(&cfg)
	rf := newRecordFIB()
	s := mustServer(t,
		WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
		WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
		WithCircuit(cfg), WithFIB(rf),
	)
	ctx, cancel := context.WithCancel(context.Background())
	go s.Serve(ctx) //nolint:errcheck // ctx shutdown
	return s, rf, cancel
}

func TestAddDeleteLocator(t *testing.T) {
	s, rf, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()
	loc := netip.MustParsePrefix("fc00:0:1::/48")

	if err := s.AddLocator(ctx, SRv6LocatorConfig{Prefix: loc}); err != nil {
		t.Fatalf("AddLocator: %v", err)
	}
	// The local End SID is installed and the locator is advertised.
	waitFor(t, "End SID installed", func() bool {
		sid, ok := rf.getSID(loc.Masked().Addr())
		return ok && sid.Behavior == fib.BehaviorEnd
	})
	waitFor(t, "locator advertised", func() bool { return hasLocatorTLV(t, s, loc) })

	// Re-adding the same locator is rejected.
	if err := s.AddLocator(ctx, SRv6LocatorConfig{Prefix: loc}); err == nil {
		t.Error("expected error re-adding an existing locator")
	}
	// A non-IPv6 locator is rejected.
	if err := s.AddLocator(ctx, SRv6LocatorConfig{Prefix: netip.MustParsePrefix("10.0.0.0/24")}); err == nil {
		t.Error("expected error for non-IPv6 locator")
	}

	if err := s.DeleteLocator(ctx, loc); err != nil {
		t.Fatalf("DeleteLocator: %v", err)
	}
	waitFor(t, "End SID removed", func() bool {
		_, ok := rf.getSID(loc.Masked().Addr())
		return !ok
	})
	waitFor(t, "locator withdrawn", func() bool { return !hasLocatorTLV(t, s, loc) })

	// Deleting an unknown locator is rejected.
	if err := s.DeleteLocator(ctx, loc); err == nil {
		t.Error("expected error deleting an unadvertised locator")
	}
}

func TestAddDeleteFlexAlgo(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()

	if err := s.AddFlexAlgo(ctx, FlexAlgoConfig{Algo: 128, Priority: 100, AdvertiseDefinition: true}); err != nil {
		t.Fatalf("AddFlexAlgo: %v", err)
	}
	waitFor(t, "algo 128 advertised", func() bool { return hasSRAlgo(t, s, 128) })

	// Reserved and duplicate algorithms are rejected.
	if err := s.AddFlexAlgo(ctx, FlexAlgoConfig{Algo: 5}); err == nil {
		t.Error("expected error for reserved Flex-Algo (<128)")
	}
	if err := s.AddFlexAlgo(ctx, FlexAlgoConfig{Algo: 128}); err == nil {
		t.Error("expected error for duplicate Flex-Algo")
	}

	// Binding a locator to the algo, then attempting to delete the algo, is
	// rejected until the locator is removed.
	loc := netip.MustParsePrefix("fc00:0:128::/48")
	if err := s.AddLocator(ctx, SRv6LocatorConfig{Prefix: loc, Algo: 128}); err != nil {
		t.Fatalf("AddLocator(algo): %v", err)
	}
	if err := s.DeleteFlexAlgo(ctx, 128); err == nil {
		t.Error("expected error deleting Flex-Algo with a bound locator")
	}
	if err := s.DeleteLocator(ctx, loc); err != nil {
		t.Fatalf("DeleteLocator: %v", err)
	}
	if err := s.DeleteFlexAlgo(ctx, 128); err != nil {
		t.Fatalf("DeleteFlexAlgo: %v", err)
	}
	waitFor(t, "algo 128 withdrawn", func() bool { return !hasSRAlgo(t, s, 128) })

	// Deleting an unknown algo is rejected.
	if err := s.DeleteFlexAlgo(ctx, 200); err == nil {
		t.Error("expected error deleting an unconfigured Flex-Algo")
	}
}

// TestAddLocatorRequiresAlgoParticipation checks a flex-algo-bound locator is
// rejected until the node participates in that algorithm.
func TestAddLocatorRequiresAlgoParticipation(t *testing.T) {
	s, _, cancel := mutateServer(t)
	defer cancel()
	ctx := context.Background()
	loc := netip.MustParsePrefix("fc00:0:128::/48")

	if err := s.AddLocator(ctx, SRv6LocatorConfig{Prefix: loc, Algo: 128}); err == nil {
		t.Error("expected error binding a locator to an unparticipated algo")
	}
	if err := s.AddFlexAlgo(ctx, FlexAlgoConfig{Algo: 128}); err != nil {
		t.Fatalf("AddFlexAlgo: %v", err)
	}
	if err := s.AddLocator(ctx, SRv6LocatorConfig{Prefix: loc, Algo: 128}); err != nil {
		t.Errorf("AddLocator after participation: %v", err)
	}
}
