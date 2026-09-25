package server

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/packet"
)

// affinityLoc is the algorithm-128 SRv6 locator the peer advertises in these
// tests: reaching it is the observable that says the link was not pruned.
var affinityLoc = netip.MustParsePrefix("fc00:128:aa::/48")

const (
	colorRed  = 0x0000_0004
	colorBlue = 0x0000_0008
)

// aslaColors builds the sub-TLVs of one IS-reachability entry for a link
// painted with the given colors, as goisis itself originates them: one ASLA
// naming the Flex-Algorithm application, carrying an admin group.
func aslaColors(words ...uint32) []packet.SubTLV {
	return []packet.SubTLV{&packet.ASLASubTLV{
		SABM:       []byte{packet.ASLAAppFlexAlgo},
		SubSubTLVs: []packet.SubTLV{&packet.AdminGroupSubTLV{Extended: len(words) > 1, Groups: words}},
	}}
}

// colorReach is isReach with sub-TLVs on every entry.
func colorReach(subs []packet.SubTLV, neighbors ...packet.NodeID) packet.TLV {
	var nbs []packet.ExtendedISReachEntry
	for _, n := range neighbors {
		nbs = append(nbs, packet.ExtendedISReachEntry{NeighborID: n, Metric: 10, SubTLVs: subs})
	}
	return &packet.ExtendedISReachabilityTLV{Neighbors: nbs}
}

// agConstraint builds a FAD admin-group constraint sub-sub-TLV (RFC 9350 §6.1
// to §6.3) over the given 4-octet units.
func agConstraint(typ uint8, words ...uint32) packet.FlexAlgoSubSubTLV {
	v := make([]byte, 4*len(words))
	for i, w := range words {
		binary.BigEndian.PutUint32(v[4*i:], w)
	}
	return packet.FlexAlgoSubSubTLV{SubSubTLVType: typ, Value: v}
}

// injectNodeLSP is injectLSP for a node the caller names by NodeID — a LAN
// pseudonode has no system ID of its own to pass.
func injectNodeLSP(s *IsisServer, id packet.NodeID, tlvs []packet.TLV, now time.Time) {
	seedImpliedAdjacencies(s, packet.Level2, id, tlvs)
	lid := packet.LSPID(append(append([]byte{}, id[:]...), 0)) //nolint:gocritic // build the 8-octet LSP ID
	s.dbs[packet.Level2].entries[lid] = &lspEntry{
		lsp:      &packet.LSP{Level: packet.Level2, RemainingTime: maxAgeSeconds, LSPID: lid, SequenceNumber: 1, ISType: 2, TLVs: tlvs},
		inserted: now,
		lifetime: maxAgeSeconds,
	}
}

// reachesOverLink installs a two-node algorithm-128 area — self and a peer
// advertising affinityLoc, joined by one link whose entries carry subs at both
// ends — and reports whether SPF still reaches the locator under a definition
// carrying cons.
func reachesOverLink(t *testing.T, subs []packet.SubTLV, cons ...packet.FlexAlgoSubSubTLV) bool {
	t.Helper()
	s := electionServer(t)
	now := time.Now()
	self, peer := nodeID(packet.SystemID{0, 0, 0, 0, 0, 1}, 0), nodeID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0)
	injectNodeLSP(s, self, []packet.TLV{partCap(), colorReach(subs, peer)}, now)
	injectNodeLSP(s, peer, []packet.TLV{partCap(), colorReach(subs, self), algoLocTLV(affinityLoc)}, now)

	aff, err := flexAlgoAffinityOf(&FlexAlgoDefinition{Algo: 128, Constraints: cons})
	if err != nil {
		t.Fatalf("flexAlgoAffinityOf: %v", err)
	}
	_, ok := s.computeSPF(packet.Level2, 128, aff, now)[affinityLoc]
	return ok
}

// TestFlexAlgoExcludeAdminGroupPrunes is RFC 9350 §13 step 1: a link carrying a
// color the definition excludes is not used.
func TestFlexAlgoExcludeAdminGroupPrunes(t *testing.T) {
	red := aslaColors(colorRed)
	if reachesOverLink(t, red, agConstraint(packet.FlexAlgoSubSubExcludeAdminGroup, colorRed)) {
		t.Error("a link carrying an excluded color was used")
	}
	if !reachesOverLink(t, red, agConstraint(packet.FlexAlgoSubSubExcludeAdminGroup, colorBlue)) {
		t.Error("control: the same link must be used when the exclude rule names a color it does not carry")
	}
}

// TestFlexAlgoIncludeAnyPrunes is RFC 9350 §13 step 3: a link carrying none of
// the colors the definition includes is pruned — and an uncolored link carries
// none, which is why a node that prunes must also advertise its own colors.
func TestFlexAlgoIncludeAnyPrunes(t *testing.T) {
	includeRed := agConstraint(packet.FlexAlgoSubSubIncludeAnyAdminGroup, colorRed)
	if reachesOverLink(t, aslaColors(colorBlue), includeRed) {
		t.Error("a link carrying only another color was used under include-any")
	}
	if reachesOverLink(t, nil, includeRed) {
		t.Error("a link advertising no link attributes at all was used under include-any")
	}
	if !reachesOverLink(t, aslaColors(colorRed|colorBlue), includeRed) {
		t.Error("control: a link carrying one of the included colors must be used")
	}
}

// TestFlexAlgoIncludeAllPrunes is RFC 9350 §13 step 4: every color the
// definition names has to be set on the link, not just one of them.
func TestFlexAlgoIncludeAllPrunes(t *testing.T) {
	includeBoth := agConstraint(packet.FlexAlgoSubSubIncludeAllAdminGroup, colorRed|colorBlue)
	if reachesOverLink(t, aslaColors(colorRed), includeBoth) {
		t.Error("a link carrying only one of the required colors was used")
	}
	if !reachesOverLink(t, aslaColors(colorRed|colorBlue), includeBoth) {
		t.Error("control: a link carrying both required colors must be used")
	}
	// A rule naming a color in a word the link does not advertise is unmet,
	// not vacuously met: RFC 7308 sends the minimum length, so a missing word
	// is all zeros.
	if reachesOverLink(t, aslaColors(colorRed), agConstraint(packet.FlexAlgoSubSubIncludeAllAdminGroup, colorRed, colorBlue)) {
		t.Error("include-all was satisfied by a word the link never advertised")
	}
	// The same convention the other way round: a rule word naming no color at
	// all is met by every link. RFC 9350 §13 step 4 asks whether all the
	// colors of the rule are set on the link, and a zero word names none —
	// and RFC 7308's minimum length is a SHOULD, so an advertiser is free to
	// pad its rule past its significant words.
	if !reachesOverLink(t, aslaColors(colorRed), agConstraint(packet.FlexAlgoSubSubIncludeAllAdminGroup, colorRed, 0)) {
		t.Error("include-all pruned a link carrying every color the rule names, because the rule was padded")
	}
}

// TestFlexAlgoPrunedLinkIsPrunedBothWays: coloring is only ever read off one
// end, because the two-way connectivity check already requires the reverse
// edge (RFC 9350 §13 reuses the algorithm-agnostic check). A link excluded at
// the far end alone must still be unusable.
func TestFlexAlgoPrunedLinkIsPrunedBothWays(t *testing.T) {
	s := electionServer(t)
	now := time.Now()
	self, peer := nodeID(packet.SystemID{0, 0, 0, 0, 0, 1}, 0), nodeID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0)
	injectNodeLSP(s, self, []packet.TLV{partCap(), colorReach(nil, peer)}, now)
	injectNodeLSP(s, peer, []packet.TLV{partCap(), colorReach(aslaColors(colorRed), self), algoLocTLV(affinityLoc)}, now)

	aff, err := flexAlgoAffinityOf(&FlexAlgoDefinition{Algo: 128, Constraints: []packet.FlexAlgoSubSubTLV{
		agConstraint(packet.FlexAlgoSubSubExcludeAdminGroup, colorRed),
	}})
	if err != nil {
		t.Fatalf("flexAlgoAffinityOf: %v", err)
	}
	if _, ok := s.computeSPF(packet.Level2, 128, aff, now)[affinityLoc]; ok {
		t.Error("only the peer's end of the link was colored, and the link was used anyway")
	}
}

// TestFlexAlgoColoredLANDoesNotGoDark is the pseudonode case. A LAN
// pseudonode's LSP is originated by the DIS and never carries link attributes;
// RFC 9350 §13 colors the member's edge towards it. Applying the include rule
// to the pseudonode's own edges back would prune every one of them and take
// the whole LAN dark.
func TestFlexAlgoColoredLANDoesNotGoDark(t *testing.T) {
	lan := func(t *testing.T, subs []packet.SubTLV) bool {
		t.Helper()
		s := electionServer(t)
		now := time.Now()
		self := nodeID(packet.SystemID{0, 0, 0, 0, 0, 1}, 0)
		peer := nodeID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0)
		pn := nodeID(packet.SystemID{0, 0, 0, 0, 0, 1}, 7)
		injectNodeLSP(s, self, []packet.TLV{partCap(), colorReach(subs, pn)}, now)
		// The DIS's pseudonode LSP: metric-0 edges to both members, no
		// attributes, no Router Capability of its own.
		injectNodeLSP(s, pn, []packet.TLV{&packet.ExtendedISReachabilityTLV{Neighbors: []packet.ExtendedISReachEntry{
			{NeighborID: self}, {NeighborID: peer},
		}}}, now)
		injectNodeLSP(s, peer, []packet.TLV{partCap(), colorReach(subs, pn), algoLocTLV(affinityLoc)}, now)

		aff, err := flexAlgoAffinityOf(&FlexAlgoDefinition{Algo: 128, Constraints: []packet.FlexAlgoSubSubTLV{
			agConstraint(packet.FlexAlgoSubSubIncludeAnyAdminGroup, colorRed),
		}})
		if err != nil {
			t.Fatalf("flexAlgoAffinityOf: %v", err)
		}
		_, ok := s.computeSPF(packet.Level2, 128, aff, now)[affinityLoc]
		return ok
	}
	if !lan(t, aslaColors(colorRed)) {
		t.Error("a LAN colored on both members went dark under include-any")
	}
	if lan(t, aslaColors(colorBlue)) {
		t.Error("control: the same LAN must go dark when the members carry another color")
	}
}

// TestFlexAlgoColorsComeFromASLAOnly: RFC 9350 §12 lets a Flex-Algorithm read
// a link's colors from an ASLA advertisement and nowhere else, the L-flag of
// RFC 8919 §4.2 being the one door back to the legacy sub-TLVs of TLV 22.
func TestFlexAlgoColorsComeFromASLAOnly(t *testing.T) {
	legacy := &packet.AdminGroupSubTLV{Groups: []uint32{colorRed}}
	flexAlgoASLA := func(l bool) packet.SubTLV {
		return &packet.ASLASubTLV{Legacy: l, SABM: []byte{packet.ASLAAppFlexAlgo}}
	}
	tests := []struct {
		name string
		subs []packet.SubTLV
		want []uint32
	}{
		{"legacy sub-TLV with no ASLA", []packet.SubTLV{legacy}, nil},
		{"legacy sub-TLV behind the L-flag", []packet.SubTLV{flexAlgoASLA(true), legacy}, []uint32{colorRed}},
		{"ASLA for this application", aslaColors(colorRed), []uint32{colorRed}},
		{"ASLA for another application", []packet.SubTLV{&packet.ASLASubTLV{
			SABM:       []byte{packet.ASLAAppRSVPTE},
			SubSubTLVs: []packet.SubTLV{legacy},
		}}, nil},
		// RFC 8919 §4.2: zero-length bit masks serve any application that has
		// no advertisement of its own.
		{"ASLA with no bit mask", []packet.SubTLV{&packet.ASLASubTLV{SubSubTLVs: []packet.SubTLV{legacy}}}, []uint32{colorRed}},
		// ...but not once this application has one, even an empty one.
		{"ASLA with no bit mask beside one for this application", []packet.SubTLV{
			&packet.ASLASubTLV{SubSubTLVs: []packet.SubTLV{legacy}}, flexAlgoASLA(false),
		}, nil},
		// RFC 9350 §12 requires both encodings to be accepted.
		{"both admin-group encodings", []packet.SubTLV{&packet.ASLASubTLV{
			SABM: []byte{packet.ASLAAppFlexAlgo},
			SubSubTLVs: []packet.SubTLV{
				&packet.AdminGroupSubTLV{Groups: []uint32{colorRed}},
				&packet.AdminGroupSubTLV{Extended: true, Groups: []uint32{colorBlue, colorRed}},
			},
		}}, []uint32{colorRed | colorBlue, colorRed}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := flexAlgoLinkColors(tc.subs); !slices.Equal(got, tc.want) {
				t.Errorf("colors = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestFlexAlgoAffinityRejectsWhatItCannotEvaluate: a definition is either
// computed as advertised or not computed at all. Anything goisis cannot prune
// on — an excluded SRLG, an unknown sub-sub-TLV, a flag bit it does not
// implement, a malformed admin group — is an error, never a rule silently left
// out. A constraint advertised twice is not in that class and is not here: RFC
// 9350 §6 makes that definition ignorable, which loses it the election
// (TestFlexAlgoIgnorableDefinitionLosesTheElection) rather than refusing the
// algorithm.
func TestFlexAlgoAffinityRejectsWhatItCannotEvaluate(t *testing.T) {
	tests := []struct {
		name string
		cons []packet.FlexAlgoSubSubTLV
		ok   bool
	}{
		{"admin groups alone", []packet.FlexAlgoSubSubTLV{
			agConstraint(packet.FlexAlgoSubSubExcludeAdminGroup, colorRed),
			agConstraint(packet.FlexAlgoSubSubIncludeAnyAdminGroup, colorBlue),
			agConstraint(packet.FlexAlgoSubSubIncludeAllAdminGroup, colorBlue),
		}, true},
		// The M-flag governs the inter-area prefix metric and RFC 9350 §6.4
		// puts SRv6 locators outside its reach, so it changes nothing here.
		{"M-flag", []packet.FlexAlgoSubSubTLV{{SubSubTLVType: packet.FlexAlgoSubSubDefinitionFlags, Value: []byte{packet.FlexAlgoFlagM}}}, true},
		{"another definition flag", []packet.FlexAlgoSubSubTLV{{SubSubTLVType: packet.FlexAlgoSubSubDefinitionFlags, Value: []byte{0x40}}}, false},
		{"a flag in a later octet", []packet.FlexAlgoSubSubTLV{{SubSubTLVType: packet.FlexAlgoSubSubDefinitionFlags, Value: []byte{packet.FlexAlgoFlagM, 0x01}}}, false},
		{"exclude SRLG", []packet.FlexAlgoSubSubTLV{agConstraint(packet.FlexAlgoSubSubExcludeSRLG, 9)}, false},
		{"an unknown constraint", []packet.FlexAlgoSubSubTLV{{SubSubTLVType: 200, Value: []byte{1}}}, false},
		{"a misshapen admin group", []packet.FlexAlgoSubSubTLV{{SubSubTLVType: packet.FlexAlgoSubSubExcludeAdminGroup, Value: []byte{1, 2, 3}}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := flexAlgoAffinityOf(&FlexAlgoDefinition{Algo: 128, Constraints: tc.cons})
			if (err == nil) != tc.ok {
				t.Errorf("err = %v, want ok = %v", err, tc.ok)
			}
		})
	}
}

// TestFlexAlgoUnevaluableDefinitionInstallsNoRoute: the refusal reaches the
// RIB. An algorithm whose elected definition asks for a constraint goisis
// cannot evaluate installs nothing, rather than a path over links the
// definition meant to exclude.
func TestFlexAlgoUnevaluableDefinitionInstallsNoRoute(t *testing.T) {
	installs := func(t *testing.T, cons ...packet.FlexAlgoSubSubTLV) bool {
		t.Helper()
		s := mustServer(t,
			WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
			WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
			WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
			WithFlexAlgo(FlexAlgoConfig{Algo: 128}),
		)
		now := time.Now()
		self, peer := nodeID(packet.SystemID{0, 0, 0, 0, 0, 1}, 0), nodeID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0)
		fad := &packet.RouterCapabilityTLV{SubTLVs: []packet.SubTLV{
			&packet.SRAlgorithmSubTLV{Algorithms: []uint8{0, 128}},
			&packet.FlexAlgoDefinitionSubTLV{FlexAlgo: 128, MetricType: packet.FlexAlgoMetricIGP, Priority: 100, SubSubTLVs: cons},
		}}
		injectNodeLSP(s, self, []packet.TLV{partCap(), colorReach(nil, peer)}, now)
		injectNodeLSP(s, peer, []packet.TLV{fad, colorReach(nil, self), algoLocTLV(affinityLoc)}, now)
		s.updateRIB(now)
		_, ok := s.rib[affinityLoc]
		return ok
	}
	if installs(t, agConstraint(packet.FlexAlgoSubSubExcludeSRLG, 9)) {
		t.Error("an algorithm whose definition excludes an SRLG installed a route anyway")
	}
	if !installs(t) {
		t.Error("control: the same definition without the SRLG constraint must install the locator")
	}
}

// TestCircuitOriginatesAdminGroupASLA: a circuit with an admin group emits one
// ASLA naming the Flex-Algorithm application on its IS-reachability entry, and
// a circuit without one emits no link attributes at all. Advertising none
// while pruning on the neighbors' colors would take every goisis link out of
// any include-any topology.
func TestCircuitOriginatesAdminGroupASLA(t *testing.T) {
	subsFor := func(t *testing.T, groups []uint32) []packet.SubTLV {
		t.Helper()
		s := mustServer(t,
			WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
			WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
			WithCircuit(CircuitConfig{
				Name: "a", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 0xa1}, 1500),
				P2P: true, Level2: true, Padding: ptrFalse(), AdminGroup: groups,
			}),
		)
		var lv levelSet
		lv.add(packet.Level2)
		s.circuits[0].p2pAdj = &adjacency{systemID: packet.SystemID{0, 0, 0, 0, 0, 2}, state: AdjUp, levels: lv}
		now := time.Now()
		s.regenerateLSPs(false, now)
		e := s.dbs[packet.Level2].get(lspID(s.systemID, 0))
		if e == nil {
			t.Fatal("no own Level-2 LSP")
		}
		for _, tlv := range e.lsp.TLVs {
			r, ok := tlv.(*packet.ExtendedISReachabilityTLV)
			if !ok {
				continue
			}
			for _, n := range r.Neighbors {
				return n.SubTLVs
			}
		}
		t.Fatal("own LSP carries no IS reachability")
		return nil
	}
	if subs := subsFor(t, nil); len(subs) != 0 {
		t.Errorf("uncolored circuit advertised %d sub-TLVs, want none", len(subs))
	}
	subs := subsFor(t, []uint32{colorRed})
	if len(subs) != 1 {
		t.Fatalf("colored circuit advertised %d sub-TLVs, want exactly the ASLA", len(subs))
	}
	asla, ok := subs[0].(*packet.ASLASubTLV)
	if !ok || !asla.Apps(packet.ASLAAppFlexAlgo) || asla.Legacy {
		t.Fatalf("advertised %+v (%T), want an ASLA for the Flex-Algorithm application with the L-flag clear", subs[0], subs[0])
	}
	if got := flexAlgoLinkColors(subs); !slices.Equal(got, []uint32{colorRed}) {
		t.Errorf("a peer reads the circuit's colors as %v, want %v", got, []uint32{colorRed})
	}
	// Two words do not fit RFC 5305's single administrative group, so they go
	// out in the extended encoding of RFC 7308.
	if got := flexAlgoLinkColors(subsFor(t, []uint32{colorRed, colorBlue})); !slices.Equal(got, []uint32{colorRed, colorBlue}) {
		t.Errorf("a peer reads a two-word admin group as %v", got)
	}
}

// TestFlexAlgoUnevaluableDefinitionWithdrawsParticipation is the other half of
// the refusal RFC 9350 §5.3 asks for: a node that stops computing an algorithm
// "MUST NOT announce participation" in it either. §13 prunes every
// non-participating node out of the other routers' topology for that
// algorithm, so the announcement is the one thing steering algorithm-K traffic
// into a node that holds no algorithm-K forwarding state.
func TestFlexAlgoUnevaluableDefinitionWithdrawsParticipation(t *testing.T) {
	fad := func(metric uint8, cons ...packet.FlexAlgoSubSubTLV) packet.SubTLV {
		return &packet.FlexAlgoDefinitionSubTLV{FlexAlgo: 128, MetricType: metric, Priority: 100, SubSubTLVs: cons}
	}
	announces := func(t *testing.T, def packet.SubTLV) bool {
		t.Helper()
		s := mustServer(t,
			WithSystemID(packet.SystemID{0, 0, 0, 0, 0, 1}),
			WithAreaAddresses(packet.AreaAddress{0x49, 0x00, 0x01}),
			WithCircuit(CircuitConfig{Name: "c", Transport: datalink.NewMockTransport(packet.SNPA{0, 0, 0, 0, 0, 1}, 1500), Level2: true, Padding: ptrFalse()}),
			WithFlexAlgo(FlexAlgoConfig{Algo: 128}),
		)
		now := time.Now()
		injectNodeLSP(s, nodeID(packet.SystemID{0, 0, 0, 0, 0, 2}, 0), []packet.TLV{
			&packet.RouterCapabilityTLV{SubTLVs: []packet.SubTLV{
				&packet.SRAlgorithmSubTLV{Algorithms: []uint8{0, 128}}, def,
			}},
		}, now)
		s.regenerateLSPs(false, now)
		if !slices.Contains(ownSRAlgorithms(t, s), 128) {
			t.Fatal("control: the node must announce participation before the definition is read")
		}
		s.updateRIB(now)
		s.drainLSPGen(now) // the refusal has to reach the LSP without another event
		return slices.Contains(ownSRAlgorithms(t, s), 128)
	}
	if announces(t, fad(packet.FlexAlgoMetricIGP, agConstraint(packet.FlexAlgoSubSubExcludeSRLG, 9))) {
		t.Error("an algorithm whose definition excludes an SRLG is still announced as participated")
	}
	if announces(t, fad(packet.FlexAlgoMetricTE)) {
		t.Error("an algorithm whose definition asks for a metric this node cannot measure is still announced as participated")
	}
	if !announces(t, fad(packet.FlexAlgoMetricIGP)) {
		t.Error("control: a definition this node computes must keep its participation announcement")
	}
}

// ownSRAlgorithms returns the algorithms this node's own Level-2 LSP announces
// participation in (RFC 9350 §11.1).
func ownSRAlgorithms(t *testing.T, s *IsisServer) []uint8 {
	t.Helper()
	e := s.dbs[packet.Level2].get(lspID(s.systemID, 0))
	if e == nil {
		t.Fatal("no own Level-2 LSP")
	}
	var algos []uint8
	for _, tlv := range e.lsp.TLVs {
		rc, ok := tlv.(*packet.RouterCapabilityTLV)
		if !ok {
			continue
		}
		for _, sub := range rc.SubTLVs {
			if sa, ok := sub.(*packet.SRAlgorithmSubTLV); ok {
				algos = append(algos, sa.Algorithms...)
			}
		}
	}
	return algos
}
