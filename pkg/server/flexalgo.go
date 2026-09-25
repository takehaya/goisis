package server

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/takehaya/goisis/pkg/packet"
)

// FlexAlgoDefinition is the Flexible Algorithm Definition (FAD) elected for an
// algorithm at a level: the winning advertisement among all FADs in the area.
type FlexAlgoDefinition struct {
	Algo       uint8
	MetricType uint8
	CalcType   uint8
	Priority   uint8
	// Advertiser is the System ID of the node whose FAD won the election.
	Advertiser packet.SystemID
	// Constraints are the winning FAD's constraint sub-sub-TLVs (RFC 9350
	// section 6: exclude/include admin groups, definition flags,
	// exclude-SRLG), in wire order. flexAlgoAffinityOf turns the admin-group
	// ones into the rules SPF prunes with and refuses the rest; render them
	// for an operator with flexAlgoConstraintSummaries.
	Constraints []packet.FlexAlgoSubSubTLV
}

// FlexAlgoInfo summarizes one Flexible Algorithm at a level: its elected
// definition (nil if no node advertises one) and the participating nodes.
type FlexAlgoInfo struct {
	Algo  uint8
	Level packet.Level
	// Definition is the elected FAD, or nil if none is advertised in the area
	// (per RFC 9350 a node must not compute the algo without a definition).
	Definition *FlexAlgoDefinition
	// Participants are the System IDs that advertise this algorithm in their
	// SR-Algorithm sub-TLV, sorted ascending.
	Participants []packet.SystemID
}

// flexAlgoState computes, for one level, the elected definition and the
// participant set of every Flexible Algorithm referenced in the LSDB (by a FAD
// or an SR-Algorithm sub-TLV). The election follows RFC 9350 §5.1: the FAD with
// the highest priority wins, ties broken by the highest advertising System ID.
func (s *IsisServer) flexAlgoState(level packet.Level, now time.Time) map[uint8]*FlexAlgoInfo {
	db := s.dbs[level]
	if db == nil {
		return nil
	}
	out := map[uint8]*FlexAlgoInfo{}
	info := func(algo uint8) *FlexAlgoInfo {
		fi := out[algo]
		if fi == nil {
			fi = &FlexAlgoInfo{Algo: algo, Level: level}
			out[algo] = fi
		}
		return fi
	}
	for id, e := range db.entries {
		if !e.purgedAt.IsZero() || e.remaining(now) == 0 || id.FragmentID() != 0 {
			continue
		}
		sys := id.NodeID().SystemID()
		// A node may carry several Router Capability TLVs / SR-Algorithm
		// sub-TLVs (RFC 7981). Count it once per algorithm, and per RFC 9350
		// §5.1 take only its first FAD for a given algorithm as that node's
		// election candidate.
		countedPart := map[uint8]bool{}
		contributedFAD := map[uint8]bool{}
		for _, tlv := range e.lsp.TLVs {
			rc, ok := tlv.(*packet.RouterCapabilityTLV)
			if !ok {
				continue
			}
			for _, sub := range rc.SubTLVs {
				switch st := sub.(type) {
				case *packet.SRAlgorithmSubTLV:
					for _, a := range st.Algorithms {
						if a == 0 || countedPart[a] {
							continue // algorithm 0 is not a Flex-Algo; dedup per node
						}
						countedPart[a] = true
						info(a).Participants = append(info(a).Participants, sys)
					}
				case *packet.FlexAlgoDefinitionSubTLV:
					if contributedFAD[st.FlexAlgo] {
						continue // a node advertises one FAD per algorithm; use the first
					}
					contributedFAD[st.FlexAlgo] = true
					// RFC 9350 §6.1-6.5: a constraint repeated inside one FAD
					// sub-TLV makes that sub-TLV one the receiver MUST ignore.
					// Ignoring it is dropping it from the election, not
					// refusing the algorithm: the next valid definition wins,
					// and no node can take an algorithm down on every goisis
					// in the area with a priority-255 advertisement.
					if repeatedConstraint(st.SubSubTLVs) {
						continue
					}
					fi := info(st.FlexAlgo)
					cand := &FlexAlgoDefinition{
						Algo:        st.FlexAlgo,
						MetricType:  st.MetricType,
						CalcType:    st.CalcType,
						Priority:    st.Priority,
						Advertiser:  sys,
						Constraints: st.SubSubTLVs,
					}
					if winsElection(cand, fi.Definition) {
						fi.Definition = cand
					}
				}
			}
		}
	}
	for _, fi := range out {
		sort.Slice(fi.Participants, func(i, j int) bool {
			return bytes.Compare(fi.Participants[i][:], fi.Participants[j][:]) < 0
		})
	}
	return out
}

// repeatedConstraint reports whether one FAD sub-TLV carries the same
// constraint sub-sub-TLV twice, which RFC 9350 §6.1-6.5 make the whole sub-TLV
// ignorable for. The rule is per sub-TLV: §6.5 lets an exclude-SRLG repeat
// across the set of FAD sub-TLVs from one IS, not inside one of them.
func repeatedConstraint(cons []packet.FlexAlgoSubSubTLV) bool {
	seen := map[uint8]bool{}
	for _, ss := range cons {
		if seen[ss.SubSubTLVType] {
			return true
		}
		seen[ss.SubSubTLVType] = true
	}
	return false
}

// winsElection reports whether candidate beats the current best FAD: higher
// priority wins; on a tie the higher advertising System ID wins (RFC 9350).
func winsElection(cand, best *FlexAlgoDefinition) bool {
	if best == nil {
		return true
	}
	if cand.Priority != best.Priority {
		return cand.Priority > best.Priority
	}
	return bytes.Compare(cand.Advertiser[:], best.Advertiser[:]) > 0
}

// ListFlexAlgos returns the Flexible Algorithm state across all levels: each
// algorithm's elected definition and participant set.
func (s *IsisServer) ListFlexAlgos(ctx context.Context) ([]FlexAlgoInfo, error) {
	var out []FlexAlgoInfo
	err := s.mgmtOperation(ctx, func() error {
		now := s.clock.Now()
		for _, level := range s.levelCap.levels() {
			for _, fi := range s.flexAlgoState(level, now) {
				out = append(out, *fi)
			}
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Level != out[j].Level {
			return out[i].Level < out[j].Level
		}
		return out[i].Algo < out[j].Algo
	})
	return out, err
}

// flexAlgoAffinity is the admin-group half of a Flexible Algorithm
// Definition's constraints: steps 1, 3 and 4 of the link pruning order in RFC
// 9350 §13, parsed once per computation. The zero value constrains nothing,
// which is what algorithm 0 computes with.
type flexAlgoAffinity struct {
	exclude    []uint32
	includeAny []uint32
	includeAll []uint32
}

// flexAlgoAffinityOf parses the elected definition's constraint sub-sub-TLVs
// into the affinity rules SPF prunes with. A constraint goisis cannot evaluate
// — an excluded SRLG, a sub-sub-TLV it does not know, an admin group whose
// length RFC 9350 §6 rules out — is an error, not a rule to leave out: a
// definition asking for a narrower topology than this node can compute must
// not be computed at all. updateRIB refuses the algorithm on it, the way it
// already refuses a metric-type it cannot measure, and withdraws this node's
// participation along with it (RFC 9350 §5.3).
//
// A constraint advertised twice is not refused here: RFC 9350 §6 has the
// receiver ignore such a definition rather than fail on it, so flexAlgoState
// drops it before the election and nothing ignorable reaches this function.
func flexAlgoAffinityOf(def *FlexAlgoDefinition) (flexAlgoAffinity, error) {
	var a flexAlgoAffinity
	for _, ss := range def.Constraints {
		var target *[]uint32
		switch ss.SubSubTLVType {
		case packet.FlexAlgoSubSubExcludeAdminGroup:
			target = &a.exclude
		case packet.FlexAlgoSubSubIncludeAnyAdminGroup:
			target = &a.includeAny
		case packet.FlexAlgoSubSubIncludeAllAdminGroup:
			target = &a.includeAll
		case packet.FlexAlgoSubSubDefinitionFlags:
			// RFC 9350 §6.4: a node MUST stop participating in an algorithm
			// whose definition sets a flag it does not support, and MUST check
			// every advertised bit rather than the subset it knows. The M-flag
			// is the one bit goisis can honor, and vacuously: it governs the
			// inter-area prefix metric, and §6.4 puts SRv6 locators — the only
			// prefixes a Flex-Algo computes here — outside its reach.
			if err := flexAlgoFlagsSupported(ss.Value); err != nil {
				return flexAlgoAffinity{}, err
			}
			continue
		default:
			// Includes exclude-SRLG (§6.5): the SRLG advertisements are
			// node-level TLVs goisis does not originate or read.
			return flexAlgoAffinity{}, fmt.Errorf("sub-sub-TLV %d is not evaluated", ss.SubSubTLVType)
		}
		words, ok := flexAlgoWords(ss.Value)
		if !ok {
			return flexAlgoAffinity{}, fmt.Errorf("sub-sub-TLV %d: %d octets is not a whole number of admin-group words", ss.SubSubTLVType, len(ss.Value))
		}
		*target = words
	}
	return a, nil
}

// flexAlgoFlagsSupported reports an error for any bit set in the definition
// flags (RFC 9350 §6.4) other than the M-flag.
func flexAlgoFlagsSupported(v []byte) error {
	for i, b := range v {
		if i == 0 {
			b &^= packet.FlexAlgoFlagM
		}
		if b != 0 {
			return fmt.Errorf("definition flags octet %d: unsupported bits 0x%02x", i, b)
		}
	}
	return nil
}

// empty reports whether there is nothing to prune on.
func (a flexAlgoAffinity) empty() bool {
	return len(a.exclude) == 0 && len(a.includeAny) == 0 && len(a.includeAll) == 0
}

// prunesLink applies RFC 9350 §13 steps 1, 3 and 4 to one IS-reachability
// entry's sub-TLVs, in that order, and also reports whether the entry carries
// colors of its own. It is not the whole rule: an entry with no colors is
// pruned a second way, when another entry advertising the same neighbor is
// pruned here — see buildTopology.
//
// The colors are read lazily so algorithm 0, whose affinity is empty, does not
// walk the sub-TLVs of every edge in the area; colored is therefore false on
// every algorithm-0 edge, where nothing reads it.
func (a flexAlgoAffinity) prunesLink(subs []packet.SubTLV) (prune, colored bool) {
	if a.empty() {
		return false, false
	}
	color := flexAlgoLinkColors(subs)
	colored = len(color) > 0
	switch {
	case anyColorSet(a.exclude, color): // 1. exclude admin group
		return true, colored
	case len(a.includeAny) > 0 && !anyColorSet(a.includeAny, color): // 3. include-any
		return true, colored
	case len(a.includeAll) > 0 && !allColorsSet(a.includeAll, color): // 4. include-all
		return true, colored
	}
	return false, colored
}

// anyColorSet reports whether the link has any color the rule names. A word
// the link does not advertise is all zeros (RFC 7308 sends the minimum length).
func anyColorSet(rule, color []uint32) bool {
	for i, w := range rule {
		if i < len(color) && w&color[i] != 0 {
			return true
		}
	}
	return false
}

// allColorsSet reports whether the link has every color the rule names, under
// the same convention anyColorSet reads: a word the link does not advertise is
// all zeros. A rule word naming no color therefore asks for nothing and is met
// by every link — RFC 9350 §13 step 4 tests the colors of the rule, and RFC
// 7308's minimum length is a SHOULD, so an advertiser may pad its rule past
// its significant words without taking every shorter-colored link out.
func allColorsSet(rule, color []uint32) bool {
	for i, w := range rule {
		var have uint32
		if i < len(color) {
			have = color[i]
		}
		if w&have != w {
			return false
		}
	}
	return true
}

// flexAlgoLinkColors returns the admin group of one IS-reachability entry as
// the Flexible Algorithm application must read it. RFC 9350 §12 makes ASLA
// (RFC 8919 §4.2) the only source: the ASLAs naming the Flex-Algo application
// win, a zero-length bit mask applies to any application that has no
// advertisement of its own, and the legacy sub-TLVs of the neighbor TLV are
// read only when the L-flag sends us there. A link with no ASLA at all
// therefore has no colors — which an exclude rule leaves alone and an include
// rule prunes, and is why goisis has to advertise its own (see
// circuit.aslaSubTLVs).
//
// RFC 8919 §4.2 lets a link carry several ASLAs for the same application and
// only asks that they not conflict, so the attributes of all of them are read
// rather than the first one's: a sender free to split its attributes across
// ASLAs must not get a different answer per sub-TLV order. Two admin groups
// that do conflict are unioned rather than resolved by §4.2's "first
// advertisement in the lowest-numbered LSP", which this function cannot see —
// the union is the reading adminGroupColors already gives a link, and it is
// the safe one under an exclude rule.
//
// One L-flag set anywhere in that set sets it for the whole application: §4.2
// requires the flag to be consistent across a link's sub-TLVs and says it MUST
// be considered set where it is not. The same clause has the ASLA's own
// sub-sub-TLVs ignored once it is set, which reading only the entry's
// top-level sub-TLVs does.
func flexAlgoLinkColors(subs []packet.SubTLV) []uint32 {
	var forFlexAlgo, forAnyApp []*packet.ASLASubTLV
	for _, sub := range subs {
		asla, ok := sub.(*packet.ASLASubTLV)
		if !ok {
			continue
		}
		switch {
		case asla.Apps(packet.ASLAAppFlexAlgo):
			forFlexAlgo = append(forFlexAlgo, asla)
		case asla.AnyApp():
			forAnyApp = append(forAnyApp, asla)
		}
	}
	if len(forFlexAlgo) == 0 {
		forFlexAlgo = forAnyApp
	}
	var attrs []packet.SubTLV
	for _, asla := range forFlexAlgo {
		if asla.Legacy {
			return adminGroupColors(subs)
		}
		attrs = append(attrs, asla.SubSubTLVs...)
	}
	return adminGroupColors(attrs)
}

// adminGroupColors folds the admin-group advertisements of one sub-TLV list
// into a single mask. RFC 9350 §12 requires both the RFC 5305 and the RFC 7308
// encodings to be accepted, and the union is the reading under which a peer
// that sends both — the migration shape of RFC 8919 §6.3.3 — is understood as
// it meant to be.
func adminGroupColors(subs []packet.SubTLV) []uint32 {
	var out []uint32
	for _, sub := range subs {
		g, ok := sub.(*packet.AdminGroupSubTLV)
		if !ok {
			continue
		}
		for len(out) < len(g.Groups) {
			out = append(out, 0)
		}
		for i, w := range g.Groups {
			out[i] |= w
		}
	}
	return out
}
