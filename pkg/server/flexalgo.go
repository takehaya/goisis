package server

import (
	"bytes"
	"context"
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
					fi := info(st.FlexAlgo)
					cand := &FlexAlgoDefinition{
						Algo:       st.FlexAlgo,
						MetricType: st.MetricType,
						CalcType:   st.CalcType,
						Priority:   st.Priority,
						Advertiser: sys,
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
		now := time.Now()
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
