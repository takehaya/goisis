package interop

import (
	"context"
	"testing"

	"github.com/takehaya/goisis/pkg/packet"
	"github.com/takehaya/goisis/pkg/server"
)

// TestFlexAlgoDefinitionInterop verifies Flex-Algo definition exchange with FRR
// (RFC 9350): FRR advertises a FAD for algo 128 at a higher priority, goisis
// participates and advertises its own at a lower priority. goisis must decode
// FRR's real FAD bytes, see FRR as a participant, and elect FRR's definition;
// FRR must accept and store goisis's LSP (its SR-Algorithm + FAD).
//
// FRR's Flex-Algo is SR-MPLS-oriented, so this validates definition exchange
// only; the SRv6 x Flex-Algo data plane is covered by the in-process 3-node
// self-interop test in pkg/server.
func TestFlexAlgoDefinitionInterop(t *testing.T) {
	requireInterop(t)

	// FRR advertises the FAD for algo 128 at priority 200 (it should win the
	// election over goisis's priority-100 advertisement).
	node := startFRR(t, true, " flex-algo 128\n  advertise-definition\n  priority 200\n exit")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startGoisis(t, ctx, node.hostVeth, true,
		server.WithFlexAlgo(server.FlexAlgoConfig{
			Algo: 128, MetricType: packet.FlexAlgoMetricIGP, Priority: 100, AdvertiseDefinition: true,
		}),
	)

	waitUp(t, "goisis<->FRR adjacency up", func() bool {
		return goisisSeesUp(t, s, frrSysID) && node.neighborUp(t, "goisis")
	})

	// FRR must accept goisis's LSP (carrying its Router Capability TLV with the
	// SR-Algorithm + FAD sub-TLVs) into its database.
	waitUp(t, "FRR has goisis's LSP", func() bool { return node.databaseContains(t, "goisis") })

	// goisis must decode FRR's FAD, list FRR as a participant, and elect FRR's
	// higher-priority definition.
	waitUp(t, "goisis elects FRR's FAD for algo 128", func() bool {
		infos, err := s.ListFlexAlgos(context.Background())
		if err != nil {
			return false
		}
		for _, fi := range infos {
			if fi.Algo != 128 || fi.Definition == nil {
				continue
			}
			frrParticipates := false
			for _, p := range fi.Participants {
				if p == frrSysID {
					frrParticipates = true
				}
			}
			return frrParticipates &&
				fi.Definition.Advertiser == frrSysID &&
				fi.Definition.Priority == 200
		}
		return false
	})
}
