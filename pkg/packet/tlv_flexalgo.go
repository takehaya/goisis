package packet

import "fmt"

// Flex-Algorithm sub-TLV code points (carried in the Router Capability TLV,
// 242). RFC 8667 defines SR-Algorithm; RFC 9350 defines the FAD.
const (
	subTLVSRAlgorithm = 19 // SR-Algorithm: the algorithms this node supports
	subTLVFlexAlgoDef = 26 // Flexible Algorithm Definition
)

// Flex-Algorithm metric-types (RFC 9350). goisis computes only the IGP metric
// initially; the others are carried so the definition round-trips and the
// winner election matches peers.
const (
	FlexAlgoMetricIGP      uint8 = 0 // default IGP metric
	FlexAlgoMetricMinDelay uint8 = 1 // min unidirectional link delay
	FlexAlgoMetricTE       uint8 = 2 // TE default metric
)

// SRAlgorithmSubTLV (type 19) lists the algorithms a node participates in. It
// is a sub-TLV of the Router Capability TLV (242). Algorithm 0 is plain SPF;
// 128-255 are Flexible Algorithms.
type SRAlgorithmSubTLV struct {
	Algorithms []uint8
}

// Type implements SubTLV.
func (s *SRAlgorithmSubTLV) Type() uint8 { return subTLVSRAlgorithm }

// Serialize implements SubTLV.
func (s *SRAlgorithmSubTLV) Serialize() ([]byte, error) {
	if len(s.Algorithms) > 255 {
		return nil, fmt.Errorf("SR-Algorithm: %w: %d algorithms", ErrTooLong, len(s.Algorithms))
	}
	out := make([]byte, 0, 2+len(s.Algorithms))
	out = append(out, subTLVSRAlgorithm, byte(len(s.Algorithms)))
	return append(out, s.Algorithms...), nil
}

func decodeSRAlgorithm(value []byte) (SubTLV, error) {
	s := &SRAlgorithmSubTLV{}
	if len(value) > 0 {
		s.Algorithms = append([]uint8(nil), value...)
	}
	return s, nil
}

// FlexAlgoSubSubTLV is a sub-sub-TLV of the FAD (admin-group constraints, the
// definition flags, exclude-SRLG). goisis preserves these opaquely: the
// initial computation is IGP-metric-only, but byte-exact round-tripping keeps
// the constraints intact so they reach peers and a later ASLA-aware computation
// can honor them without a wire change.
type FlexAlgoSubSubTLV struct {
	SubSubTLVType uint8
	Value         []byte
}

// flexAlgoDefFixedLen is the fixed FAD prefix: flex-algo, metric-type,
// calc-type, priority. The constraint sub-sub-TLVs (RFC 9350: exclude/include
// admin groups, definition flags, exclude-SRLG) follow and are preserved
// opaquely until the ASLA-aware computation lands.
const flexAlgoDefFixedLen = 4

// FlexAlgoDefinitionSubTLV (type 26) is a Flexible Algorithm Definition: the
// algorithm number, how cost is measured (metric-type), how paths are computed
// (calc-type), the advertiser's priority for the winner election, and optional
// constraint sub-sub-TLVs.
type FlexAlgoDefinitionSubTLV struct {
	FlexAlgo   uint8
	MetricType uint8
	CalcType   uint8
	Priority   uint8
	SubSubTLVs []FlexAlgoSubSubTLV
}

// Type implements SubTLV.
func (f *FlexAlgoDefinitionSubTLV) Type() uint8 { return subTLVFlexAlgoDef }

// Serialize implements SubTLV.
func (f *FlexAlgoDefinitionSubTLV) Serialize() ([]byte, error) {
	value := []byte{f.FlexAlgo, f.MetricType, f.CalcType, f.Priority}
	for _, ss := range f.SubSubTLVs {
		if len(ss.Value) > 255 {
			return nil, fmt.Errorf("FAD sub-sub-TLV %d: %w: %d octets", ss.SubSubTLVType, ErrTooLong, len(ss.Value))
		}
		value = append(value, ss.SubSubTLVType, byte(len(ss.Value)))
		value = append(value, ss.Value...)
	}
	if len(value) > 255 {
		return nil, fmt.Errorf("flex-algo definition: %w: %d octets", ErrTooLong, len(value))
	}
	out := make([]byte, 0, 2+len(value))
	out = append(out, subTLVFlexAlgoDef, byte(len(value)))
	return append(out, value...), nil
}

func decodeFlexAlgoDefinition(value []byte) (SubTLV, error) {
	if len(value) < flexAlgoDefFixedLen {
		return nil, fmt.Errorf("flex-algo definition: %w", ErrTruncated)
	}
	f := &FlexAlgoDefinitionSubTLV{
		FlexAlgo:   value[0],
		MetricType: value[1],
		CalcType:   value[2],
		Priority:   value[3],
	}
	rest := value[flexAlgoDefFixedLen:]
	for len(rest) > 0 {
		if len(rest) < 2 {
			return nil, fmt.Errorf("flex-algo sub-sub-TLV header: %w", ErrTruncated)
		}
		t, l := rest[0], int(rest[1])
		if len(rest) < 2+l {
			return nil, fmt.Errorf("flex-algo sub-sub-TLV %d: %w", t, ErrTruncated)
		}
		ss := FlexAlgoSubSubTLV{SubSubTLVType: t}
		if l > 0 {
			ss.Value = append([]byte(nil), rest[2:2+l]...)
		}
		f.SubSubTLVs = append(f.SubSubTLVs, ss)
		rest = rest[2+l:]
	}
	return f, nil
}

func init() {
	registerSubTLVDecoder(SubTLVContextRouterCapability, subTLVSRAlgorithm, decodeSRAlgorithm)
	registerSubTLVDecoder(SubTLVContextRouterCapability, subTLVFlexAlgoDef, decodeFlexAlgoDefinition)
}
