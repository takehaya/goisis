package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"connectrpc.com/connect"

	goisisv1 "github.com/takehaya/goisis/gen/goisis/v1"
	"github.com/takehaya/goisis/gen/goisis/v1/goisisv1connect"
	"github.com/takehaya/goisis/pkg/packet"
)

// connectHandler adapts IsisServer to goisis.v1.IsisService. It only
// converts types; logic lives on IsisServer so library consumers and RPC
// clients share one implementation.
type connectHandler struct {
	goisisv1connect.UnimplementedIsisServiceHandler
	s *IsisServer
}

// NewConnectHandler returns the HTTP mount path and handler exposing s over
// Connect RPC (which also serves the gRPC and gRPC-Web protocols).
func NewConnectHandler(s *IsisServer, opts ...connect.HandlerOption) (string, http.Handler) {
	return goisisv1connect.NewIsisServiceHandler(&connectHandler{s: s}, opts...)
}

func (h *connectHandler) GetIsis(
	ctx context.Context,
	_ *connect.Request[goisisv1.GetIsisRequest],
) (*connect.Response[goisisv1.GetIsisResponse], error) {
	g, err := h.s.GetGlobal(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&goisisv1.GetIsisResponse{
		Global: &goisisv1.Global{Version: g.Version, SystemId: g.SystemID.String()},
	}), nil
}

func (h *connectHandler) ListCircuits(
	ctx context.Context,
	_ *connect.Request[goisisv1.ListCircuitsRequest],
) (*connect.Response[goisisv1.ListCircuitsResponse], error) {
	cs, err := h.s.ListCircuits(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*goisisv1.Circuit, 0, len(cs))
	for _, c := range cs {
		out = append(out, &goisisv1.Circuit{
			Interface:    c.Interface,
			PointToPoint: c.P2P,
			Level1:       c.Level1,
			Level2:       c.Level2,
			Priority:     uint32(c.Priority),
			Metric:       c.Metric,
		})
	}
	return connect.NewResponse(&goisisv1.ListCircuitsResponse{Circuits: out}), nil
}

func (h *connectHandler) ListAdjacencies(
	ctx context.Context,
	_ *connect.Request[goisisv1.ListAdjacenciesRequest],
) (*connect.Response[goisisv1.ListAdjacenciesResponse], error) {
	adjs, err := h.s.ListAdjacencies(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*goisisv1.Adjacency, 0, len(adjs))
	for _, a := range adjs {
		out = append(out, adjacencyToProto(a))
	}
	return connect.NewResponse(&goisisv1.ListAdjacenciesResponse{Adjacencies: out}), nil
}

func (h *connectHandler) GetLsdb(
	ctx context.Context,
	_ *connect.Request[goisisv1.GetLsdbRequest],
) (*connect.Response[goisisv1.GetLsdbResponse], error) {
	lsps, err := h.s.ListLSDB(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*goisisv1.Lsp, 0, len(lsps))
	for _, l := range lsps {
		out = append(out, &goisisv1.Lsp{
			Level:             levelToProto(l.Level),
			LspId:             l.LSPID.String(),
			SequenceNumber:    l.SequenceNumber,
			RemainingLifetime: uint32(l.Remaining),
			Checksum:          uint32(l.Checksum),
			Own:               l.Own,
		})
	}
	return connect.NewResponse(&goisisv1.GetLsdbResponse{Lsps: out}), nil
}

func (h *connectHandler) ListRoutes(
	ctx context.Context,
	_ *connect.Request[goisisv1.ListRoutesRequest],
) (*connect.Response[goisisv1.ListRoutesResponse], error) {
	routes, err := h.s.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*goisisv1.Route, 0, len(routes))
	for _, r := range routes {
		out = append(out, routeToProto(r))
	}
	return connect.NewResponse(&goisisv1.ListRoutesResponse{Routes: out}), nil
}

func (h *connectHandler) ListLocators(
	ctx context.Context,
	_ *connect.Request[goisisv1.ListLocatorsRequest],
) (*connect.Response[goisisv1.ListLocatorsResponse], error) {
	locs, err := h.s.ListLocators(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*goisisv1.Locator, 0, len(locs))
	for _, l := range locs {
		out = append(out, &goisisv1.Locator{
			Prefix:    l.Prefix.String(),
			Algorithm: uint32(l.Algorithm),
			EndSid:    l.EndSID.String(),
		})
	}
	return connect.NewResponse(&goisisv1.ListLocatorsResponse{Locators: out}), nil
}

func (h *connectHandler) ListFlexAlgos(
	ctx context.Context,
	_ *connect.Request[goisisv1.ListFlexAlgosRequest],
) (*connect.Response[goisisv1.ListFlexAlgosResponse], error) {
	infos, err := h.s.ListFlexAlgos(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*goisisv1.FlexAlgo, 0, len(infos))
	for _, fi := range infos {
		fa := &goisisv1.FlexAlgo{
			Algorithm: uint32(fi.Algo),
			Level:     levelToProto(fi.Level),
		}
		if fi.Definition != nil {
			fa.Definition = &goisisv1.FlexAlgoDefinition{
				MetricType: uint32(fi.Definition.MetricType),
				CalcType:   uint32(fi.Definition.CalcType),
				Priority:   uint32(fi.Definition.Priority),
				Advertiser: fi.Definition.Advertiser.String(),
			}
		}
		for _, p := range fi.Participants {
			fa.Participants = append(fa.Participants, p.String())
		}
		out = append(out, fa)
	}
	return connect.NewResponse(&goisisv1.ListFlexAlgosResponse{FlexAlgos: out}), nil
}

func (h *connectHandler) AddLocator(
	ctx context.Context,
	req *connect.Request[goisisv1.AddLocatorRequest],
) (*connect.Response[goisisv1.AddLocatorResponse], error) {
	prefix, err := netip.ParsePrefix(req.Msg.GetPrefix())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	algo, err := locatorAlgo(req.Msg.GetAlgorithm())
	if err != nil {
		return nil, err
	}
	if err := h.s.AddLocator(ctx, SRv6LocatorConfig{Prefix: prefix, Algo: algo}); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&goisisv1.AddLocatorResponse{}), nil
}

func (h *connectHandler) DeleteLocator(
	ctx context.Context,
	req *connect.Request[goisisv1.DeleteLocatorRequest],
) (*connect.Response[goisisv1.DeleteLocatorResponse], error) {
	prefix, err := netip.ParsePrefix(req.Msg.GetPrefix())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := h.s.DeleteLocator(ctx, prefix); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&goisisv1.DeleteLocatorResponse{}), nil
}

func (h *connectHandler) AddFlexAlgo(
	ctx context.Context,
	req *connect.Request[goisisv1.AddFlexAlgoRequest],
) (*connect.Response[goisisv1.AddFlexAlgoResponse], error) {
	algo, err := flexAlgoNumber(req.Msg.GetAlgorithm())
	if err != nil {
		return nil, err
	}
	mt, err := uint8FromProto(req.Msg.GetMetricType(), "metric_type")
	if err != nil {
		return nil, err
	}
	prio, err := uint8FromProto(req.Msg.GetPriority(), "priority")
	if err != nil {
		return nil, err
	}
	cfg := FlexAlgoConfig{
		Algo:                algo,
		MetricType:          mt,
		Priority:            prio,
		AdvertiseDefinition: req.Msg.GetAdvertiseDefinition(),
	}
	if err := h.s.AddFlexAlgo(ctx, cfg); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&goisisv1.AddFlexAlgoResponse{}), nil
}

func (h *connectHandler) DeleteFlexAlgo(
	ctx context.Context,
	req *connect.Request[goisisv1.DeleteFlexAlgoRequest],
) (*connect.Response[goisisv1.DeleteFlexAlgoResponse], error) {
	algo, err := flexAlgoNumber(req.Msg.GetAlgorithm())
	if err != nil {
		return nil, err
	}
	if err := h.s.DeleteFlexAlgo(ctx, algo); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&goisisv1.DeleteFlexAlgoResponse{}), nil
}

// toConnectError maps an IsisServer error to a Connect error code. The
// lifecycle errors get their canonical codes; everything else the mutators
// return is a validation failure, hence InvalidArgument.
func toConnectError(err error) error {
	var ce *connect.Error
	switch {
	case errors.Is(err, ErrServerStopped):
		return connect.NewError(connect.CodeUnavailable, err)
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	case errors.As(err, &ce):
		return err // already coded (e.g. a validated proto field)
	default:
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
}

// flexAlgoNumber validates that a wire algorithm number fits the Flex-Algo
// range (128-255) and returns it as a uint8.
func flexAlgoNumber(v uint32) (uint8, error) {
	if v < 128 || v > 255 {
		return 0, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("algorithm %d out of Flex-Algo range (128-255)", v))
	}
	return uint8(v), nil
}

// locatorAlgo validates a locator's algorithm: 0 (normal SPF) or a Flexible
// Algorithm (128-255).
func locatorAlgo(v uint32) (uint8, error) {
	if v == 0 {
		return 0, nil
	}
	return flexAlgoNumber(v)
}

// uint8FromProto narrows a wire uint32 to uint8, rejecting overflow.
func uint8FromProto(v uint32, field string) (uint8, error) {
	if v > 255 {
		return 0, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("%s %d exceeds 255", field, v))
	}
	return uint8(v), nil
}

func (h *connectHandler) WatchEvent(
	ctx context.Context,
	_ *connect.Request[goisisv1.WatchEventRequest],
	stream *connect.ServerStream[goisisv1.WatchEventResponse],
) error {
	sub, err := h.s.Subscribe(ctx)
	if err != nil {
		return err
	}
	defer sub.Unsubscribe()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-sub.Events:
			if !ok {
				// A lagging drop is distinct from a clean server stop: report
				// it as retryable so the client knows to resubscribe.
				if sub.Lagged() {
					return connect.NewError(connect.CodeResourceExhausted,
						errors.New("watch subscriber fell behind; resubscribe"))
				}
				return nil
			}
			if err := stream.Send(eventToProto(ev)); err != nil {
				return err
			}
		}
	}
}

func eventToProto(ev Event) *goisisv1.WatchEventResponse {
	switch {
	case ev.Adjacency != nil:
		return &goisisv1.WatchEventResponse{
			Event: &goisisv1.WatchEventResponse_Adjacency{
				Adjacency: &goisisv1.AdjacencyEvent{Adjacency: adjacencyToProto(*ev.Adjacency)},
			},
		}
	case ev.Route != nil:
		return &goisisv1.WatchEventResponse{
			Event: &goisisv1.WatchEventResponse_Route{
				Route: &goisisv1.RouteEvent{Route: routeToProto(*ev.Route), Withdrawn: ev.Withdrawn},
			},
		}
	default:
		return &goisisv1.WatchEventResponse{}
	}
}

func adjacencyToProto(a AdjacencyInfo) *goisisv1.Adjacency {
	return &goisisv1.Adjacency{
		Interface:   a.Interface,
		Level:       levelToProto(a.Level),
		SystemId:    a.SystemID.String(),
		Snpa:        a.SNPA.String(),
		State:       a.State.String(),
		Priority:    uint32(a.Priority),
		HoldingTime: uint32(a.Holding),
	}
}

func routeToProto(r RouteInfo) *goisisv1.Route {
	nhs := make([]*goisisv1.NextHop, 0, len(r.NextHops))
	for _, nh := range r.NextHops {
		nhs = append(nhs, &goisisv1.NextHop{Interface: nh.Interface, Gateway: nh.Gateway.String()})
	}
	return &goisisv1.Route{
		Prefix:    r.Prefix.String(),
		Metric:    r.Metric,
		Level:     levelToProto(r.Level),
		NextHops:  nhs,
		Algorithm: uint32(r.Algorithm),
	}
}

func levelToProto(l packet.Level) goisisv1.Level {
	switch l {
	case packet.Level1:
		return goisisv1.Level_LEVEL_1
	case packet.Level2:
		return goisisv1.Level_LEVEL_2
	default:
		return goisisv1.Level_LEVEL_UNSPECIFIED
	}
}
