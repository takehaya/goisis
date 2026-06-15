package server

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	goisisv1alpha1 "github.com/takehaya/goisis/gen/goisis/v1alpha1"
	"github.com/takehaya/goisis/gen/goisis/v1alpha1/goisisv1alpha1connect"
	"github.com/takehaya/goisis/pkg/packet"
)

// connectHandler adapts IsisServer to goisis.v1alpha1.IsisService. It only
// converts types; logic lives on IsisServer so library consumers and RPC
// clients share one implementation.
type connectHandler struct {
	goisisv1alpha1connect.UnimplementedIsisServiceHandler
	s *IsisServer
}

// NewConnectHandler returns the HTTP mount path and handler exposing s over
// Connect RPC (which also serves the gRPC and gRPC-Web protocols).
func NewConnectHandler(s *IsisServer, opts ...connect.HandlerOption) (string, http.Handler) {
	return goisisv1alpha1connect.NewIsisServiceHandler(&connectHandler{s: s}, opts...)
}

func (h *connectHandler) GetIsis(
	ctx context.Context,
	_ *connect.Request[goisisv1alpha1.GetIsisRequest],
) (*connect.Response[goisisv1alpha1.GetIsisResponse], error) {
	g, err := h.s.GetGlobal(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&goisisv1alpha1.GetIsisResponse{
		Global: &goisisv1alpha1.Global{Version: g.Version, SystemId: g.SystemID.String()},
	}), nil
}

func (h *connectHandler) ListCircuits(
	ctx context.Context,
	_ *connect.Request[goisisv1alpha1.ListCircuitsRequest],
) (*connect.Response[goisisv1alpha1.ListCircuitsResponse], error) {
	cs, err := h.s.ListCircuits(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*goisisv1alpha1.Circuit, 0, len(cs))
	for _, c := range cs {
		out = append(out, &goisisv1alpha1.Circuit{
			Interface:    c.Interface,
			PointToPoint: c.P2P,
			Level1:       c.Level1,
			Level2:       c.Level2,
			Priority:     uint32(c.Priority),
			Metric:       c.Metric,
		})
	}
	return connect.NewResponse(&goisisv1alpha1.ListCircuitsResponse{Circuits: out}), nil
}

func (h *connectHandler) ListAdjacencies(
	ctx context.Context,
	_ *connect.Request[goisisv1alpha1.ListAdjacenciesRequest],
) (*connect.Response[goisisv1alpha1.ListAdjacenciesResponse], error) {
	adjs, err := h.s.ListAdjacencies(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*goisisv1alpha1.Adjacency, 0, len(adjs))
	for _, a := range adjs {
		out = append(out, adjacencyToProto(a))
	}
	return connect.NewResponse(&goisisv1alpha1.ListAdjacenciesResponse{Adjacencies: out}), nil
}

func (h *connectHandler) GetLsdb(
	ctx context.Context,
	_ *connect.Request[goisisv1alpha1.GetLsdbRequest],
) (*connect.Response[goisisv1alpha1.GetLsdbResponse], error) {
	lsps, err := h.s.ListLSDB(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*goisisv1alpha1.Lsp, 0, len(lsps))
	for _, l := range lsps {
		out = append(out, &goisisv1alpha1.Lsp{
			Level:             levelToProto(l.Level),
			LspId:             l.LSPID.String(),
			SequenceNumber:    l.SequenceNumber,
			RemainingLifetime: uint32(l.Remaining),
			Checksum:          uint32(l.Checksum),
			Own:               l.Own,
		})
	}
	return connect.NewResponse(&goisisv1alpha1.GetLsdbResponse{Lsps: out}), nil
}

func (h *connectHandler) ListRoutes(
	ctx context.Context,
	_ *connect.Request[goisisv1alpha1.ListRoutesRequest],
) (*connect.Response[goisisv1alpha1.ListRoutesResponse], error) {
	routes, err := h.s.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*goisisv1alpha1.Route, 0, len(routes))
	for _, r := range routes {
		out = append(out, routeToProto(r))
	}
	return connect.NewResponse(&goisisv1alpha1.ListRoutesResponse{Routes: out}), nil
}

func (h *connectHandler) WatchEvent(
	ctx context.Context,
	_ *connect.Request[goisisv1alpha1.WatchEventRequest],
	stream *connect.ServerStream[goisisv1alpha1.WatchEventResponse],
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

func eventToProto(ev Event) *goisisv1alpha1.WatchEventResponse {
	switch {
	case ev.Adjacency != nil:
		return &goisisv1alpha1.WatchEventResponse{
			Event: &goisisv1alpha1.WatchEventResponse_Adjacency{
				Adjacency: &goisisv1alpha1.AdjacencyEvent{Adjacency: adjacencyToProto(*ev.Adjacency)},
			},
		}
	case ev.Route != nil:
		return &goisisv1alpha1.WatchEventResponse{
			Event: &goisisv1alpha1.WatchEventResponse_Route{
				Route: &goisisv1alpha1.RouteEvent{Route: routeToProto(*ev.Route), Withdrawn: ev.Withdrawn},
			},
		}
	default:
		return &goisisv1alpha1.WatchEventResponse{}
	}
}

func adjacencyToProto(a AdjacencyInfo) *goisisv1alpha1.Adjacency {
	return &goisisv1alpha1.Adjacency{
		Interface:   a.Interface,
		Level:       levelToProto(a.Level),
		SystemId:    a.SystemID.String(),
		Snpa:        a.SNPA.String(),
		State:       a.State.String(),
		Priority:    uint32(a.Priority),
		HoldingTime: uint32(a.Holding),
	}
}

func routeToProto(r RouteInfo) *goisisv1alpha1.Route {
	nhs := make([]*goisisv1alpha1.NextHop, 0, len(r.NextHops))
	for _, nh := range r.NextHops {
		nhs = append(nhs, &goisisv1alpha1.NextHop{Interface: nh.Interface, Gateway: nh.Gateway.String()})
	}
	return &goisisv1alpha1.Route{
		Prefix:   r.Prefix.String(),
		Metric:   r.Metric,
		Level:    levelToProto(r.Level),
		NextHops: nhs,
	}
}

func levelToProto(l packet.Level) goisisv1alpha1.Level {
	switch l {
	case packet.Level1:
		return goisisv1alpha1.Level_LEVEL_1
	case packet.Level2:
		return goisisv1alpha1.Level_LEVEL_2
	default:
		return goisisv1alpha1.Level_LEVEL_UNSPECIFIED
	}
}
