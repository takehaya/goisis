package server

import (
	"context"
	"net/http"

	"connectrpc.com/connect"

	goisisv1alpha1 "github.com/takehaya/goisis/gen/goisis/v1alpha1"
	"github.com/takehaya/goisis/gen/goisis/v1alpha1/goisisv1alpha1connect"
)

// connectHandler adapts IsisServer to goisis.v1alpha1.IsisService. It only
// converts types; logic lives on IsisServer so library consumers and RPC
// clients share one implementation.
type connectHandler struct {
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
		Global: &goisisv1alpha1.Global{Version: g.Version},
	}), nil
}
