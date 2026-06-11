package server

import "github.com/takehaya/goisis/pkg/datalink"

// event is an internal occurrence delivered to the Serve loop. Implementing
// types are processed serially by handleEvent, so they may mutate protocol
// state directly.
type event interface{ isEvent() }

// rxEvent carries a frame received on a circuit.
type rxEvent struct {
	circuit *circuit
	frame   datalink.Frame
}

func (*rxEvent) isEvent() {}
