package server

import "github.com/takehaya/goisis/pkg/datalink"

// event is an internal occurrence delivered to the Serve loop. Implementing
// types are processed serially by handleEvent, so they may mutate protocol
// state directly. Every event names the circuit it came from, which is what
// lets handleEvent refuse one for a circuit that has since been deleted.
type event interface{ on() *circuit }

// rxEvent carries a frame received on a circuit.
type rxEvent struct {
	circuit *circuit
	frame   datalink.Frame
}

func (e *rxEvent) on() *circuit { return e.circuit }

// rxErrEvent carries a circuit's failed receive to the Serve loop. The reader
// goroutine does not report it itself: Metrics is documented as being called
// only from that loop, so an implementation is entitled to be unsynchronized
// on the write side.
type rxErrEvent struct {
	circuit *circuit
}

func (e *rxErrEvent) on() *circuit { return e.circuit }
