// Package datalink carries IS-IS PDUs over a circuit's link layer.
//
// IS-IS is not transported over IP: on Ethernet its PDUs ride in 802.3
// frames with an LLC header (DSAP=SSAP=0xFE, control 0x03) to well-known
// multicast MACs, and on point-to-point circuits in frames with EtherType
// 0x00FE and no LLC. Transport hides this framing so the rest of goisis
// deals only in PDU bytes, and a mock Transport lets the adjacency and
// flooding logic be tested without privileges.
package datalink

import (
	"errors"

	"github.com/takehaya/goisis/pkg/packet"
)

// Well-known IS-IS multicast destination MACs (ISO 10589 8.4.8).
var (
	AllL1ISs = packet.SNPA{0x01, 0x80, 0xc2, 0x00, 0x00, 0x14}
	AllL2ISs = packet.SNPA{0x01, 0x80, 0xc2, 0x00, 0x00, 0x15}
	AllISs   = packet.SNPA{0x09, 0x00, 0x2b, 0x00, 0x00, 0x05}
)

// LLC header bytes prefixed to IS-IS PDUs on 802.3 (broadcast) circuits.
var llcHeader = [3]byte{0xfe, 0xfe, 0x03}

// ErrClosed is returned by Recv after the Transport has been closed.
var ErrClosed = errors.New("datalink: transport closed")

// Frame is a received IS-IS PDU together with its source MAC.
type Frame struct {
	PDU []byte
	Src packet.SNPA
}

// Transport sends and receives IS-IS PDUs on one circuit.
type Transport interface {
	// Send transmits an IS-IS PDU. For broadcast circuits dst selects the
	// destination multicast group (AllL1ISs/AllL2ISs); p2p transports
	// ignore dst.
	Send(dst packet.SNPA, pdu []byte) error

	// Recv returns the next IS-IS PDU. It blocks until a PDU arrives or the
	// transport is closed (ErrClosed).
	Recv() (Frame, error)

	// LocalSNPA returns the circuit's own MAC.
	LocalSNPA() packet.SNPA

	// MTU returns the interface MTU in octets (the maximum 802.3 payload).
	MTU() int

	// Close releases the transport and unblocks any pending Recv.
	Close() error
}

// DestForLevel returns the all-IS multicast MAC for a level on a broadcast
// circuit.
func DestForLevel(level packet.Level) packet.SNPA {
	if level == packet.Level2 {
		return AllL2ISs
	}
	return AllL1ISs
}
