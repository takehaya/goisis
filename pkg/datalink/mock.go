package datalink

import (
	"sync"

	"github.com/takehaya/goisis/pkg/packet"
)

// MockTransport is an in-memory Transport for tests. Two MockTransports can
// be wired together with Link so a sent PDU is delivered to the peer's
// Recv, modelling a point-to-point or two-node broadcast segment without
// any privileges.
type MockTransport struct {
	snpa packet.SNPA
	mtu  int

	mu     sync.Mutex
	peers  []*MockTransport
	inbox  chan Frame
	closed bool
}

// NewMockTransport returns a MockTransport with the given MAC and MTU.
func NewMockTransport(snpa packet.SNPA, mtu int) *MockTransport {
	return &MockTransport{
		snpa:  snpa,
		mtu:   mtu,
		inbox: make(chan Frame, 256),
	}
}

// Link connects transports onto a shared segment: each subsequently
// delivers PDUs sent by any other to its own Recv. Call once with all
// members of the segment.
func Link(ts ...*MockTransport) {
	for _, t := range ts {
		t.mu.Lock()
		for _, other := range ts {
			if other != t {
				t.peers = append(t.peers, other)
			}
		}
		t.mu.Unlock()
	}
}

// Send implements Transport. The PDU is delivered to every linked peer
// whose inbox has room (a full inbox drops, modelling loss under overload).
func (m *MockTransport) Send(_ packet.SNPA, pdu []byte) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	peers := append([]*MockTransport(nil), m.peers...)
	m.mu.Unlock()

	cp := append([]byte(nil), pdu...)
	for _, p := range peers {
		p.deliver(Frame{PDU: cp, Src: m.snpa})
	}
	return nil
}

func (m *MockTransport) deliver(f Frame) {
	// The send stays inside the critical section: Close also holds m.mu, so
	// the channel cannot be closed between the closed-check and the send.
	// The send is non-blocking, so holding the lock across it cannot
	// deadlock.
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	select {
	case m.inbox <- f:
	default: // drop on overload
	}
}

// Recv implements Transport.
func (m *MockTransport) Recv() (Frame, error) {
	f, ok := <-m.inbox
	if !ok {
		return Frame{}, ErrClosed
	}
	return f, nil
}

// LocalSNPA implements Transport.
func (m *MockTransport) LocalSNPA() packet.SNPA { return m.snpa }

// MTU implements Transport.
func (m *MockTransport) MTU() int { return m.mtu }

// Close implements Transport.
func (m *MockTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.inbox)
	}
	return nil
}
