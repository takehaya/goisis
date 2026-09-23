package server

// edgeLog logs the edge of a condition that persists instead of every
// occurrence of it: warn runs fn the first time it is called for a key and
// stays quiet until clear re-arms that key. Conditions here are driven by
// received PDUs or by retransmission timers, so logging each occurrence would
// turn one misconfiguration into log amplification on the management loop.
//
// The key is whatever tells one instance of the condition from another at that
// site — a level, a circuit, a (circuit, LSP ID) pair. A single flag per site
// is what hid the undeliverable LSP in transmitSRM: the first oversize LSP
// silenced every later, different one for the life of the process.
//
// The zero value is ready to use. It carries no lock: every use but readLoop's
// is on the Serve goroutine, and readLoop keeps its own on the stack.
type edgeLog[K comparable] struct {
	fired map[K]bool
}

// warn runs fn unless this key has already fired and has not been cleared since.
func (e *edgeLog[K]) warn(key K, fn func()) {
	if e.fired[key] {
		return
	}
	if e.fired == nil {
		e.fired = map[K]bool{}
	}
	e.fired[key] = true
	fn()
}

// clear re-arms a key: the condition went away, so its return is worth logging.
func (e *edgeLog[K]) clear(key K) { delete(e.fired, key) }
