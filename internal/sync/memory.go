package sync

import (
	"context"
	"fmt"
	"sort"
	stdsync "sync"

	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/wire"
)

// Mesh is an in-process transport connecting several nodes with no network at all.
//
// Two-node and N-node tests run on this (plan §0.4). Running them in memory is not a
// shortcut: it removes timing, DNS, and socket behaviour from the picture, so a
// convergence test that fails has found a protocol bug rather than a flaky network.
// The tailnet transport gets its own integration test, build-tagged out of the default
// run.
//
// A Mesh is safe for concurrent use.
type Mesh struct {
	mu    stdsync.Mutex
	nodes map[record.NodeID]*MemoryTransport
	// partitions records node pairs that cannot reach each other, so a test can
	// split the mesh and heal it.
	partitions map[[2]record.NodeID]bool
	closed     bool
}

// NewMesh returns an empty mesh.
func NewMesh() *Mesh {
	return &Mesh{
		nodes:      make(map[record.NodeID]*MemoryTransport),
		partitions: make(map[[2]record.NodeID]bool),
	}
}

// Join adds a node and returns its transport.
func (m *Mesh) Join(id record.NodeID) *MemoryTransport {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := &MemoryTransport{mesh: m, id: id, inbound: make(chan Session, 64)}
	m.nodes[id] = t
	return t
}

// Leave removes a node. Leaving is free: no announcement, no handover, nothing to
// wait for (plan §5.4).
func (m *Mesh) Leave(id record.NodeID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nodes, id)
}

// Partition makes two nodes unable to reach each other.
func (m *Mesh) Partition(a, b record.NodeID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.partitions[pairKey(a, b)] = true
}

// Heal restores a partition.
func (m *Mesh) Heal(a, b record.NodeID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.partitions, pairKey(a, b))
}

// HealAll restores every partition.
func (m *Mesh) HealAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.partitions = make(map[[2]record.NodeID]bool)
}

func pairKey(a, b record.NodeID) [2]record.NodeID {
	if a < b {
		return [2]record.NodeID{a, b}
	}
	return [2]record.NodeID{b, a}
}

func (m *Mesh) partitioned(a, b record.NodeID) bool {
	return m.partitions[pairKey(a, b)]
}

// Close shuts every transport down.
func (m *Mesh) Close() error {
	m.mu.Lock()
	nodes := make([]*MemoryTransport, 0, len(m.nodes))
	for _, t := range m.nodes {
		nodes = append(nodes, t)
	}
	m.closed = true
	m.mu.Unlock()
	for _, t := range nodes {
		t.Close()
	}
	return nil
}

// MemoryTransport is one node's view of a Mesh.
type MemoryTransport struct {
	mesh *Mesh
	id   record.NodeID

	mu      stdsync.Mutex
	inbound chan Session
	closed  bool
}

// Dial implements Transport.
func (t *MemoryTransport) Dial(ctx context.Context, peer record.NodeID) (Session, error) {
	t.mesh.mu.Lock()
	remote, ok := t.mesh.nodes[peer]
	partitioned := t.mesh.partitioned(t.id, peer)
	t.mesh.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s is not in the mesh", ErrNoSuchPeer, peer)
	}
	if partitioned {
		return nil, fmt.Errorf("%w: %s is partitioned from %s", ErrNoSuchPeer, peer, t.id)
	}

	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return nil, ErrTransportClosed
	}

	// A pair of pipes, each end holding the other's write channel. Buffered, so a
	// send does not block on the peer being ready to read — which is what lets one
	// side send a whole batch before reading the response.
	aToB := make(chan *wire.Frame, 256)
	bToA := make(chan *wire.Frame, 256)
	done := make(chan struct{})

	initiator := &memorySession{
		peer: peer, send: aToB, recv: bToA, done: done, local: t.id,
	}
	responder := &memorySession{
		peer: t.id, send: bToA, recv: aToB, done: done, local: peer,
	}

	remote.mu.Lock()
	remoteClosed := remote.closed
	remote.mu.Unlock()
	if remoteClosed {
		return nil, fmt.Errorf("%w: %s has shut down", ErrNoSuchPeer, peer)
	}

	select {
	case remote.inbound <- responder:
		return initiator, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Accept implements Transport.
func (t *MemoryTransport) Accept(ctx context.Context) (Session, error) {
	select {
	case s, ok := <-t.inbound:
		if !ok {
			return nil, ErrTransportClosed
		}
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Peers implements Transport.
func (t *MemoryTransport) Peers() ([]Peer, error) {
	t.mesh.mu.Lock()
	defer t.mesh.mu.Unlock()
	out := make([]Peer, 0, len(t.mesh.nodes))
	for id := range t.mesh.nodes {
		if id == t.id {
			continue
		}
		out = append(out, Peer{
			Node:      id,
			Address:   "memory:" + string(id),
			Transport: TransportMemory,
			Online:    !t.mesh.partitioned(t.id, id),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out, nil
}

// Discovery implements Transport.
func (t *MemoryTransport) Discovery() string { return "in-process mesh" }

// Close implements Transport.
func (t *MemoryTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	close(t.inbound)
	return nil
}

// memorySession is one end of an in-process frame pipe.
type memorySession struct {
	local record.NodeID
	peer  record.NodeID
	send  chan *wire.Frame
	recv  chan *wire.Frame
	done  chan struct{}

	mu     stdsync.Mutex
	closed bool
}

func (s *memorySession) Peer() record.NodeID      { return s.peer }
func (s *memorySession) SetPeer(id record.NodeID) { s.peer = id }
func (s *memorySession) Transport() string        { return TransportMemory }
func (s *memorySession) RemoteAddr() string       { return "memory:" + string(s.peer) }

func (s *memorySession) Send(f *wire.Frame) error {
	// Marshal and re-parse even in memory, so the in-process transport exercises the
	// same encoding, size limits and signature verification the network path does.
	// A protocol bug that only appears once bytes are involved would otherwise hide
	// from every test in the suite.
	raw, err := f.Marshal()
	if err != nil {
		return err
	}
	parsed, err := wire.Unmarshal(raw[4:])
	if err != nil {
		return err
	}
	if err := parsed.Verify(); err != nil {
		return err
	}

	select {
	case s.send <- parsed:
		return nil
	case <-s.done:
		return ErrTransportClosed
	}
}

func (s *memorySession) Receive() (*wire.Frame, error) {
	// Drain anything already buffered before honouring a close. A TCP peer that
	// hangs up still delivers the bytes it sent first, and a transport that loses
	// them instead would make every test's timing load-bearing.
	select {
	case f, ok := <-s.recv:
		if !ok {
			return nil, ErrTransportClosed
		}
		return f, nil
	default:
	}
	select {
	case f, ok := <-s.recv:
		if !ok {
			return nil, ErrTransportClosed
		}
		return f, nil
	case <-s.done:
		// One last look, in case a frame landed as the session closed.
		select {
		case f, ok := <-s.recv:
			if ok {
				return f, nil
			}
		default:
		}
		return nil, ErrTransportClosed
	}
}

func (s *memorySession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	// Closing either end ends the session, which is what a dropped connection does.
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	return nil
}
