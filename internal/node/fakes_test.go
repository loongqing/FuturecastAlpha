package node_test

import (
	"crypto/ed25519"
	"sort"
	"sync"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/node"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// ---------- 内存 MessageStore ----------

type memStore struct {
	mu     sync.Mutex
	seen   map[housekitchen.Hash]time.Time
	msgs   map[housekitchen.Hash]*pb.Envelope
	order  []housekitchen.Hash
	chunks map[housekitchen.Hash]map[uint32][]byte
}

func newMemStore() *memStore {
	return &memStore{
		seen:   map[housekitchen.Hash]time.Time{},
		msgs:   map[housekitchen.Hash]*pb.Envelope{},
		chunks: map[housekitchen.Hash]map[uint32][]byte{},
	}
}

func (m *memStore) Seen(id housekitchen.Hash, at time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.seen[id]; ok {
		return false
	}
	m.seen[id] = at
	return true
}

func (m *memStore) Put(env *pb.Envelope, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := housekitchen.GetHash(env.GetMsgId())
	if _, ok := m.msgs[id]; ok {
		return housekitchen.ErrDuplicate
	}
	m.msgs[id] = env
	m.order = append(m.order, id)
	return nil
}

func (m *memStore) Get(id housekitchen.Hash) (*pb.Envelope, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.msgs[id]
	return e, ok
}

func (m *memStore) List(topic string, since time.Time, limit int) []*pb.Envelope {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*pb.Envelope
	for _, id := range m.order {
		e := m.msgs[id]
		if e == nil {
			continue
		}
		if topic != "" && e.GetBody().GetTopic() != topic {
			continue
		}
		if !since.IsZero() && time.Unix(0, e.GetFirstSeenUnixNanos()).Before(since) {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func (m *memStore) Topics() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := map[string]struct{}{}
	var out []string
	for _, id := range m.order {
		e := m.msgs[id]
		if e == nil {
			continue
		}
		t := e.GetBody().GetTopic()
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func (m *memStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.msgs)
}

func (m *memStore) GC(time.Time) int { return 0 }

func (m *memStore) PutChunk(id housekitchen.Hash, index uint32, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.chunks[id] == nil {
		m.chunks[id] = map[uint32][]byte{}
	}
	m.chunks[id][index] = append([]byte(nil), data...)
	return nil
}

func (m *memStore) GetChunk(id housekitchen.Hash, index uint32) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.chunks[id][index]
	return b, ok
}

func (m *memStore) HasContent(id housekitchen.Hash, count uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.chunks[id]) != int(count) {
		return false
	}
	for i := uint32(0); i < count; i++ {
		if m.chunks[id][i] == nil {
			return false
		}
	}
	return true
}

func (m *memStore) MissingChunks(id housekitchen.Hash, count uint32) []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []uint32
	for i := uint32(0); i < count; i++ {
		if m.chunks[id][i] == nil {
			out = append(out, i)
		}
	}
	return out
}

func (m *memStore) CommitManifest(*pb.ContentManifest) error { return nil }

// ---------- 内存 PeerTable ----------

type memPeer struct {
	mu  sync.Mutex
	rec map[housekitchen.NodeID]node.PeerRecord
}

func newMemPeer() *memPeer { return &memPeer{rec: map[housekitchen.NodeID]node.PeerRecord{}} }

func (p *memPeer) Upsert(rec node.PeerRecord) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if old, ok := p.rec[rec.NodeID]; ok && len(rec.Addrs) == 0 {
		rec.Addrs = old.Addrs
	}
	p.rec[rec.NodeID] = rec
	return nil
}

func (p *memPeer) Remove(id housekitchen.NodeID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.rec, id)
}

func (p *memPeer) Get(id housekitchen.NodeID) (node.PeerRecord, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.rec[id]
	return r, ok
}

func (p *memPeer) Touch(id housekitchen.NodeID, rtt time.Duration, at time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.rec[id]
	r.NodeID = id
	r.LastSeen = at
	if rtt > 0 {
		r.LatencyMS = rtt.Milliseconds()
	}
	p.rec[id] = r
}

func (p *memPeer) MarkFailure(id housekitchen.NodeID, at time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.rec[id]
	r.Failures++
	p.rec[id] = r
	if r.Failures >= 3 {
		delete(p.rec, id)
		return true
	}
	return false
}

func (p *memPeer) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.rec)
}

func (p *memPeer) NeedMorePeers() bool { return p.Len() < 8 }

func (p *memPeer) Closest(target housekitchen.NodeID, k int) []node.PeerRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]node.PeerRecord, 0, len(p.rec))
	for _, r := range p.rec {
		out = append(out, r)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && housekitchen.CompareNodeID(target, out[j].NodeID, out[j-1].NodeID) < 0; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	if k > 0 && len(out) > k {
		out = out[:k]
	}
	return out
}

func (p *memPeer) All() []node.PeerRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]node.PeerRecord, 0, len(p.rec))
	for _, r := range p.rec {
		out = append(out, r)
	}
	return out
}

func (p *memPeer) Bucket(housekitchen.NodeID) int { return 0 }

func (p *memPeer) Expire(time.Time) []housekitchen.NodeID { return nil }

func (p *memPeer) Reward(id housekitchen.NodeID, delta int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.rec[id]
	r.Score += delta
	p.rec[id] = r
}

func (p *memPeer) Penalize(id housekitchen.NodeID, delta int, reason string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.rec[id]
	r.Score += delta
	p.rec[id] = r
	return r.Score <= -100
}

func (p *memPeer) IsBanned(housekitchen.NodeID, time.Time) bool { return false }

// ---------- 令牌桶 ----------

type fakeLimiter struct {
	remaining int
}

func (l *fakeLimiter) Allow(n int, _ time.Time) bool {
	if l.remaining <= 0 {
		return false
	}
	l.remaining -= n
	return true
}

var _ node.MessageStore = (*memStore)(nil)
var _ node.PeerTable = (*memPeer)(nil)
var _ node.Limiter = (*fakeLimiter)(nil)
var _ ed25519.PublicKey
