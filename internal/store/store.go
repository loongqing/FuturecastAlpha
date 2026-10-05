// Package store 提供内容寻址存储、去重表与分片校验。
//
// 设计要点（对应 docs/CONTRACTS.md 第 6.1 节）：
//   - 去重表 Seen 是「LRU + 滑动时间窗」：同一 msgID 在 ttl 内重复出现返回 false；
//     最后一次出现超过 ttl 后视为过期，再次出现重新算首次。容量达上限时淘汰最久未见的条目。
//   - 消息表按 first_seen 升序保存，Put 重复 msgID 返回包装 ErrDuplicate 的错误。
//   - 分片在 CommitManifest 时逐片做 SHA-256 校验并重建 Merkle 根，与清单不符返回包装
//     ErrInvalidSignature 的错误。
//
// 本包只依赖 internal/housekitchen 与标准库，禁止导入 registry/identity/node。
//
// 全部方法并发安全（内部单把互斥锁；返回的 proto 对象一律是深拷贝，调用方可自由修改）。
package store

import (
	"container/list"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
)

const (
	// DefaultCapacity 是容量参数的默认值（去重表与消息表各自的上限）。
	DefaultCapacity = housekitchen.DefaultDedupCapacity
	// DefaultTTL 是 ttl 参数的默认值（7 天），与 DefaultMsgTTLNanos 一致。
	DefaultTTL = time.Duration(housekitchen.DefaultMsgTTLNanos)
	// maxChunkCount 是单个清单允许的最大分片数，防御性上限。
	maxChunkCount = 1 << 22
)

// errIncompleteContent 表示清单声明的分片尚未全部到齐（无法校验，而非校验失败）。
var errIncompleteContent = errors.New("futurecast: store: 分片不完整")

// errZeroID 表示调用方传入了零值标识。
var errZeroID = errors.New("futurecast: store: 标识为零值")

// Store 是内容寻址存储 + 去重表。零值不可用，必须用 New 构造。
type Store struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration

	// 去重表：LRU 链表（front = 最近一次出现）+ 索引。
	seen    map[housekitchen.Hash]*list.Element
	seenLRU *list.List

	// 消息表：msgID → 条目；msgOrder 按 first_seen 升序。
	msgs     map[housekitchen.Hash]*msgEntry
	msgOrder []*msgEntry

	// 分片表：contentID → index → data；chunkAt 记录最近一次写入时间，供 GC 使用。
	chunks    map[housekitchen.Hash]map[uint32][]byte
	chunkAt   map[housekitchen.Hash]time.Time
	manifests map[housekitchen.Hash]*pb.ContentManifest
}

type seenEntry struct {
	id housekitchen.Hash
	at time.Time
}

type msgEntry struct {
	id        housekitchen.Hash
	env       *pb.Envelope
	firstSeen time.Time
}

// New 构造 Store。capacity <= 0 时取 DefaultCapacity，ttl <= 0 时取 DefaultTTL。
func New(capacity int, ttl time.Duration) *Store {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Store{
		capacity:  capacity,
		ttl:       ttl,
		seen:      make(map[housekitchen.Hash]*list.Element),
		seenLRU:   list.New(),
		msgs:      make(map[housekitchen.Hash]*msgEntry),
		chunks:    make(map[housekitchen.Hash]map[uint32][]byte),
		chunkAt:   make(map[housekitchen.Hash]time.Time),
		manifests: make(map[housekitchen.Hash]*pb.ContentManifest),
	}
}

// Capacity 返回去重表/消息表的容量上限。
func (s *Store) Capacity() int { return s.capacity }

// TTL 返回去重时间窗与消息保留时长。
func (s *Store) TTL() time.Duration { return s.ttl }

// ---------- 去重 ----------

// Seen 记录一次 msgID 的出现。
//
// 若 msgID 在 ttl 滑动窗口内已出现过，返回 false（重复，应丢弃）并刷新其时间与 LRU 位置；
// 若是首次出现（或上次出现已超出窗口），返回 true 并记录。容量达上限时淘汰最久未见的条目。
func (s *Store) Seen(msgID housekitchen.Hash, at time.Time) bool {
	if at.IsZero() {
		at = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if el, ok := s.seen[msgID]; ok {
		e := el.Value.(*seenEntry)
		if !e.at.Add(s.ttl).Before(at) { // at - e.at <= ttl
			e.at = at
			s.seenLRU.MoveToFront(el)
			return false
		}
		// 窗口外：按首次出现处理。
		s.seenLRU.Remove(el)
		delete(s.seen, msgID)
	}

	el := s.seenLRU.PushFront(&seenEntry{id: msgID, at: at})
	s.seen[msgID] = el
	for s.seenLRU.Len() > s.capacity {
		back := s.seenLRU.Back()
		if back == nil {
			break
		}
		s.seenLRU.Remove(back)
		delete(s.seen, back.Value.(*seenEntry).id)
	}
	return true
}

// Repeated 只查询不记录：msgID 是否仍在去重窗口内。
func (s *Store) Repeated(msgID housekitchen.Hash, at time.Time) bool {
	if at.IsZero() {
		at = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.seen[msgID]
	if !ok {
		return false
	}
	return !el.Value.(*seenEntry).at.Add(s.ttl).Before(at)
}

// SeenLen 返回当前去重表条目数。
func (s *Store) SeenLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// ---------- 消息表 ----------

// Put 存入一个信封。msgID 已在表中时返回包装 ErrDuplicate 的错误。
//
// 存入的是深拷贝；调用方后续修改 env 不影响存储内容。
func (s *Store) Put(env *pb.Envelope, at time.Time) error {
	if env == nil {
		return fmt.Errorf("futurecast: store.Put: 信封为空")
	}
	id, err := envelopeID(env)
	if err != nil {
		return err
	}
	firstSeen := at
	if firstSeen.IsZero() {
		if env.GetFirstSeenUnixNanos() != 0 {
			firstSeen = housekitchen.FromUnixNanos(env.GetFirstSeenUnixNanos())
		} else if env.GetBody() != nil && env.GetBody().GetCreatedAtUnixNanos() != 0 {
			firstSeen = housekitchen.FromUnixNanos(env.GetBody().GetCreatedAtUnixNanos())
		} else {
			firstSeen = time.Now()
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.msgs[id]; ok {
		return fmt.Errorf("futurecast: store.Put: msg_id %s: %w", id.Short(), housekitchen.ErrDuplicate)
	}
	if at.IsZero() && env.FirstSeenUnixNanos == 0 {
		// 补全信封自述的 first_seen，便于 List 排序与 GC 判定。
		envCopy := proto.Clone(env).(*pb.Envelope)
		envCopy.FirstSeenUnixNanos = firstSeen.UnixNano()
		env = envCopy
	}

	e := &msgEntry{id: id, env: proto.Clone(env).(*pb.Envelope), firstSeen: firstSeen}
	s.msgs[id] = e
	s.insertOrderedLocked(e)
	s.evictMessagesLocked()
	return nil
}

// Get 按 msgID 取出信封的深拷贝。
func (s *Store) Get(msgID housekitchen.Hash) (*pb.Envelope, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.msgs[msgID]
	if !ok {
		return nil, false
	}
	return proto.Clone(e.env).(*pb.Envelope), true
}

// List 返回满足条件的信封深拷贝，按 first_seen 升序。
//
// topic 为空表示不限主题；since 为零值表示不限起始时间；limit <= 0 表示不限条数。
func (s *Store) List(topic string, since time.Time, limit int) []*pb.Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []*pb.Envelope
	for _, e := range s.msgOrder {
		if limit > 0 && len(out) >= limit {
			break
		}
		if !since.IsZero() && e.firstSeen.Before(since) {
			continue
		}
		if topic != "" && e.env.GetBody().GetTopic() != topic {
			continue
		}
		out = append(out, proto.Clone(e.env).(*pb.Envelope))
	}
	return out
}

// Topics 返回消息表中出现过的全部主题（去重、已排序、不含空主题）。
//
// 供节点的 anti-entropy 使用：INV 必须覆盖"本地实际存在的主题"，
// 而不是只看配置的订阅列表。否则未订阅主题上的消息永远不会被广告出去，
// "最终一致"对它们失效（这是被端到端演示暴露出来的真实缺陷）。
func (s *Store) Topics() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]struct{}, len(s.msgs))
	out := make([]string, 0, len(s.msgs))
	for _, e := range s.msgs {
		t := e.env.GetBody().GetTopic()
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

// Len 返回消息表中保存的消息条数。
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.msgs)
}

// GC 清理过期条目：去重表超过 ttl 的条目、消息表超过保留时长（或信封 expires_at 已过）的消息、
// 分片表超过保留时长的内容。返回清除的条目总数（去重条目 + 消息 + 内容组）。
func (s *Store) GC(now time.Time) int {
	if now.IsZero() {
		now = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0

	// 去重表
	var expiredSeen []*list.Element
	for el := s.seenLRU.Back(); el != nil; el = el.Prev() {
		if now.Sub(el.Value.(*seenEntry).at) > s.ttl {
			expiredSeen = append(expiredSeen, el)
		}
	}
	for _, el := range expiredSeen {
		s.seenLRU.Remove(el)
		delete(s.seen, el.Value.(*seenEntry).id)
		removed++
	}

	// 消息表
	kept := s.msgOrder[:0]
	for _, e := range s.msgOrder {
		if s.expiredLocked(e, now) {
			delete(s.msgs, e.id)
			removed++
			continue
		}
		kept = append(kept, e)
	}
	for i := len(kept); i < len(s.msgOrder); i++ {
		s.msgOrder[i] = nil // 帮助 GC
	}
	s.msgOrder = kept

	// 分片表
	for cid, at := range s.chunkAt {
		if now.Sub(at) > s.ttl {
			delete(s.chunkAt, cid)
			delete(s.chunks, cid)
			delete(s.manifests, cid)
			removed++
		}
	}
	return removed
}

func (s *Store) expiredLocked(e *msgEntry, now time.Time) bool {
	if now.Sub(e.firstSeen) > s.ttl {
		return true
	}
	if b := e.env.GetBody(); b != nil && b.GetExpiresAtUnixNanos() > 0 {
		if now.UnixNano() > b.GetExpiresAtUnixNanos() {
			return true
		}
	}
	return false
}

// insertOrderedLocked 按 first_seen 升序插入（同刻按 msg_id 字典序，保证确定性）。
func (s *Store) insertOrderedLocked(e *msgEntry) {
	i := sort.Search(len(s.msgOrder), func(i int) bool {
		o := s.msgOrder[i]
		if o.firstSeen.Equal(e.firstSeen) {
			return bytesCompare(o.id[:], e.id[:]) >= 0
		}
		return o.firstSeen.After(e.firstSeen)
	})
	s.msgOrder = append(s.msgOrder, nil)
	copy(s.msgOrder[i+1:], s.msgOrder[i:])
	s.msgOrder[i] = e
}

// evictMessagesLocked 在超过容量时淘汰 first_seen 最旧的消息。
func (s *Store) evictMessagesLocked() {
	for len(s.msgOrder) > s.capacity {
		old := s.msgOrder[0]
		s.msgOrder = s.msgOrder[1:]
		delete(s.msgs, old.id)
	}
}

// ---------- 分片 ----------

// PutChunk 写入一个分片（深拷贝）。index 超过防御性上限返回错误。
func (s *Store) PutChunk(contentID housekitchen.Hash, index uint32, data []byte) error {
	if contentID.IsZero() {
		return fmt.Errorf("futurecast: store.PutChunk: content_id: %w", errZeroID)
	}
	if index >= maxChunkCount {
		return fmt.Errorf("futurecast: store.PutChunk: index %d 超出上限 %d", index, maxChunkCount)
	}
	cp := append([]byte(nil), data...)
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.chunks[contentID]
	if m == nil {
		m = make(map[uint32][]byte)
		s.chunks[contentID] = m
	}
	m[index] = cp
	s.chunkAt[contentID] = time.Now()
	return nil
}

// GetChunk 取出分片深拷贝。
func (s *Store) GetChunk(contentID housekitchen.Hash, index uint32) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.chunks[contentID]
	if m == nil {
		return nil, false
	}
	data, ok := m[index]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), data...), true
}

// HasContent 判断 [0,count) 的分片是否全部到场。count == 0 视为空内容（真）。
func (s *Store) HasContent(contentID housekitchen.Hash, count uint32) bool {
	return len(s.MissingChunks(contentID, count)) == 0
}

// MissingChunks 返回 [0,count) 中缺失的分片序号，升序。
func (s *Store) MissingChunks(contentID housekitchen.Hash, count uint32) []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return missingChunksLocked(s.chunks[contentID], count)
}

func missingChunksLocked(m map[uint32][]byte, count uint32) []uint32 {
	if count == 0 {
		return nil
	}
	var out []uint32
	for i := uint32(0); i < count; i++ {
		if _, ok := m[i]; !ok {
			out = append(out, i)
		}
	}
	return out
}

// CommitManifest 校验清单并登记。
//
// 校验项：
//  1. 清单结构：content_id 非零、chunk_size > 0、chunk_count 与 total_size 自洽；
//  2. 完整性：[0,chunk_count) 分片必须全部到场，否则返回 errIncompleteContent；
//  3. 逐片 SHA-256：重建 Merkle 根（见 MerkleRoot），与清单 merkle_root 不符 → 包装 ErrInvalidSignature；
//     分片长度之和与 total_size 不符同样视为内容与清单不符 → 包装 ErrInvalidSignature。
func (s *Store) CommitManifest(m *pb.ContentManifest) error {
	if m == nil {
		return fmt.Errorf("futurecast: store.CommitManifest: 清单为空")
	}
	cid := housekitchen.GetHash(m.GetContentId())
	if cid.IsZero() {
		return fmt.Errorf("futurecast: store.CommitManifest: content_id: %w", errZeroID)
	}
	if m.GetChunkSize() == 0 {
		return fmt.Errorf("futurecast: store.CommitManifest: chunk_size 为 0")
	}
	count := m.GetChunkCount()
	if count > maxChunkCount {
		return fmt.Errorf("futurecast: store.CommitManifest: chunk_count %d 超出上限 %d", count, maxChunkCount)
	}
	if count == 0 && m.GetTotalSize() == 0 {
		return fmt.Errorf("futurecast: store.CommitManifest: 空清单（chunk_count 与 total_size 均为 0）")
	}
	if count == 0 {
		count = uint32((m.GetTotalSize() + uint64(m.GetChunkSize()) - 1) / uint64(m.GetChunkSize()))
	}
	if m.GetTotalSize() > 0 {
		want := (m.GetTotalSize() + uint64(m.GetChunkSize()) - 1) / uint64(m.GetChunkSize())
		if uint64(count) != want {
			return fmt.Errorf("futurecast: store.CommitManifest: chunk_count %d 与 total_size/chunk_size=%d 不一致", count, want)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	chunks := s.chunks[cid]
	if miss := missingChunksLocked(chunks, count); len(miss) > 0 {
		return fmt.Errorf("futurecast: store.CommitManifest: %s: %w: 缺失分片 %v", cid.Short(), errIncompleteContent, miss)
	}

	// 逐片 SHA-256，构造 Merkle 叶。
	leaves := make([][]byte, 0, count)
	var total uint64
	for i := uint32(0); i < count; i++ {
		data := chunks[i]
		total += uint64(len(data))
		h := housekitchen.Sum256(data)
		leaves = append(leaves, h.Bytes())
	}
	if m.GetTotalSize() > 0 && total != m.GetTotalSize() {
		return fmt.Errorf("futurecast: store.CommitManifest: %s: 分片总长 %d 与 total_size %d 不符: %w",
			cid.Short(), total, m.GetTotalSize(), housekitchen.ErrInvalidSignature)
	}
	if len(m.GetMerkleRoot()) > 0 {
		if len(m.GetMerkleRoot()) != housekitchen.HashSize {
			return fmt.Errorf("futurecast: store.CommitManifest: %s: merkle_root 长度 %d 应为 %d: %w",
				cid.Short(), len(m.GetMerkleRoot()), housekitchen.HashSize, housekitchen.ErrInvalidSignature)
		}
		root := merkleRoot(leaves)
		if !housekitchen.ConstantTimeEqual(root, m.GetMerkleRoot()) {
			return fmt.Errorf("futurecast: store.CommitManifest: %s: merkle_root 不符: %w",
				cid.Short(), housekitchen.ErrInvalidSignature)
		}
	}

	s.manifests[cid] = proto.Clone(m).(*pb.ContentManifest)
	s.chunkAt[cid] = time.Now()
	return nil
}

// Manifest 返回已登记的清单深拷贝。
func (s *Store) Manifest(contentID housekitchen.Hash) (*pb.ContentManifest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.manifests[contentID]
	if !ok {
		return nil, false
	}
	return proto.Clone(m).(*pb.ContentManifest), true
}

// ChunkCount 返回某内容当前已保存的分片数。
func (s *Store) ChunkCount(contentID housekitchen.Hash) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.chunks[contentID])
}

// MerkleRoot 按本包约定计算分片 Merkle 根，供调用方构造清单。
//
// 约定：叶 = SHA-256(chunk_i)；逐层两两配对父 = SHA-256(left||right)，奇数个节点时末节点原样进位。
func MerkleRoot(chunks [][]byte) []byte {
	leaves := make([][]byte, 0, len(chunks))
	for _, c := range chunks {
		h := housekitchen.Sum256(c)
		leaves = append(leaves, append([]byte(nil), h[:]...))
	}
	return merkleRoot(leaves)
}

func merkleRoot(nodes [][]byte) []byte {
	if len(nodes) == 0 {
		return nil
	}
	level := nodes
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			h := housekitchen.HashOf(level[i], level[i+1])
			next = append(next, append([]byte(nil), h[:]...))
		}
		level = next
	}
	return level[0]
}

// ---------- 内部工具 ----------

func envelopeID(env *pb.Envelope) (housekitchen.Hash, error) {
	id := housekitchen.GetHash(env.GetMsgId())
	if id.IsZero() && env.GetBody() != nil {
		id = housekitchen.GetHash(env.GetBody().GetMsgId())
	}
	if id.IsZero() {
		return housekitchen.Hash{}, fmt.Errorf("futurecast: store: 信封缺少 msg_id")
	}
	return id, nil
}

func bytesCompare(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}
