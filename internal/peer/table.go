// Package peer 提供 Kademlia 路由表、地址簿、评分封禁与令牌桶限速。
//
// 设计要点（对应 docs/CONTRACTS.md 第 6.3 节）：
//   - 路由表按异或距离分 256 桶，每桶默认 K=8；同 /24（IPv4）或 /48（IPv6）地址数受
//     MaxPerSubnet 限制以防日蚀。
//   - 地址 15 分钟未刷新即过期（AddrTTL），由 Expire 清理。
//   - 连败 3 次踢出；累计扣分到 -100 封禁 BanDuration（默认 24h）。
//
// 本包只依赖 internal/housekitchen 与标准库，禁止导入 registry/identity/node。
// 全部导出方法并发安全；返回的 NodeRecord 一律是深拷贝。
package peer

import (
	"crypto/ed25519"
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
	// DefaultK 是每个 Kademlia 桶的容量。
	DefaultK = 8
	// DefaultMinPeers 是 NeedMorePeers 的门槛。
	DefaultMinPeers = housekitchen.DefaultMinPeers
	// DefaultMaxPeers 是路由表总容量。
	DefaultMaxPeers = housekitchen.DefaultMaxPeers
	// DefaultAddrTTL 是地址有效期（15 分钟未刷新即过期）。
	DefaultAddrTTL = 15 * time.Minute
	// DefaultMaxPerSubnet 是同一子网允许的最大地址数（防日蚀）。
	DefaultMaxPerSubnet = 2
	// DefaultBanDuration 是默认封禁时长。
	DefaultBanDuration = 24 * time.Hour

	// bucketCount 是 Kademlia 桶数量（256 位 NodeID）。
	bucketCount = 256
	// maxFailures 是连败踢出阈值。
	maxFailures = 3
	// banScoreThreshold 是触发封禁的分数阈值。
	banScoreThreshold = -100
	// minScore / maxScore 是分数的钳制范围。
	minScore = -100
	maxScore = 100
)

// ErrSelfPeer 在把本地节点加入路由表时返回。
var ErrSelfPeer = errors.New("futurecast: peer: 不能把自身加入路由表")

// NodeRecord 是路由表中的一个节点及其地址簿、评分状态。
// 它是 housekitchen.NodeRecord 的别名（定义在下沉底座，便于 node 包声明
// PeerTable 接口时引用而不产生包间循环依赖）。
type NodeRecord = housekitchen.NodeRecord

// TableOptions 是 Table 的可调参数，零值字段使用默认值。
type TableOptions struct {
	K            int           // 每桶容量，默认 8
	MinPeers     int           // 默认 8
	MaxPeers     int           // 默认 64
	AddrTTL      time.Duration // 默认 15min
	MaxPerSubnet int           // 默认 2（防日蚀）
	BanDuration  time.Duration // 默认 24h
}

// Table 是并发安全的路由表 + 地址簿 + 评分封禁表。
type Table struct {
	mu sync.RWMutex

	self         housekitchen.NodeID
	k            int
	minPeers     int
	maxPeers     int
	maxPerSubnet int
	addrTTL      time.Duration
	banDuration  time.Duration

	clock func() time.Time

	buckets [bucketCount]map[housekitchen.NodeID]struct{}
	records map[housekitchen.NodeID]*NodeRecord
	bans    map[housekitchen.NodeID]time.Time
}

// NewTable 构造路由表。self 为本地节点 ID；opts 零值字段取默认值。
func NewTable(self housekitchen.NodeID, opts TableOptions) *Table {
	if opts.K <= 0 {
		opts.K = DefaultK
	}
	if opts.MinPeers <= 0 {
		opts.MinPeers = DefaultMinPeers
	}
	if opts.MaxPeers <= 0 {
		opts.MaxPeers = DefaultMaxPeers
	}
	if opts.MaxPeers < opts.MinPeers {
		opts.MaxPeers = opts.MinPeers
	}
	if opts.AddrTTL <= 0 {
		opts.AddrTTL = DefaultAddrTTL
	}
	if opts.MaxPerSubnet <= 0 {
		opts.MaxPerSubnet = DefaultMaxPerSubnet
	}
	if opts.BanDuration <= 0 {
		opts.BanDuration = DefaultBanDuration
	}
	t := &Table{
		self:         self,
		k:            opts.K,
		minPeers:     opts.MinPeers,
		maxPeers:     opts.MaxPeers,
		maxPerSubnet: opts.MaxPerSubnet,
		addrTTL:      opts.AddrTTL,
		banDuration:  opts.BanDuration,
		clock:        time.Now,
		records:      make(map[housekitchen.NodeID]*NodeRecord),
		bans:         make(map[housekitchen.NodeID]time.Time),
	}
	for i := range t.buckets {
		t.buckets[i] = make(map[housekitchen.NodeID]struct{})
	}
	return t
}

// Self 返回本地节点 ID。
func (t *Table) Self() housekitchen.NodeID { return t.self }

// ---------- 增删改查 ----------

// Upsert 插入或更新一个节点记录。
//
// 校验与副作用：
//   - NodeID 为零或等于 self、公钥长度非法 → 错误；
//   - 处于封禁期内的节点 → 包装 ErrBanned；
//   - LastSeen 超过 AddrTTL 的地址视为已过期，不予采纳（已有记录保留旧地址）；
//   - 新增地址所在子网（IPv4 /24、IPv6 /48）内其他节点数已达 MaxPerSubnet → 包装 ErrRateLimited；
//   - 桶满（K）或表满（MaxPeers）时淘汰"最差"记录（分数低、失败多、久未见者优先）。
func (t *Table) Upsert(rec NodeRecord) error {
	if rec.NodeID.IsZero() {
		return fmt.Errorf("futurecast: peer.Upsert: NodeID 为零值")
	}
	if rec.NodeID == t.self {
		return fmt.Errorf("futurecast: peer.Upsert: %w", ErrSelfPeer)
	}
	if len(rec.Pub) != 0 && len(rec.Pub) != ed25519.PublicKeySize {
		return fmt.Errorf("futurecast: peer.Upsert: 公钥长度 %d 应为 %d", len(rec.Pub), ed25519.PublicKeySize)
	}

	now := t.clock()
	if rec.LastSeen.IsZero() {
		rec.LastSeen = now
	}
	fresh := !rec.LastSeen.Add(t.addrTTL).Before(now) // now - LastSeen <= AddrTTL
	addrs := rec.Addrs
	if !fresh {
		addrs = nil
	}
	addrs = normalizeAddrs(addrs)

	t.mu.Lock()
	defer t.mu.Unlock()

	if until, ok := t.bans[rec.NodeID]; ok {
		if now.Before(until) {
			return fmt.Errorf("futurecast: peer.Upsert: %s 封禁至 %s: %w",
				rec.NodeID.Short(), until.UTC().Format(time.RFC3339), housekitchen.ErrBanned)
		}
		delete(t.bans, rec.NodeID)
	}

	existing := t.records[rec.NodeID]
	if existing == nil {
		if len(addrs) > 0 {
			if err := t.checkSubnetQuotaLocked(rec.NodeID, addrs, nil); err != nil {
				return err
			}
		}
		stored := cloneRecord(rec)
		stored.Addrs = addrs
		t.insertLocked(&stored)
		return nil
	}

	// 更新已有记录：只在来者更新鲜时覆盖字段，避免用旧信息抹掉新信息。
	merged := cloneRecord(*existing)
	if !rec.LastSeen.Before(existing.LastSeen) {
		merged.LastSeen = rec.LastSeen
	}
	if len(rec.Pub) != 0 {
		merged.Pub = append(ed25519.PublicKey(nil), rec.Pub...)
	}
	if len(addrs) > 0 {
		if err := t.checkSubnetQuotaLocked(rec.NodeID, addrs, existing.Addrs); err != nil {
			return err
		}
		merged.Addrs = addrs
	} else {
		merged.Addrs = normalizeAddrs(existing.Addrs)
	}
	if rec.Failures != 0 {
		merged.Failures = rec.Failures
	}
	if rec.Score != 0 {
		merged.Score = rec.Score
	}
	if rec.LatencyMS != 0 {
		merged.LatencyMS = rec.LatencyMS
	}
	if rec.Outbound {
		merged.Outbound = true
	}
	if rec.Announce != nil {
		merged.Announce = proto.Clone(rec.Announce).(*pb.NodeAnnounce)
	}
	t.records[rec.NodeID] = &merged
	return nil
}

// Remove 删除节点记录（不解除封禁）。
func (t *Table) Remove(id housekitchen.NodeID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.removeLocked(id)
}

// Get 返回节点记录的深拷贝。
func (t *Table) Get(id housekitchen.NodeID) (NodeRecord, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	r, ok := t.records[id]
	if !ok {
		return NodeRecord{}, false
	}
	return cloneRecord(*r), true
}

// Touch 记录一次成功交互：刷新 LastSeen、清空连败计数、更新 RTT。
// 节点不存在时不做任何事（不隐式插入）。
func (t *Table) Touch(id housekitchen.NodeID, rtt time.Duration, at time.Time) {
	if at.IsZero() {
		at = t.clock()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.records[id]
	if !ok {
		return
	}
	r.LastSeen = at
	r.Failures = 0
	if rtt >= 0 {
		r.LatencyMS = rtt.Milliseconds()
	}
}

// MarkFailure 记一次失败。连败达到阈值（3）时将该节点踢出路由表并返回 evicted=true。
func (t *Table) MarkFailure(id housekitchen.NodeID, at time.Time) (evicted bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.records[id]
	if !ok {
		return false
	}
	r.Failures++
	if r.Failures >= maxFailures {
		t.removeLocked(id)
		return true
	}
	return false
}

// Len 返回路由表节点数。
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.records)
}

// NeedMorePeers 报告路由表是否少于 MinPeers。
func (t *Table) NeedMorePeers() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.records) < t.minPeers
}

// Closest 返回按异或距离离 target 最近的至多 k 个节点（确定序）。
// All 返回表中全部记录（无排序保证，调用方自行排序）。
//
// 与 Closest 分开是有意的：Closest(k<=0) 返回 nil，用"很大的 k"来冒充
// "取全部"会掩盖语义，也让调用方误以为按距离排序过。
func (t *Table) All() []NodeRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]NodeRecord, 0, len(t.records))
	for _, r := range t.records {
		out = append(out, cloneRecord(*r))
	}
	return out
}

func (t *Table) Closest(target housekitchen.NodeID, k int) []NodeRecord {
	if k <= 0 {
		return nil
	}
	t.mu.RLock()
	out := make([]NodeRecord, 0, len(t.records))
	for _, r := range t.records {
		out = append(out, cloneRecord(*r))
	}
	t.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		switch housekitchen.CompareNodeID(target, out[i].NodeID, out[j].NodeID) {
		case -1:
			return true
		case 1:
			return false
		}
		return string(out[i].NodeID[:]) < string(out[j].NodeID[:])
	})
	if len(out) > k {
		out = out[:k]
	}
	return out
}

// Bucket 返回 target 所属的 Kademlia 桶序号（0..255；与 self 相同时取 255）。
func (t *Table) Bucket(target housekitchen.NodeID) int {
	return bucketIndex(t.self, target)
}

// EmptyBuckets 返回当前为空的桶序号，升序。
func (t *Table) EmptyBuckets() []int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []int
	for i := range t.buckets {
		if len(t.buckets[i]) == 0 {
			out = append(out, i)
		}
	}
	return out
}

// Expire 移除地址已过期（超过 AddrTTL 未见）的节点，并清理到期封禁。返回被移除的节点 ID，升序。
func (t *Table) Expire(now time.Time) []housekitchen.NodeID {
	if now.IsZero() {
		now = t.clock()
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	var removed []housekitchen.NodeID
	for id, r := range t.records {
		if now.Sub(r.LastSeen) > t.addrTTL {
			removed = append(removed, id)
		}
	}
	sort.Slice(removed, func(i, j int) bool {
		return string(removed[i][:]) < string(removed[j][:])
	})
	for _, id := range removed {
		t.removeLocked(id)
	}
	for id, until := range t.bans {
		if !now.Before(until) {
			delete(t.bans, id)
		}
	}
	return removed
}

// ---------- 评分与封禁 ----------

// Reward 增加节点分数（钳制到 [-100,100]）。
func (t *Table) Reward(id housekitchen.NodeID, delta int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.records[id]
	if !ok {
		return
	}
	r.Score = clampScore(r.Score + delta)
}

// Penalize 扣减节点分数。delta 采用与 internal/node 一致的「带符号分数变化」语义
// （集成侧传 -10/-20/-30），即 Score += delta；为兼容「惩罚量级」写法，正数一律按扣分处理
// ——Penalize 永不加分，加分请用 Reward。累计到 -100 时封禁 BanDuration 并从路由表踢出，
// 返回 true；重复调用在封禁期内同样返回 true。
func (t *Table) Penalize(id housekitchen.NodeID, delta int, reason string) (banned bool) {
	_ = reason
	penalty := delta
	if penalty > 0 {
		penalty = -penalty
	}
	now := t.clock()
	t.mu.Lock()
	defer t.mu.Unlock()

	if until, ok := t.bans[id]; ok {
		if now.Before(until) {
			return true
		}
		delete(t.bans, id)
	}
	r, ok := t.records[id]
	if !ok {
		return false
	}
	r.Score = clampScore(r.Score + penalty)
	if r.Score <= banScoreThreshold {
		t.bans[id] = now.Add(t.banDuration)
		t.removeLocked(id)
		return true
	}
	return false
}

// IsBanned 报告节点在 at 时刻是否处于封禁期。
func (t *Table) IsBanned(id housekitchen.NodeID, at time.Time) bool {
	if at.IsZero() {
		at = t.clock()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	until, ok := t.bans[id]
	if !ok {
		return false
	}
	if !at.Before(until) {
		delete(t.bans, id)
		return false
	}
	return true
}

// BannedUntil 返回封禁截止时刻；未封禁返回零值。
func (t *Table) BannedUntil(id housekitchen.NodeID) time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	until, ok := t.bans[id]
	if !ok {
		return time.Time{}
	}
	if !t.clock().Before(until) {
		delete(t.bans, id)
		return time.Time{}
	}
	return until
}

// BannedCount 返回当前封禁中的节点数（顺带清理到期封禁）。
func (t *Table) BannedCount() int {
	now := t.clock()
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, until := range t.bans {
		if !now.Before(until) {
			delete(t.bans, id)
		}
	}
	return len(t.bans)
}

// ---------- 内部实现 ----------

func bucketIndex(self, target housekitchen.NodeID) int {
	b := housekitchen.CommonPrefixLen(self, target)
	if b >= bucketCount {
		return bucketCount - 1
	}
	if b < 0 {
		return 0
	}
	return b
}

// insertLocked 插入新记录，必要时按"最差优先"淘汰。
func (t *Table) insertLocked(rec *NodeRecord) {
	idx := bucketIndex(t.self, rec.NodeID)

	if len(t.buckets[idx]) >= t.k {
		if worst := t.worstInBucketLocked(idx); worst != nil {
			t.removeLocked(worst.NodeID)
		}
	}
	if len(t.records) >= t.maxPeers {
		if worst := t.worstLocked(); worst != nil && worst.NodeID != rec.NodeID {
			t.removeLocked(worst.NodeID)
		}
	}

	t.records[rec.NodeID] = rec
	t.buckets[idx][rec.NodeID] = struct{}{}
}

func (t *Table) removeLocked(id housekitchen.NodeID) {
	if _, ok := t.records[id]; !ok {
		return
	}
	delete(t.buckets[bucketIndex(t.self, id)], id)
	delete(t.records, id)
}

func (t *Table) worstInBucketLocked(idx int) *NodeRecord {
	var worst *NodeRecord
	for id := range t.buckets[idx] {
		r := t.records[id]
		if r == nil {
			continue
		}
		if worst == nil || preferRecord(*r, *worst) {
			worst = r
		}
	}
	return worst
}

func (t *Table) worstLocked() *NodeRecord {
	var worst *NodeRecord
	for _, r := range t.records {
		if worst == nil || preferRecord(*r, *worst) {
			worst = r
		}
	}
	return worst
}

// preferRecord 报告 a 是否比 b 更该被淘汰（更差）。
func preferRecord(a, b NodeRecord) bool {
	if a.Score != b.Score {
		return a.Score < b.Score
	}
	if a.Failures != b.Failures {
		return a.Failures > b.Failures
	}
	if !a.LastSeen.Equal(b.LastSeen) {
		return a.LastSeen.Before(b.LastSeen)
	}
	if a.LatencyMS != b.LatencyMS {
		return a.LatencyMS > b.LatencyMS
	}
	return string(a.NodeID[:]) > string(b.NodeID[:])
}

// checkSubnetQuotaLocked 校验新地址不会让任一子网超过 MaxPerSubnet。
// prev 是记录原有地址（其子网不重复计数）。
func (t *Table) checkSubnetQuotaLocked(self housekitchen.NodeID, addrs, prev []string) error {
	if len(addrs) == 0 {
		return nil
	}
	inPrev := make(map[string]struct{}, len(prev))
	for _, a := range prev {
		if sk := SubnetKey(a); sk != "" {
			inPrev[sk] = struct{}{}
		}
	}
	checked := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		sk := SubnetKey(a)
		if sk == "" {
			continue
		}
		if _, ok := inPrev[sk]; ok {
			continue // 该记录原本就在这个子网里，不算新增
		}
		if _, ok := checked[sk]; ok {
			continue
		}
		checked[sk] = struct{}{}
		n := 0
		for id, r := range t.records {
			if id == self {
				continue
			}
			for _, other := range r.Addrs {
				if SubnetKey(other) == sk {
					n++
					break
				}
			}
		}
		if n+1 > t.maxPerSubnet {
			return fmt.Errorf("futurecast: peer.Upsert: 子网 %s 已达配额 %d: %w",
				sk, t.maxPerSubnet, housekitchen.ErrRateLimited)
		}
	}
	return nil
}

func clampScore(v int) int {
	if v < minScore {
		return minScore
	}
	if v > maxScore {
		return maxScore
	}
	return v
}

func cloneRecord(r NodeRecord) NodeRecord {
	out := r
	if r.Pub != nil {
		out.Pub = append(ed25519.PublicKey(nil), r.Pub...)
	}
	if r.Addrs != nil {
		out.Addrs = append([]string(nil), r.Addrs...)
	}
	if r.Announce != nil {
		out.Announce = proto.Clone(r.Announce).(*pb.NodeAnnounce)
	}
	return out
}
