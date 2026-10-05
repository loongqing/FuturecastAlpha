package peer

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
)

func nid(bs ...byte) housekitchen.NodeID {
	var n housekitchen.NodeID
	copy(n[:], bs)
	return n
}

func zeroID() housekitchen.NodeID { return housekitchen.NodeID{} }

func testPub(b byte) ed25519.PublicKey {
	p := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range p {
		p[i] = b
	}
	return p
}

// ---------- 地址簿与子网配额 ----------

func TestUpsertSubnetQuotaIPv4(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{MaxPerSubnet: 2, AddrTTL: time.Hour})

	addrs := []string{"203.0.113.1:1", "203.0.113.2:2", "203.0.113.3:3"}
	for i, addr := range addrs {
		err := tbl.Upsert(NodeRecord{NodeID: nid(0x11, byte(i+1)), Addrs: []string{addr}, LastSeen: now})
		switch {
		case i < 2 && err != nil:
			t.Fatalf("第 %d 个同 /24 地址应被接受，实为 %v", i+1, err)
		case i == 2 && !errors.Is(err, housekitchen.ErrRateLimited):
			t.Fatalf("第 3 个同 /24 地址应返回 ErrRateLimited，实为 %v", err)
		}
	}
	if tbl.Len() != 2 {
		t.Fatalf("同 /24 被拒后路由表应只有 2 个节点，实为 %d", tbl.Len())
	}

	// 相邻 /24 不受影响。
	if err := tbl.Upsert(NodeRecord{NodeID: nid(0x22, 1), Addrs: []string{"203.0.114.1:1"}, LastSeen: now}); err != nil {
		t.Fatalf("不同 /24 应被接受，实为 %v", err)
	}
	// /24 内的另一个地址同样落在配额里。
	err := tbl.Upsert(NodeRecord{NodeID: nid(0x22, 2), Addrs: []string{"203.0.113.99:9"}, LastSeen: now})
	if !errors.Is(err, housekitchen.ErrRateLimited) {
		t.Fatalf("同 /24 内的新地址应被拒，实为 %v", err)
	}
	// 一个节点携带两个同 /24 地址只算一次新增，落在一个已有节点的子网里应被拒。
	err = tbl.Upsert(NodeRecord{NodeID: nid(0x22, 3), Addrs: []string{"203.0.114.2:2", "203.0.113.100:1"}, LastSeen: now})
	if !errors.Is(err, housekitchen.ErrRateLimited) {
		t.Fatalf("多地址记录命中已满子网也应被拒，实为 %v", err)
	}
}

func TestUpsertSubnetQuotaIPv6(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{MaxPerSubnet: 2, AddrTTL: time.Hour})

	addrs := []string{"2001:db8:1::1", "[2001:db8:1::2]:9", "2001:db8:1::3"}
	for i, addr := range addrs {
		err := tbl.Upsert(NodeRecord{NodeID: nid(0x31, byte(i+1)), Addrs: []string{addr}, LastSeen: now})
		switch {
		case i < 2 && err != nil:
			t.Fatalf("第 %d 个同 /48 地址应被接受，实为 %v", i+1, err)
		case i == 2 && !errors.Is(err, housekitchen.ErrRateLimited):
			t.Fatalf("第 3 个同 /48 地址应返回 ErrRateLimited，实为 %v", err)
		}
	}
	if err := tbl.Upsert(NodeRecord{NodeID: nid(0x32, 1), Addrs: []string{"2001:db8:2::1"}, LastSeen: now}); err != nil {
		t.Fatalf("不同 /48 应被接受，实为 %v", err)
	}
}

func TestUpsertKeepsFreshAddressesOnStaleUpdate(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{AddrTTL: time.Minute})
	id := nid(0x41, 1)
	if err := tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"203.0.113.1:1"}, LastSeen: now}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// 用过期信息更新：地址不得被抹掉，LastSeen 也不得回退。
	if err := tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"203.0.113.9:9"}, LastSeen: now.Add(-10 * time.Minute)}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, ok := tbl.Get(id)
	if !ok {
		t.Fatal("记录应存在")
	}
	if len(got.Addrs) != 1 || got.Addrs[0] != "203.0.113.1:1" {
		t.Fatalf("过期地址不应覆盖新鲜地址，实为 %v", got.Addrs)
	}
	if !got.LastSeen.Equal(now) {
		t.Fatalf("LastSeen 不应回退，实为 %v", got.LastSeen)
	}

	// 全新记录携带过期地址：地址被丢弃（AddrTTL 未刷新），但仍可登记身份。
	id2 := nid(0x41, 2)
	if err := tbl.Upsert(NodeRecord{NodeID: id2, Addrs: []string{"198.51.100.1:1"}, LastSeen: now.Add(-10 * time.Minute)}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got2, ok := tbl.Get(id2)
	if !ok {
		t.Fatal("记录应存在")
	}
	if len(got2.Addrs) != 0 {
		t.Fatalf("过期地址不应被采纳，实为 %v", got2.Addrs)
	}
	// 该记录的 LastSeen 已过期，Expire 应清掉它。
	if removed := tbl.Expire(now); len(removed) != 1 || removed[0] != id2 {
		t.Fatalf("Expire 应清掉过期记录 %v，实为 %v", id2.Short(), removed)
	}
}

// ---------- Kademlia 路由 ----------

func TestClosestOrderWithKnownXorDistances(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{AddrTTL: time.Hour, MaxPerSubnet: 100})

	nA := nid(0x00, 0x01) // 距离 2^240
	nB := nid(0x00, 0x80) // 距离 2^247
	nC := nid(0x01)       // 距离 2^248
	nD := nid(0x80)       // 距离 2^255

	// 故意乱序插入。
	for i, id := range []housekitchen.NodeID{nD, nC, nB, nA} {
		if err := tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"203.0.113." + string(rune('1'+i)) + ":1"}, LastSeen: now}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	got := tbl.Closest(zeroID(), 2)
	if len(got) != 2 || got[0].NodeID != nA || got[1].NodeID != nB {
		t.Fatalf("Closest(2) = %v，应为 [nA nB]", idsOf(got))
	}
	all := tbl.Closest(zeroID(), 10)
	want := []housekitchen.NodeID{nA, nB, nC, nD}
	if len(all) != 4 {
		t.Fatalf("Closest(10) 应返回 4 个，实为 %d", len(all))
	}
	for i, id := range want {
		if all[i].NodeID != id {
			t.Fatalf("Closest 顺序错误：第 %d 个为 %s，应为 %s", i, all[i].NodeID.Short(), id.Short())
		}
	}
	if tbl.Closest(zeroID(), 0) != nil {
		t.Fatal("k<=0 应返回 nil")
	}
	if tbl.Closest(zeroID(), -3) != nil {
		t.Fatal("k<0 应返回 nil")
	}

	// 桶序号 = 公共前缀长度。
	buckets := map[housekitchen.NodeID]int{nA: 15, nB: 8, nC: 7, nD: 0}
	for id, want := range buckets {
		if got := tbl.Bucket(id); got != want {
			t.Fatalf("Bucket(%s) = %d，应为 %d", id.Short(), got, want)
		}
	}
	if got := tbl.Bucket(zeroID()); got != 255 {
		t.Fatalf("与 self 相同应归入 255 号桶，实为 %d", got)
	}

	empty := tbl.EmptyBuckets()
	if len(empty) != 252 {
		t.Fatalf("应有 252 个空桶，实为 %d", len(empty))
	}
	occupied := map[int]bool{0: true, 7: true, 8: true, 15: true}
	for _, b := range empty {
		if occupied[b] {
			t.Fatalf("桶 %d 非空，不应出现在 EmptyBuckets", b)
		}
	}
}

func idsOf(recs []NodeRecord) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.NodeID.Short())
	}
	return out
}

func TestUpsertBucketCapacityK(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{K: 4, MaxPeers: 100, MaxPerSubnet: 100, AddrTTL: time.Hour})

	// 首字节 0x80 → 与全零 self 的公共前缀为 0，全部落在 0 号桶。
	ids := make([]housekitchen.NodeID, 5)
	for i := range ids {
		ids[i] = nid(0x80, byte(i+1))
		if err := tbl.Upsert(NodeRecord{NodeID: ids[i], Addrs: []string{"203.0." + string(rune('1'+i)) + ".1:1"}, LastSeen: now.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatalf("Upsert(%d): %v", i, err)
		}
	}
	if tbl.Len() != 4 {
		t.Fatalf("每桶 K=4，路由表应保持 4 个，实为 %d", tbl.Len())
	}
	if _, ok := tbl.Get(ids[0]); ok {
		t.Fatal("最久未见的节点应被淘汰")
	}
	if _, ok := tbl.Get(ids[4]); !ok {
		t.Fatal("最新节点应在表中")
	}
}

func TestUpsertMaxPeers(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{K: 8, MinPeers: 1, MaxPeers: 3, MaxPerSubnet: 100, AddrTTL: time.Hour})

	// 不同首字节 → 不同桶，排除桶容量因素，只考验 MaxPeers。
	ids := []housekitchen.NodeID{nid(0x80), nid(0x40), nid(0x20), nid(0x10)}
	for i, id := range ids {
		if err := tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"198.51.100." + string(rune('1'+i)) + ":1"}, LastSeen: now.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatalf("Upsert(%d): %v", i, err)
		}
	}
	if tbl.Len() != 3 {
		t.Fatalf("MaxPeers=3 时应保持 3 个，实为 %d", tbl.Len())
	}
	if _, ok := tbl.Get(ids[0]); ok {
		t.Fatal("最早加入的节点应被淘汰")
	}
}

func TestNeedMorePeers(t *testing.T) {
	tbl := NewTable(zeroID(), TableOptions{MinPeers: 3, MaxPerSubnet: 100})
	if !tbl.NeedMorePeers() {
		t.Fatal("空表应需要更多邻居")
	}
	if len(tbl.EmptyBuckets()) != 256 {
		t.Fatalf("空表应有 256 个空桶，实为 %d", len(tbl.EmptyBuckets()))
	}
	now := time.Now()
	for i := 0; i < 3; i++ {
		if err := tbl.Upsert(NodeRecord{NodeID: nid(0x80, byte(i+1)), Addrs: []string{"192.0.2." + string(rune('1'+i)) + ":1"}, LastSeen: now}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}
	if tbl.NeedMorePeers() {
		t.Fatal("达到 MinPeers 后不应再报告需要更多邻居")
	}
}

// ---------- 失败、评分与封禁 ----------

func TestMarkFailureEvictsAfterThree(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{AddrTTL: time.Hour})
	id := nid(0x51, 1)
	if err := tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"203.0.113.1:1"}, LastSeen: now}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if evicted := tbl.MarkFailure(id, now); evicted {
		t.Fatal("第 1 次失败不应踢出")
	}
	if evicted := tbl.MarkFailure(id, now); evicted {
		t.Fatal("第 2 次失败不应踢出")
	}
	if r, _ := tbl.Get(id); r.Failures != 2 {
		t.Fatalf("Failures 应为 2，实为 %d", r.Failures)
	}
	if evicted := tbl.MarkFailure(id, now); !evicted {
		t.Fatal("第 3 次失败应踢出")
	}
	if tbl.Len() != 0 {
		t.Fatalf("踢出后 Len 应为 0，实为 %d", tbl.Len())
	}
	if _, ok := tbl.Get(id); ok {
		t.Fatal("踢出后不应还能查到")
	}
	if evicted := tbl.MarkFailure(id, now); evicted {
		t.Fatal("对不存在的节点 MarkFailure 应返回 false")
	}
}

func TestTouchResetsFailures(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{AddrTTL: time.Hour})
	id := nid(0x52, 1)
	if err := tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"203.0.113.1:1"}, LastSeen: now}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	tbl.MarkFailure(id, now)
	tbl.MarkFailure(id, now)
	tbl.Touch(id, 42*time.Millisecond, now.Add(time.Second))
	r, _ := tbl.Get(id)
	if r.Failures != 0 {
		t.Fatalf("Touch 后 Failures 应清零，实为 %d", r.Failures)
	}
	if r.LatencyMS != 42 {
		t.Fatalf("LatencyMS 应为 42，实为 %d", r.LatencyMS)
	}
	if !r.LastSeen.Equal(now.Add(time.Second)) {
		t.Fatalf("LastSeen 应被刷新，实为 %v", r.LastSeen)
	}
	if evicted := tbl.MarkFailure(id, now); evicted {
		t.Fatal("清零后第 1 次失败不应踢出")
	}
	// Touch 不存在的节点是 no-op。
	tbl.Touch(nid(0xFF), time.Millisecond, now)
}

func TestPenalizeBansAndIsBanned(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{BanDuration: 100 * time.Millisecond, AddrTTL: time.Hour})
	id := nid(0x61, 1)
	if err := tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"203.0.113.1:1"}, LastSeen: now}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// internal/node 集成侧传负数（-10/-20/-30），必须按扣分处理。
	if banned := tbl.Penalize(id, -40, "invalid signature"); banned {
		t.Fatal("累计 -40 不应封禁")
	}
	tbl.Reward(id, 10)
	if r, _ := tbl.Get(id); r.Score != -30 {
		t.Fatalf("Score 应为 -30，实为 %d", r.Score)
	}
	if banned := tbl.Penalize(id, -40, "flood"); banned {
		t.Fatal("累计 -70 不应封禁")
	}
	// 正数「惩罚量级」写法同样按扣分处理，Penalize 永不加分。
	if banned := tbl.Penalize(id, 30, "flood"); !banned {
		t.Fatal("累计到 -100 应封禁")
	}
	if !tbl.IsBanned(id, now) {
		t.Fatal("封禁期内 IsBanned 应为 true")
	}
	if until := tbl.BannedUntil(id); until.IsZero() {
		t.Fatal("BannedUntil 应非零")
	}
	if tbl.Len() != 0 {
		t.Fatalf("封禁应同时踢出路由表，Len 实为 %d", tbl.Len())
	}
	// 封禁期内重复扣分仍返回 true。
	if banned := tbl.Penalize(id, -1, "again"); !banned {
		t.Fatal("封禁期内 Penalize 应返回 true")
	}
	// 封禁期内 Upsert 应被拒。
	err := tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"203.0.113.1:1"}, LastSeen: now})
	if !errors.Is(err, housekitchen.ErrBanned) {
		t.Fatalf("封禁期内 Upsert 应包装 ErrBanned，实为 %v", err)
	}
	// 时间推进越过封禁期 → 解封。
	if tbl.IsBanned(id, now.Add(time.Second)) {
		t.Fatal("封禁期过后 IsBanned 应为 false")
	}
	if until := tbl.BannedUntil(id); !until.IsZero() {
		t.Fatal("封禁期过后 BannedUntil 应为零值")
	}
	if err := tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"203.0.113.1:1"}, LastSeen: now.Add(time.Second)}); err != nil {
		t.Fatalf("解封后应可重新加入，实为 %v", err)
	}
	// 未知节点扣分返回 false。
	if banned := tbl.Penalize(nid(0xEE), 5, "x"); banned {
		t.Fatal("未知节点不应被封禁")
	}
}

func TestRewardClampsAtMaxScore(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{AddrTTL: time.Hour})
	id := nid(0x71, 1)
	if err := tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"203.0.113.1:1"}, LastSeen: now}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	tbl.Reward(id, 1000)
	if r, _ := tbl.Get(id); r.Score != 100 {
		t.Fatalf("Score 应被钳制到 100，实为 %d", r.Score)
	}
	tbl.Reward(nid(0xEE), 5) // 未知节点 no-op
}

func TestPenalizeNeverRewards(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{AddrTTL: time.Hour, MaxPerSubnet: 100})
	posID, negID := nid(0x72, 1), nid(0x72, 2)
	for i, id := range []housekitchen.NodeID{posID, negID} {
		if err := tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"203.0.113." + string(rune('1'+i)) + ":1"}, LastSeen: now}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}
	// 正数按惩罚量级扣分，负数按带符号变化扣分——两者都不得加分。
	if banned := tbl.Penalize(posID, 50, "positive delta"); banned {
		t.Fatal("扣 50 不应封禁")
	}
	if banned := tbl.Penalize(negID, -50, "negative delta"); banned {
		t.Fatal("扣 50 不应封禁")
	}
	if r, _ := tbl.Get(posID); r.Score != -50 {
		t.Fatalf("正数 50 应扣到 -50，实为 %d", r.Score)
	}
	if r, _ := tbl.Get(negID); r.Score != -50 {
		t.Fatalf("负数 -50 应扣到 -50，实为 %d", r.Score)
	}
}

// ---------- 过期 ----------

func TestExpireRemovesStaleAddresses(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{AddrTTL: 100 * time.Millisecond})
	id := nid(0x81, 1)
	if err := tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"203.0.113.1:1"}, LastSeen: now}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if removed := tbl.Expire(now.Add(50 * time.Millisecond)); len(removed) != 0 {
		t.Fatalf("未过期不应移除，实为 %v", removed)
	}
	removed := tbl.Expire(now.Add(200 * time.Millisecond))
	if len(removed) != 1 || removed[0] != id {
		t.Fatalf("过期后应移除 %s，实为 %v", id.Short(), removed)
	}
	if _, ok := tbl.Get(id); ok {
		t.Fatal("Expire 后不应还能查到")
	}

	// Touch 会续期。
	id2 := nid(0x81, 2)
	if err := tbl.Upsert(NodeRecord{NodeID: id2, Addrs: []string{"203.0.114.1:1"}, LastSeen: now}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	tbl.Touch(id2, time.Millisecond, now.Add(80*time.Millisecond))
	if removed := tbl.Expire(now.Add(150 * time.Millisecond)); len(removed) != 0 {
		t.Fatalf("Touch 续期后不应被移除，实为 %v", removed)
	}
	if removed := tbl.Expire(now.Add(300 * time.Millisecond)); len(removed) != 1 || removed[0] != id2 {
		t.Fatalf("续期也过期后应移除，实为 %v", removed)
	}
}

// ---------- 参数校验与深拷贝 ----------

func TestUpsertValidation(t *testing.T) {
	tbl := NewTable(nid(0xAA), TableOptions{})
	if err := tbl.Upsert(NodeRecord{}); err == nil {
		t.Fatal("零 NodeID 应报错")
	}
	if err := tbl.Upsert(NodeRecord{NodeID: nid(0xAA)}); !errors.Is(err, ErrSelfPeer) {
		t.Fatalf("加入自身应返回 ErrSelfPeer，实为 %v", err)
	}
	if err := tbl.Upsert(NodeRecord{NodeID: nid(0x01), Pub: ed25519.PublicKey{1, 2, 3}}); err == nil {
		t.Fatal("非法公钥长度应报错")
	}
	if err := tbl.Upsert(NodeRecord{NodeID: nid(0x01), Pub: testPub(1)}); err != nil {
		t.Fatalf("合法公钥应被接受，实为 %v", err)
	}
}

func TestUpsertMergeAndGetReturnsClone(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{AddrTTL: time.Hour, MaxPerSubnet: 100})
	id := nid(0x91, 1)
	ann := &pb.NodeAnnounce{Seq: 7}
	if err := tbl.Upsert(NodeRecord{
		NodeID:   id,
		Pub:      testPub(9),
		Addrs:    []string{"203.0.113.1:1"},
		LastSeen: now,
		Score:    20,
		Outbound: true,
		Announce: ann,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// 用一条只带 LastSeen 的记录更新：其余字段应保留。
	if err := tbl.Upsert(NodeRecord{NodeID: id, LastSeen: now.Add(time.Minute)}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, ok := tbl.Get(id)
	if !ok {
		t.Fatal("记录应存在")
	}
	if got.Score != 20 || !got.Outbound || got.Announce.GetSeq() != 7 || len(got.Addrs) != 1 {
		t.Fatalf("更新不应抹掉既有字段: %+v", got)
	}
	if !got.LastSeen.Equal(now.Add(time.Minute)) {
		t.Fatalf("LastSeen 应被刷新，实为 %v", got.LastSeen)
	}
	// 返回深拷贝：改动返回值不得影响表内状态。
	got.Addrs[0] = "0.0.0.0:0"
	got.Announce.Seq = 999
	again, _ := tbl.Get(id)
	if again.Addrs[0] != "203.0.113.1:1" || again.Announce.GetSeq() != 7 {
		t.Fatalf("Get 应返回深拷贝，实为 %v seq=%d", again.Addrs, again.Announce.GetSeq())
	}

	tbl.Remove(id)
	if _, ok := tbl.Get(id); ok {
		t.Fatal("Remove 后不应还能查到")
	}
}

// ---------- 并发 ----------

func TestTableConcurrentOperations(t *testing.T) {
	now := time.Now()
	tbl := NewTable(zeroID(), TableOptions{K: 8, MaxPeers: 64, MaxPerSubnet: 4, AddrTTL: time.Hour})

	const workers = 8
	const iters = 300
	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < iters; i++ {
				id := nid(byte(0x80|w), byte(i%16+1), byte(i%251))
				switch i % 6 {
				case 0:
					_ = tbl.Upsert(NodeRecord{NodeID: id, Addrs: []string{"198.51.100." + string(rune('1'+i%9)) + ":1"}, LastSeen: now})
				case 1:
					tbl.Touch(id, time.Duration(i)*time.Millisecond, now)
				case 2:
					tbl.MarkFailure(id, now)
				case 3:
					tbl.Reward(id, 1)
				case 4:
					tbl.Penalize(id, 1, "concurrent")
				case 5:
					tbl.Remove(id)
				}
				_, _ = tbl.Get(id)
				_ = tbl.Closest(nid(byte(w)), 8)
				_ = tbl.Len()
				_ = tbl.NeedMorePeers()
				_ = tbl.Bucket(id)
				_ = tbl.EmptyBuckets()
				_ = tbl.IsBanned(id, now)
				_ = tbl.BannedUntil(id)
				_ = tbl.BannedCount()
				if i%50 == 0 {
					tbl.Expire(now.Add(time.Duration(i) * time.Hour))
				}
				_ = SubnetKey("203.0.113.7:7777")
			}
		}(w)
	}
	close(start)
	wg.Wait()
}
