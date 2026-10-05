package node_test

import (
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
	"github.com/loongqing/FuturecastAlpha/internal/node"
	"github.com/loongqing/FuturecastAlpha/internal/peer"
	"github.com/loongqing/FuturecastAlpha/internal/registry"
	"github.com/loongqing/FuturecastAlpha/internal/store"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

func cryptoEd25519ToX25519ForTest(pub ed25519.PublicKey) ([]byte, error) {
	return crypto.Ed25519ToX25519(pub)
}

const (
	testTopic       = "alerts"
	testTopicSecret = "correct-horse-battery-staple"
)

// ---------- 测试脚手架 ----------

type testnet struct {
	keyring *identity.Keyring
	set     *pb.AdminSet
	keys    []*identity.AdminKey
	now     time.Time
	clk     *clock
}

func newTestnet(t *testing.T) *testnet {
	t.Helper()
	kr := identity.NewKeyring()
	keys := make([]*identity.AdminKey, 0, 3)
	for _, lbl := range []string{"alice", "bob", "carol"} {
		k, err := identity.NewAdminKey(lbl, pb.AdminRole_ADMIN_ROLE_ROOT)
		if err != nil {
			t.Fatalf("生成管理员密钥失败: %v", err)
		}
		kr.Add(k)
		keys = append(keys, k)
	}
	set, err := kr.BuildAdminSet(1, 2, 3, "genesis")
	if err != nil {
		t.Fatalf("构建 AdminSet 失败: %v", err)
	}
	return &testnet{keyring: kr, set: set, keys: keys, now: time.Unix(1700000000, 0), clk: newClock(time.Unix(1700000000, 0))}
}

type testNode struct {
	*node.Node
	store *memStore
	peer  *memPeer
	// realStore / realPeer 仅在 startNodeWithRealDeps 下非 nil，
	// 用于验证"契约接口 ↔ 真实实现"的接线。
	realStore *store.Store
	realPeer  *peer.Table
	got       []*pb.Envelope
	gotV      []registry.Verification
	mu        sync.Mutex
}

func (tn *testNode) record(env *pb.Envelope, v registry.Verification) {
	tn.mu.Lock()
	defer tn.mu.Unlock()
	tn.got = append(tn.got, env)
	tn.gotV = append(tn.gotV, v)
}

func (tn *testNode) count() int {
	tn.mu.Lock()
	defer tn.mu.Unlock()
	return len(tn.got)
}

func (tn *testNode) messages() []*pb.Envelope {
	tn.mu.Lock()
	defer tn.mu.Unlock()
	return append([]*pb.Envelope(nil), tn.got...)
}

func (tn *testNode) verifications() []registry.Verification {
	tn.mu.Lock()
	defer tn.mu.Unlock()
	return append([]registry.Verification(nil), tn.gotV...)
}

// clock 是一个"固定起点 + 真实流逝"的单调时钟。
//
// 为什么不能用停止的时钟：封存中继依赖"抖动延迟到期后发布"，
// 如果时间不前进，publishAt 永远不会到期，测试会假死超时。
type clock struct {
	base time.Time
	t0   time.Time
}

func newClock(base time.Time) *clock     { return &clock{base: base, t0: time.Now()} }
func (c *clock) now() time.Time          { return c.base.Add(time.Since(c.t0)) }
func (c *clock) advance(d time.Duration) { c.t0 = c.t0.Add(-d) }

// startNode 启动一个测试节点。listen 为空表示不监听（sealed/signed 超管）。
func startNode(t *testing.T, tn *testnet, name string, listen string, mode node.AdminMode, seeds []string, adminKeys []*identity.AdminKey) *testNode {
	return startNodeAt(t, tn, name, listen, mode, seeds, adminKeys, tn.clk)
}

// startNodeNoSecret 启动一个**不带主题口令**的节点（用于验证中继的降级防护）。
func startNodeNoSecret(t *testing.T, tn *testnet, name, listen string, seeds []string) *testNode {
	t.Helper()
	id, err := identity.NewNodeIdentity()
	if err != nil {
		t.Fatalf("[%s] 生成节点身份失败: %v", name, err)
	}
	cfg := node.DefaultConfig()
	cfg.Listen = listen
	cfg.Seeds = seeds
	cfg.AdminMode = node.AdminModePublic
	cfg.VerifyLevel = node.VerifyStandard
	cfg.Topics = []string{testTopic}
	cfg.Relay.Enabled = true
	// 刻意不设 TopicSecret

	n, err := node.New(node.Options{
		Config:   cfg,
		Identity: id,
		Genesis:  tn.set,
		Now:      tn.clk.now,
		Logf:     func(f string, a ...any) { t.Logf("["+name+"] "+f, a...) },
	})
	if err != nil {
		t.Fatalf("[%s] 创建节点失败: %v", name, err)
	}
	store := newMemStore()
	peers := newMemPeer()
	n.SetStore(store)
	n.SetPeerTable(peers)
	n.SetLimiterFactory(func() node.Limiter { return &fakeLimiter{remaining: 100000} })
	n.Registry().SetTopicPolicy(&pb.TopicPolicy{
		Topic:       testTopic,
		WritePolicy: pb.WritePolicy_WRITE_POLICY_NODE_ALLOWED,
		ReadPolicy:  pb.ReadPolicy_READ_POLICY_PUBLIC,
	})
	tnNode := &testNode{Node: n, store: store, peer: peers}
	n.OnMessage(tnNode.record)
	if err := n.Start(); err != nil {
		t.Fatalf("[%s] 启动节点失败: %v", name, err)
	}
	t.Cleanup(n.Stop)
	return tnNode
}

// startNodeWithRealDeps 用 internal/store 与 internal/peer 的真实实现启动节点，
// 验证 node 包声明的契约接口与真实实现确实吻合。
func startNodeWithRealDeps(t *testing.T, tn *testnet, name, listen string, seeds []string) *testNode {
	t.Helper()
	id, err := identity.NewNodeIdentity()
	if err != nil {
		t.Fatalf("[%s] 生成节点身份失败: %v", name, err)
	}
	cfg := node.DefaultConfig()
	cfg.Listen = listen
	cfg.Seeds = seeds
	cfg.AdminMode = node.AdminModePublic
	cfg.VerifyLevel = node.VerifyStandard
	cfg.Topics = []string{testTopic}
	cfg.TopicSecret = testTopicSecret
	cfg.Relay.Enabled = true

	n, err := node.New(node.Options{
		Config:   cfg,
		Identity: id,
		Genesis:  tn.set,
		Now:      tn.clk.now,
		Logf:     func(f string, a ...any) { t.Logf("["+name+"] "+f, a...) },
	})
	if err != nil {
		t.Fatalf("[%s] 创建节点失败: %v", name, err)
	}
	st := store.New(housekitchen.DefaultDedupCapacity, 7*24*time.Hour)
	pt := peer.NewTable(id.ID, peer.TableOptions{})
	n.SetStore(st)
	n.SetPeerTable(pt)
	n.SetLimiterFactory(func() node.Limiter { return peer.NewLimiter(1000, 2000) })
	n.Registry().SetTopicPolicy(&pb.TopicPolicy{
		Topic:       testTopic,
		WritePolicy: pb.WritePolicy_WRITE_POLICY_NODE_ALLOWED,
		ReadPolicy:  pb.ReadPolicy_READ_POLICY_PUBLIC,
	})
	tnNode := &testNode{Node: n, realStore: st, realPeer: pt}
	n.OnMessage(tnNode.record)
	if err := n.Start(); err != nil {
		t.Fatalf("[%s] 启动节点失败: %v", name, err)
	}
	t.Cleanup(n.Stop)
	return tnNode
}

func startNodeAt(t *testing.T, tn *testnet, name string, listen string, mode node.AdminMode, seeds []string, adminKeys []*identity.AdminKey, clk *clock) *testNode {
	t.Helper()
	id, err := identity.NewNodeIdentity()
	if err != nil {
		t.Fatalf("[%s] 生成节点身份失败: %v", name, err)
	}
	cfg := node.DefaultConfig()
	cfg.Listen = listen
	cfg.Seeds = seeds
	cfg.AdminMode = mode
	cfg.VerifyLevel = node.VerifyStandard
	cfg.Topics = []string{testTopic}
	cfg.Relay.Enabled = true
	cfg.TopicSecret = testTopicSecret

	n, err := node.New(node.Options{
		Config:    cfg,
		Identity:  id,
		Genesis:   tn.set,
		AdminKeys: adminKeys,
		Now:       clk.now,
		Logf:      func(f string, a ...any) { t.Logf("["+name+"] "+f, a...) },
	})
	if err != nil {
		t.Fatalf("[%s] 创建节点失败: %v", name, err)
	}
	store := newMemStore()
	peers := newMemPeer()
	n.SetStore(store)
	_ = peers
	n.SetPeerTable(peers)
	n.SetLimiterFactory(func() node.Limiter { return &fakeLimiter{remaining: 100000} })
	// 模拟"管理员已广播过该主题策略"：允许节点写入，便于普通节点参与。
	n.Registry().SetTopicPolicy(&pb.TopicPolicy{
		Topic:       testTopic,
		WritePolicy: pb.WritePolicy_WRITE_POLICY_NODE_ALLOWED,
		ReadPolicy:  pb.ReadPolicy_READ_POLICY_PUBLIC,
	})
	tnNode := &testNode{Node: n, store: store, peer: peers}
	n.OnMessage(tnNode.record)
	if err := n.Start(); err != nil {
		t.Fatalf("[%s] 启动节点失败: %v", name, err)
	}
	t.Cleanup(n.Stop)
	return tnNode
}

// realOrMemStore 返回该测试节点的消息存储（真实或内存实现）。
func (tn *testNode) realOrMemStore() node.MessageStore {
	if tn.realStore != nil {
		return tn.realStore
	}
	return tn.store
}

// hashFromBytes 把 32 字节切片转成 housekitchen.Hash。
func hashFromBytes(b []byte) (housekitchen.Hash, error) { return housekitchen.HashFromBytes(b) }

func addrOf(t *testing.T, tn *testNode) string {
	t.Helper()
	a := tn.LocalAddr()
	if a == "" {
		t.Fatal("节点未监听，无法取地址")
	}
	return a
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, desc string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待超时（%s）：%s", timeout, desc)
}

// signBroadcast 用 n 把密钥签一条管理员广播。
func signBroadcast(t *testing.T, tn *testnet, n int, text string) *pb.Envelope {
	t.Helper()
	body, err := registry.NewAdminBroadcast(tn.set, testTopic, text, "text/plain", time.Hour, tn.now)
	if err != nil {
		t.Fatalf("组装广播失败: %v", err)
	}
	canonical, err := registry.CanonicalForSigning(body)
	if err != nil {
		t.Fatalf("规范化失败: %v", err)
	}
	if err := registry.FinalizeAdminBody(body, canonical, tn.keys[:n], n, tn.now); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	return registry.WrapEnvelope(body, tn.now)
}

// ---------- T1: 多节点广播必须全达 ----------

func TestBroadcastReachesAllNodes(t *testing.T) {
	tn := newTestnet(t)

	// A 作为种子（监听），B 与 C 通过 A 加入 —— 只给 1 个种子地址。
	a := startNode(t, tn, "A", "127.0.0.1:0", node.AdminModePublic, nil, nil)
	aAddr := addrOf(t, a)
	b := startNode(t, tn, "B", "127.0.0.1:0", node.AdminModePublic, []string{aAddr}, nil)
	c := startNode(t, tn, "C", "127.0.0.1:0", node.AdminModePublic, []string{aAddr}, nil)

	waitFor(t, 15*time.Second, func() bool {
		return a.peer.Len() >= 2 && b.peer.Len() >= 1 && c.peer.Len() >= 1
	}, "三个节点互相建立连接")

	env := signBroadcast(t, tn, 2, "请所有节点进入静默模式")
	if !a.Publish(env) {
		t.Fatal("节点 A 应接受本地发布的管理员广播")
	}

	waitFor(t, 10*time.Second, func() bool {
		return b.count() >= 1 && c.count() >= 1
	}, "广播到达 B 与 C")

	for _, n := range []*testNode{b, c} {
		v := n.verifications()[0]
		if !v.AdminAuthorized {
			t.Fatalf("节点收到的广播应标记为管理员授权")
		}
		if len(v.Signers) != 2 {
			t.Fatalf("应有 2 个有效签名者，实为 %d", len(v.Signers))
		}
		got := n.messages()[0].GetBody().GetPayload().GetText().GetBody()
		if got != "请所有节点进入静默模式" {
			t.Fatalf("正文不一致：%q", got)
		}
	}
}

// ---------- T2: 只有 1/3 签名必须被全网丢弃 ----------

func TestBelowThresholdRejectedOnWire(t *testing.T) {
	tn := newTestnet(t)
	a := startNode(t, tn, "A", "127.0.0.1:0", node.AdminModePublic, nil, nil)
	aAddr := addrOf(t, a)
	b := startNode(t, tn, "B", "127.0.0.1:0", node.AdminModePublic, []string{aAddr}, nil)
	waitFor(t, 15*time.Second, func() bool { return b.peer.Len() >= 1 }, "B 连上 A")

	// 1/3 签名的广播：A 自己就应该拒收，更不能转发出去。
	env := signBroadcast(t, tn, 1, "伪造广播")
	if a.Publish(env) {
		t.Fatal("门限不足的广播不应被接受")
	}
	time.Sleep(700 * time.Millisecond)
	if b.count() != 0 {
		t.Fatalf("门限不足的广播不应到达 B，实收 %d 条", b.count())
	}
}

// ---------- T3: 篡改一字节必须被丢弃 ----------

func TestTamperedBroadcastRejected(t *testing.T) {
	tn := newTestnet(t)
	a := startNode(t, tn, "A", "127.0.0.1:0", node.AdminModePublic, nil, nil)
	aAddr := addrOf(t, a)
	b := startNode(t, tn, "B", "127.0.0.1:0", node.AdminModePublic, []string{aAddr}, nil)
	waitFor(t, 15*time.Second, func() bool { return b.peer.Len() >= 1 }, "B 连上 A")

	env := signBroadcast(t, tn, 2, "原始内容")
	env.Body.Payload.GetText().Body = "篡改后的内容" // msg_id 不再匹配
	if a.Publish(env) {
		t.Fatal("被篡改的广播不应被接受")
	}
	time.Sleep(700 * time.Millisecond)
	if b.count() != 0 {
		t.Fatalf("被篡改的广播不应到达 B，实收 %d 条", b.count())
	}
}

// findSealed 在已收消息中找到第一条封存消息。
func findSealed(tn *testNode) *pb.Envelope {
	for _, e := range tn.messages() {
		if e.GetBody().GetKind() == pb.MessageKind_MESSAGE_KIND_SEALED {
			return e
		}
	}
	return nil
}

// ---------- T4: sealed 模式 —— 中继转发，公网看不到超管 ----------

func TestSealedRelayEndToEnd(t *testing.T) {
	tn := newTestnet(t)

	// R 是中继（普通监听节点）。
	relay := startNode(t, tn, "R", "127.0.0.1:0", node.AdminModePublic, nil, nil)
	relayAddr := addrOf(t, relay)

	// S 是订阅者，通过中继加入网络。
	sub := startNode(t, tn, "S", "127.0.0.1:0", node.AdminModePublic, []string{relayAddr}, nil)
	waitFor(t, 15*time.Second, func() bool { return sub.peer.Len() >= 1 && relay.peer.Len() >= 1 }, "订阅者连上中继")

	// ADMIN 是 sealed 超管：不监听任何端口，只主动出站连中继。
	admin := startNode(t, tn, "ADMIN", "", node.AdminModeSealed, []string{relayAddr}, tn.keys[:1])
	waitFor(t, 15*time.Second, func() bool { return len(admin.Peers()) >= 1 }, "sealed 超管连上中继")

	// 测试辅助：核对双方由 ed25519 派生出的 X25519 公钥。
	adminPub := admin.IdentityPublic()
	relayPub := relay.IdentityPublic()
	ax, _ := cryptoEd25519ToX25519ForTest(adminPub)
	rx, _ := cryptoEd25519ToX25519ForTest(relayPub)
	t.Logf("ADMIN ed25519=%x -> x25519=%x", adminPub, ax)
	t.Logf("RELAY ed25519=%x -> x25519=%x", relayPub, rx)

	if admin.LocalAddr() != "" {
		t.Fatal("sealed 超管不应监听任何端口")
	}

	// 超管签名后走封存投递。
	env := signBroadcast(t, tn, 2, "封存广播：进入静默模式")
	body := env.GetBody()
	if accepted, err := admin.SubmitSealed(body); err != nil || accepted == 0 {
		t.Fatalf("封存投递失败：accepted=%d err=%v", accepted, err)
	}

	// 订阅者应收到一条**中继签名的普通节点消息**（类型为 SEALED）。
	// 注意：订阅者会先收到中继的 NODE_ANNOUNCE，所以必须按类型等待，
	// 不能只等"收到任意消息"。
	waitFor(t, 20*time.Second, func() bool { return findSealed(sub) != nil }, "订阅者收到中继发布的封存消息")

	msg := findSealed(sub)
	if msg.GetBody().GetKind() != pb.MessageKind_MESSAGE_KIND_SEALED {
		t.Fatalf("期望 SEALED 类型，实为 %s", msg.GetBody().GetKind())
	}
	if got := housekitchen.GetNodeID(msg.GetBody().GetAuthor()); got != relay.ID() {
		t.Fatalf("外层作者应是中继 %s，实为 %s", relay.ID().Short(), got.Short())
	}
	if got := housekitchen.GetNodeID(msg.GetBody().GetAuthor()); got == admin.ID() {
		t.Fatal("外层绝不能暴露超管身份")
	}
	// 外层不能含任何跨副本共享的明文字段（否则可关联出中继）
	sp := msg.GetBody().GetPayload().GetSealed()
	if len(sp.GetCiphertext()) != 0 || sp.GetEpoch() != 0 || len(sp.GetEphemeralX25519()) != 0 {
		t.Fatal("发布通道的封存载荷不得携带提交通道字段")
	}
	if len(sp.GetInnerCiphertext()) == 0 {
		t.Fatal("配置了主题口令时，内层正文必须是密文（否则 sealed 不提供内容保密）")
	}
	if len(sp.GetInnerBody()) != 0 {
		t.Fatal("加密模式下不得同时携带内层明文")
	}

	// 订阅者解封：必须验证出 2/3 管理员授权。
	inner, v, err := sub.Unseal(msg)
	if err != nil {
		t.Fatalf("解封失败: %v", err)
	}
	if !v.AdminAuthorized {
		t.Fatal("解封后应确认为管理员授权")
	}
	if got := inner.GetPayload().GetText().GetBody(); got != "封存广播：进入静默模式" {
		t.Fatalf("内层正文不一致：%q", got)
	}
	if inner.GetTopic() != testTopic {
		t.Fatalf("内层主题不一致：%q", inner.GetTopic())
	}
}

// ---------- T5: 同一条消息从两个方向到达，只接受一次 ----------

func TestDuplicateSuppressed(t *testing.T) {
	tn := newTestnet(t)
	a := startNode(t, tn, "A", "127.0.0.1:0", node.AdminModePublic, nil, nil)
	aAddr := addrOf(t, a)
	b := startNode(t, tn, "B", "127.0.0.1:0", node.AdminModePublic, []string{aAddr}, nil)
	waitFor(t, 15*time.Second, func() bool { return a.peer.Len() >= 1 && b.peer.Len() >= 1 }, "A/B 互连")

	env := signBroadcast(t, tn, 2, "只应出现一次")
	if !b.Publish(env) {
		t.Fatal("B 应接受本地发布")
	}
	waitFor(t, 10*time.Second, func() bool { return a.count() >= 1 }, "A 收到广播")
	// 再次从同一条消息投递（模拟另一条路径回环）
	if b.Publish(env) {
		t.Fatal("重复消息不应被重复接受")
	}
	time.Sleep(500 * time.Millisecond)
	if a.count() != 1 {
		t.Fatalf("A 应只接受一次，实为 %d 次", a.count())
	}
}
