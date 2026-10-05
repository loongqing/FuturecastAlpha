package node_test

import (
	"testing"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/node"
	"github.com/loongqing/FuturecastAlpha/internal/peer"
	"github.com/loongqing/FuturecastAlpha/internal/store"
)

// 编译期断言：真实实现必须满足 node 包声明的契约接口。
//
// 这是防止"契约漂移"的守卫 —— node 包为避免被并行开发阻塞，
// 自己声明了 MessageStore / PeerTable 接口（Go 结构化类型）。
// 一旦 store/peer 的真实签名与 node 期望不一致，这里会直接编译失败，
// 而不是等到运行时接线才发现。
var (
	_ node.MessageStore = (*store.Store)(nil)
	_ node.PeerTable    = (*peer.Table)(nil)
	_ node.Limiter      = (*peer.Limiter)(nil)
)

// 真实实现接线后必须能正常收发一条广播。
func TestRealStoreAndPeerWiring(t *testing.T) {
	tn := newTestnet(t)

	a := startNodeWithRealDeps(t, tn, "A", "127.0.0.1:0", nil)
	aAddr := addrOf(t, a)
	b := startNodeWithRealDeps(t, tn, "B", "127.0.0.1:0", []string{aAddr})

	waitFor(t, 15*time.Second, func() bool {
		return a.realPeer.Len() >= 1 && b.realPeer.Len() >= 1
	}, "真实 store/peer 接入后 A/B 建立连接")

	env := signBroadcast(t, tn, 2, "真实存储接线验证")
	if !a.Publish(env) {
		t.Fatal("A 应接受本地发布")
	}
	waitFor(t, 10*time.Second, func() bool { return b.count() >= 1 }, "B 通过真实存储收到广播")

	// 真实 store 必须落盘且去重生效。
	msgID := env.GetMsgId().GetValue()
	id, err := hashFromBytes(msgID)
	if err != nil {
		t.Fatalf("解析 msg_id 失败: %v", err)
	}
	if _, ok := b.realStore.Get(id); !ok {
		t.Fatal("B 的真实 store 应已保存该消息")
	}
	if b.realStore.Seen(id, tn.clk.now()) {
		t.Fatal("同一 msg_id 第二次 Seen 必须返回 false")
	}
}
