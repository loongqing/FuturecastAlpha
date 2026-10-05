package node_test

import (
	"testing"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/node"
)

// 统计形态的消息传播：node2/node3 只连 node1，广播从 node1 发起。
//
// 这个测试同时验证两件事：
//  1. 消息确实到达了每一个节点；
//  2. 如果 PUSH 阶段有丢失，anti-entropy（INV/GET）必须把它补上 —— 这是
//     "最终一致"承诺的核心，不能只靠一次 PUSH 的运气。
func TestBroadcastReachesAllNodesReliably(t *testing.T) {
	for round := 0; round < 5; round++ {
		tn := newTestnet(t)
		n1 := startNode(t, tn, "n1", "127.0.0.1:0", node.AdminModePublic, nil, nil)
		a1 := addrOf(t, n1)
		n2 := startNode(t, tn, "n2", "127.0.0.1:0", node.AdminModePublic, []string{a1}, nil)
		n3 := startNode(t, tn, "n3", "127.0.0.1:0", node.AdminModePublic, []string{a1}, nil)

		waitFor(t, 15*time.Second, func() bool {
			return n1.peer.Len() >= 2 && n2.peer.Len() >= 1 && n3.peer.Len() >= 1
		}, "三节点互连")

		// 发布方是一个临时节点：它连上 n1 后立即发布，然后马上断开。
		// 这模拟真实 CLI 的 publish（一次性客户端），也是 PUSH 最容易丢的场景。
		pub := startNode(t, tn, "pub", "", node.AdminModePublic, []string{a1}, nil)
		waitFor(t, 15*time.Second, func() bool { return len(pub.Peers()) >= 1 }, "发布方连上 n1")

		env := signBroadcast(t, tn, 2, "可靠性验证")
		if !pub.Publish(env) {
			t.Fatalf("第 %d 轮：发布方应接受本地消息", round)
		}
		pub.Stop() // 立刻断开：此时 PUSH 可能还在途

		waitFor(t, 20*time.Second, func() bool {
			return n2.count() >= 1 && n3.count() >= 1
		}, "两个远端节点都收到广播")
	}
}
