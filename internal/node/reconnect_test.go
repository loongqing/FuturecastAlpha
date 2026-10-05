package node_test

import (
	"testing"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/node"
)

// 稳定网络里绝不能出现重连风暴。
//
// 这个测试锁住一个真实出现过的 bug：两个节点各自把对方当种子，
// dialLoop 在连接被对端关闭后立刻重连，两边反复重复建连，
// 3 个节点几秒内就产生了 18 次建连。
func TestNoReconnectStorm(t *testing.T) {
	tn := newTestnet(t)

	a := startNode(t, tn, "A", "127.0.0.1:0", node.AdminModePublic, nil, nil)
	aAddr := addrOf(t, a)

	// B、C 都把 A 当种子；A 不把任何人当种子。
	b := startNode(t, tn, "B", "127.0.0.1:0", node.AdminModePublic, []string{aAddr}, nil)
	c := startNode(t, tn, "C", "127.0.0.1:0", node.AdminModePublic, []string{aAddr}, nil)

	waitFor(t, 15*time.Second, func() bool {
		return a.peer.Len() >= 2 && b.peer.Len() >= 1 && c.peer.Len() >= 1
	}, "三个节点建立连接")

	// 让网络充分运行，观察建连计数是否收敛。
	time.Sleep(6 * time.Second)

	total := a.ConnectionsEstablished() + b.ConnectionsEstablished() + c.ConnectionsEstablished()
	// 正常情况下：A 接受 2 条入站 + B/C 各 1 条出站 = 4 次建连。
	// 允许少量重连（例如握手竞态），但绝不能是持续增长的数量级。
	if total > 12 {
		t.Fatalf("疑似重连风暴：6 秒内累计建连 %d 次（A=%d B=%d C=%d）",
			total, a.ConnectionsEstablished(), b.ConnectionsEstablished(), c.ConnectionsEstablished())
	}
	t.Logf("6 秒内累计建连 %d 次（A=%d B=%d C=%d）", total,
		a.ConnectionsEstablished(), b.ConnectionsEstablished(), c.ConnectionsEstablished())

	// 连接数应保持稳定，不应出现塌缩。
	if a.peer.Len() < 2 {
		t.Fatalf("A 的邻居数不应下降到 2 以下，实为 %d", a.peer.Len())
	}
}
