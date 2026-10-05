package node_test

import (
	"testing"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/node"
)

// 回归守卫：一次性发布客户端必须确定送达。
//
// 真实 bug（§5.10 的根因之一）：CLI 的 publish 是"连上 → 发一条 → 立刻退出"。
// QUIC 的 WriteFrame 返回成功只代表帧进了发送缓冲，而进程退出时
// transport 用 CloseWithError 直接断开连接（等价于 CancelWrite），
// quic-go 明确说明这种情况下**已写入但未发出的数据不保证送达**。
// 结果：约 1/3 概率消息静默丢失，而调用方却报告"已发布"。
//
// 这里循环多次独立复现该场景，任何一次丢消息都必须让测试失败。
func TestOneShotPublisherAlwaysDelivers(t *testing.T) {
	const rounds = 8

	tn := newTestnet(t)
	seed := startNode(t, tn, "SEED", "127.0.0.1:0", node.AdminModePublic, nil, nil)
	seedAddr := addrOf(t, seed)
	relay := startNode(t, tn, "RELAY", "127.0.0.1:0", node.AdminModePublic, []string{seedAddr}, nil)
	waitFor(t, 15*time.Second, func() bool {
		return seed.peer.Len() >= 1 && relay.peer.Len() >= 1
	}, "种子与中继互连")

	for i := 0; i < rounds; i++ {
		// 每次一个全新的临时发布者：连上种子 → 发布 → **立刻停止**。
		pub := startNode(t, tn, "PUB", "", node.AdminModePublic, []string{seedAddr}, nil)
		waitFor(t, 15*time.Second, func() bool { return len(pub.Peers()) >= 1 }, "发布者连上种子")

		text := "一次性发布 " + time.Now().Format("150405.000000")
		env := signBroadcast(t, tn, 2, text)

		ok, delivered := pub.PublishAndConfirm(env, 1, 5*time.Second)
		if !ok {
			t.Fatalf("第 %d 轮：本地校验未通过", i)
		}
		if delivered == 0 {
			t.Fatalf("第 %d 轮：没有任何邻居确认收到", i)
		}
		// 关键：立刻停掉发布者。帧此时可能还在发送缓冲里。
		pub.Stop()

		msgID := env.GetMsgId().GetValue()
		id, err := hashFromBytes(msgID)
		if err != nil {
			t.Fatal(err)
		}
		waitFor(t, 10*time.Second, func() bool {
			_, ok := seed.realOrMemStore().Get(id)
			return ok
		}, "种子应收到一次性发布的消息（第 "+itoa(i)+" 轮）")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
