package node_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/node"
)

// 定向广播要求超管能拿到**收件人的公钥**，而收件人往往不与超管直连。
// 因此必须能通过一轮 FIND_NODE/NODES 学到间接节点及其公钥。
func TestDiscoveryLearnsIndirectPeerKeys(t *testing.T) {
	tn := newTestnet(t)

	seed := startNode(t, tn, "SEED", "127.0.0.1:0", node.AdminModePublic, nil, nil)
	seedAddr := addrOf(t, seed)
	// 两个节点直连种子。
	p1 := startNode(t, tn, "P1", "127.0.0.1:0", node.AdminModePublic, []string{seedAddr}, nil)
	p2 := startNode(t, tn, "P2", "127.0.0.1:0", node.AdminModePublic, []string{seedAddr}, nil)
	waitFor(t, 15*time.Second, func() bool {
		return seed.peer.Len() >= 2 && p1.peer.Len() >= 1 && p2.peer.Len() >= 1
	}, "两个节点接入种子")

	// 第三个节点只连种子，它应当能通过 NODES 学到 P1/P2。
	probe := startNode(t, tn, "PROBE", "127.0.0.1:0", node.AdminModePublic, []string{seedAddr}, nil)
	waitFor(t, 15*time.Second, func() bool { return len(probe.Peers()) >= 1 }, "探针连上种子")

	dir := t.TempDir()
	book := filepath.Join(dir, "recipients.json")
	if err := probe.DiscoverAndRecord(book); err != nil {
		t.Fatalf("DiscoverAndRecord 失败: %v", err)
	}
	raw, err := os.ReadFile(book)
	if err != nil {
		t.Fatalf("地址簿未写出: %v", err)
	}
	t.Logf("地址簿条目数（应含 3 个节点）:\n%s", raw)
	// 至少要包含探针之外的 3 个节点（seed/p1/p2）。
	for _, id := range []string{seed.ID().String(), p1.ID().String(), p2.ID().String()} {
		if !contains(raw, id) {
			t.Fatalf("地址簿缺少节点 %s（间接节点公钥未被学到）", id[:8])
		}
	}
}

func contains(b []byte, s string) bool {
	return len(s) > 0 && len(b) >= len(s) && indexOf(string(b), s) >= 0
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// 种子侧必须持有直连节点的公钥 —— 否则它无法通过 NODES 把公钥传给第三方。
func TestSeedHoldsDirectPeerKeys(t *testing.T) {
	tn := newTestnet(t)
	seed := startNode(t, tn, "SEED", "127.0.0.1:0", node.AdminModePublic, nil, nil)
	seedAddr := addrOf(t, seed)
	p1 := startNode(t, tn, "P1", "127.0.0.1:0", node.AdminModePublic, []string{seedAddr}, nil)
	waitFor(t, 15*time.Second, func() bool { return seed.peer.Len() >= 1 }, "P1 接入种子")
	time.Sleep(500 * time.Millisecond)

	got := seed.KnownNodes()
	t.Logf("种子已知 %d 条记录", len(got))
	found := false
	for _, r := range got {
		t.Logf("  %s pub=%d addrs=%v", r.NodeID.Short(), len(r.Pub), r.Addrs)
		if r.NodeID == p1.ID() {
			found = true
			if len(r.Pub) == 0 {
				t.Fatal("种子持有直连节点记录但没有公钥")
			}
		}
	}
	if !found {
		t.Fatal("种子看不到直连节点")
	}
}
