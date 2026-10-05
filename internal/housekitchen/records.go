package housekitchen

import (
	"crypto/ed25519"
	"time"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// NodeRecord 描述路由表/地址簿中的一个节点。
//
// 放在 housekitchen 而不是 peer 或 node：它是两个包的**共享数据契约**。
// node 声明 PeerTable 接口时需要引用它，而 node 不应导入 peer（避免反向依赖
// 与潜在循环）；peer 也不应导入 node。下沉到共同底座是唯一无环的解法。
type NodeRecord struct {
	NodeID    NodeID
	Pub       ed25519.PublicKey
	Addrs     []string
	LastSeen  time.Time
	Failures  int
	Score     int
	LatencyMS int64
	Outbound  bool
	Announce  *pb.NodeAnnounce // 最近一次已验签的动态
}
