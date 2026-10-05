package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/directed"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
	"github.com/loongqing/FuturecastAlpha/internal/node"
	"github.com/loongqing/FuturecastAlpha/internal/nodefile"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// recipientBookName 是本地收件人地址簿文件名。
//
// 为什么需要它：定向广播要求超管知道收件人的 ed25519 公钥，而网络里
// 可见的只有 node_id。地址簿把"见过的节点"的 node_id → 公钥 记下来，
// 让超管可以在离线状态下组装定向广播。
const recipientBookName = "recipients.json"

// recipientBook 是 node_id → 公钥 的本地映射。
type recipientBook struct {
	// Peers 按 node_id 十六进制索引。
	Peers map[string]string `json:"peers"` // node_id(hex) -> ed25519 公钥(base64)
}

func bookPath(cfg nodefile.Config) string {
	dir := filepath.Dir(expandHome(cfg.AdminSetPath))
	if dir == "" || dir == "." {
		return recipientBookName
	}
	return filepath.Join(dir, recipientBookName)
}

// loadBook 读取地址簿，不存在时返回空簿。
func loadBook(path string) (*recipientBook, error) {
	book := &recipientBook{Peers: map[string]string{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return book, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, book); err != nil {
		return nil, fmt.Errorf("futurecast: 解析收件人地址簿失败: %w", err)
	}
	if book.Peers == nil {
		book.Peers = map[string]string{}
	}
	return book, nil
}

// saveBook 写回地址簿（0600）。
func saveBook(path string, book *recipientBook) error {
	raw, err := json.MarshalIndent(book, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// rememberPeers 把当前在线节点的 node_id → 公钥 记入地址簿。
func rememberPeers(path string, n *node.Node) error {
	book, err := loadBook(path)
	if err != nil {
		return err
	}
	for _, s := range n.Peers() {
		book.Peers[s.NodeID.String()] = base64.StdEncoding.EncodeToString(s.Pub)
	}
	return saveBook(path, book)
}

// collectBook 搜集已知节点的公钥：直连邻居 + 向邻居问来的一轮节点列表。
//
// 语义上与节点侧一致：**只要见过一次就记下来**，因为定向广播要求超管
// 在离线状态下也能组装收件人集合。
func collectBook(n *node.Node) (*recipientBook, error) {
	book := &recipientBook{Peers: map[string]string{}}
	for _, s := range n.Peers() {
		book.Peers[s.NodeID.String()] = base64.StdEncoding.EncodeToString(s.Pub)
	}
	for _, rec := range n.KnownNodes() {
		if len(rec.Pub) == 0 {
			continue
		}
		book.Peers[rec.NodeID.String()] = base64.StdEncoding.EncodeToString(rec.Pub)
	}
	return book, nil
}

// resolveRecipients 把 --direct-to 里的 node_id 列表解析成收件人集合。
//
// 解析优先级：当前在线邻居 → 本地地址簿。
// 找不到公钥时**必须报错**而不是静默跳过 —— 静默跳过会让超管以为
// "发给了三个人"，实际只发给了两个。
func resolveRecipients(cfg nodefile.Config, n *node.Node, ids []string) ([]directed.Recipient, error) {
	book, err := loadBook(bookPath(cfg))
	if err != nil {
		return nil, err
	}
	// 在线邻居优先（拿到的是握手已证实的公钥）。
	online := map[string][]byte{}
	for _, s := range n.Peers() {
		online[s.NodeID.String()] = s.Pub
	}
	// 顺带把在线邻居补进地址簿，供离线组装时使用。
	if err := rememberPeers(bookPath(cfg), n); err != nil {
		return nil, err
	}

	var out []directed.Recipient
	seen := map[string]bool{}
	for _, raw := range ids {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// 允许写前 8 位短 ID，但必须在地址簿/在线列表里唯一匹配。
		full, err := matchNodeID(raw, online, book)
		if err != nil {
			return nil, err
		}
		if seen[full] {
			continue // 去重：同一个人写两次只留一个槽位
		}
		seen[full] = true

		id, err := housekitchen.NodeIDFromHex(full)
		if err != nil {
			return nil, fmt.Errorf("futurecast: 非法 node_id %q: %w", full, err)
		}
		pub := online[full]
		if len(pub) == 0 {
			decoded, err := base64.StdEncoding.DecodeString(book.Peers[full])
			if err != nil {
				return nil, fmt.Errorf("futurecast: 地址簿里 %s 的公钥无法解析: %w", full, err)
			}
			pub = decoded
		}
		if housekitchen.NodeIDFromPub(pub) != id {
			return nil, fmt.Errorf("futurecast: %s 的公钥与 node_id 不匹配（地址簿可能已过期）", full[:8])
		}
		out = append(out, directed.Recipient{NodeID: id, Ed25519Pub: pub})
	}
	if len(out) == 0 {
		return nil, usageErrorf("--direct-to 没有解析出任何有效收件人")
	}
	return out, nil
}

// matchNodeID 把可能是短 ID 的输入解析成完整 node_id 十六进制串。
func matchNodeID(raw string, online map[string][]byte, book *recipientBook) (string, error) {
	raw = strings.ToLower(strings.TrimPrefix(raw, "0x"))
	if len(raw) == housekitchen.NodeIDSize*2 {
		return raw, nil
	}
	var matches []string
	for id := range online {
		if strings.HasPrefix(id, raw) {
			matches = append(matches, id)
		}
	}
	for id := range book.Peers {
		if strings.HasPrefix(id, raw) {
			matches = append(matches, id)
		}
	}
	uniq := map[string]bool{}
	for _, m := range matches {
		uniq[m] = true
	}
	switch len(uniq) {
	case 0:
		return "", fmt.Errorf("futurecast: 找不到 node_id 前缀 %q 对应的节点（用 `futurecast peers` 查看已知节点）", raw)
	case 1:
		for m := range uniq {
			return m, nil
		}
	}
	return "", fmt.Errorf("futurecast: node_id 前缀 %q 匹配到 %d 个节点，请写完整 node_id", raw, len(uniq))
}

// cmdPeers 列出已知节点及其完整 node_id，便于复制到 --direct-to。
func cmdPeers(args []string) error {
	fs := newFlagSet("peers")
	configPath := fs.String("config", "", "配置文件路径（必填）")
	wait := fs.Duration("wait", 3*time.Second, "收敛等待时间")
	offline := fs.Bool("offline", false, "只读本地地址簿，不启动节点")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return usageErrorf("必须提供 --config")
	}
	cfg, err := nodefile.Load(*configPath)
	if err != nil {
		return err
	}
	book, err := loadBook(bookPath(cfg))
	if err != nil {
		return err
	}
	if !*offline {
		// 与 publish 同样的道理：配置里没有 seeds 时，把自身 listen 当作要连的节点。
		if len(cfg.Seeds) == 0 && cfg.Listen != "" {
			cfg.Seeds = []string{cfg.Listen}
		}
		cfg.Listen = ""
		cfg.MinPeers = 1
		ephemeral, err := identity.NewNodeIdentity()
		if err != nil {
			return err
		}
		n, err := buildNodeWithIdentity(cfg, ephemeral)
		if err != nil {
			return err
		}
		if err := n.Start(); err != nil {
			return err
		}
		// 等连上，并主动向对端要一轮节点列表：
		// 只记"直连邻居"是不够的 —— 网络上绝大多数节点并不与超管直连，
		// 而定向广播的收件人完全可能是那些间接节点。
		deadline := time.Now().Add(*wait)
		for time.Now().Before(deadline) {
			time.Sleep(150 * time.Millisecond)
		}
		if err := n.DiscoverAndRecord(bookPath(cfg)); err != nil {
			n.Stop()
			return err
		}
		fmt.Println("== 本次直连到的邻居 ==")
		for _, s := range n.Peers() {
			fmt.Printf("  %s\n", s.NodeID)
		}
		n.Stop()
		book, _ = loadBook(bookPath(cfg))
	}
	fmt.Println("== 本地地址簿（可直接用于 --direct-to）==")
	if len(book.Peers) == 0 {
		fmt.Println("  （空：先跑一次 `futurecast peers --config <cfg>` 让节点上线采集）")
		return nil
	}
	ids := make([]string, 0, len(book.Peers))
	for id := range book.Peers {
		ids = append(ids, id)
	}
	sortStrings(ids)
	for _, id := range ids {
		fmt.Printf("  %s\n", id)
	}
	fmt.Printf("\n用法示例：--direct-to %s\n", strings.Join(ids[:minInt(2, len(ids))], ","))
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// publishDirected 执行一次定向广播发布。
func publishDirected(cfg nodefile.Config, n *node.Node, env *pb.Envelope, body *pb.DirectedBody) error {
	ok, delivered := n.PublishDirected(env, 1, 5*time.Second)
	if !ok {
		return fmt.Errorf("futurecast: 本地校验未通过，未发布")
	}
	if delivered == 0 {
		return fmt.Errorf("futurecast: 消息已接受，但 5s 内没有邻居确认收到 —— 未发布成功")
	}
	fmt.Printf("已发布定向广播（%d 名收件人）\n", len(body.GetRecipients()))
	fmt.Printf("  msg_id    = %s\n", housekitchen.GetHash(env.GetMsgId()).Short())
	fmt.Printf("  收件人槽位 = %d（名单已隐藏，只有收件人能认出自己）\n", len(body.GetRecipients()))
	fmt.Printf("  确认送达   = %d 个邻居\n", delivered)
	fmt.Println("  说明：全网节点都能验证“这确实来自超管”，但只有被点名的节点能解出正文。")
	return nil
}
