package cli

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/directed"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
	"github.com/loongqing/FuturecastAlpha/internal/node"
	"github.com/loongqing/FuturecastAlpha/internal/nodefile"
	"github.com/loongqing/FuturecastAlpha/internal/peer"
	"github.com/loongqing/FuturecastAlpha/internal/registry"
	"github.com/loongqing/FuturecastAlpha/internal/store"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// expandHome 展开开头的 ~。
func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}

// buildNode 按配置创建节点（注入真实 store/peer）。
func buildNode(cfg nodefile.Config) (*node.Node, error) {
	return buildNodeWithIdentity(cfg, nil)
}

// buildNodeWithIdentity 允许注入一个显式身份（例如发布客户端的一次性身份）。
//
// identityOverride 非 nil 时优先使用它：发布客户端必须用一次性身份，
// 否则会与正在运行的节点共用配置里的 node_key_path，导致 node_id 相同、
// 握手被判为"自己连自己"，消息一条都发不出去。
func buildNodeWithIdentity(cfg nodefile.Config, identityOverride *identity.NodeIdentity) (*node.Node, error) {
	if cfg.AdminSetPath == "" {
		return nil, usageErrorf("配置缺少 admin_set_path（用 admin keygen 生成）")
	}
	genesis, err := loadAdminSet(expandHome(cfg.AdminSetPath))
	if err != nil {
		return nil, err
	}
	nc, err := cfg.ToNodeConfig()
	if err != nil {
		return nil, err
	}
	nc.NodeKeyPath = expandHome(nc.NodeKeyPath)

	id := identityOverride
	if id == nil {
		var err error
		id, err = identity.LoadOrCreateNodeIdentity(nc.NodeKeyPath)
		if err != nil {
			return nil, err
		}
	}
	var adminKeys []*identity.AdminKey
	for _, p := range cfg.AdminKeyPaths {
		k, err := identity.LoadAdminKey(expandHome(p))
		if err != nil {
			return nil, err
		}
		adminKeys = append(adminKeys, k)
	}
	n, err := node.New(node.Options{
		Config:    nc,
		Identity:  id,
		Genesis:   genesis,
		AdminKeys: adminKeys,
	})
	if err != nil {
		return nil, err
	}
	n.SetStore(store.New(housekitchen.DefaultDedupCapacity, time.Duration(housekitchen.DefaultMsgTTLNanos)))
	n.SetPeerTable(peer.NewTable(id.ID, peer.TableOptions{}))
	n.SetLimiterFactory(func() node.Limiter { return peer.NewLimiter(200, 400) })
	return n, nil
}

// cmdNode 启动一个节点并阻塞，直到收到 SIGINT/SIGTERM。
func cmdNode(args []string) error {
	fs := newFlagSet("node")
	configPath := fs.String("config", "", "配置文件路径（必填）")
	quiet := fs.Bool("quiet", false, "只输出关键事件")
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
	n, err := buildNode(cfg)
	if err != nil {
		return err
	}
	if cfg.TopicSecret == "" && (cfg.AdminMode == "sealed" || cfg.AdminMode == "signed") {
		fmt.Fprintln(os.Stderr, "⚠️  警告：admin_mode="+cfg.AdminMode+" 但未配置 topic_secret。")
		fmt.Fprintln(os.Stderr, "    此时 sealed 只隐藏“谁提交的”，**不隐藏内容** —— 任何节点都能读到明文并验证。")
		fmt.Fprintln(os.Stderr, "    若要真正的机密性，请配置 topic_secret。")
	}
	if !*quiet {
		n.OnMessage(func(env *pb.Envelope, v registry.Verification) {
			body := env.GetBody()
			marker := "·"
			if v.AdminAuthorized {
				marker = "★"
			}
			fmt.Printf("%s [%s] %s", marker, body.GetKind(), housekitchen.GetHash(env.GetMsgId()).Short())
			if t := body.GetTopic(); t != "" {
				fmt.Printf(" topic=%q", t)
			}
			if txt := body.GetPayload().GetText().GetBody(); txt != "" {
				fmt.Printf("  %s", txt)
			}
			if v.AdminAuthorized {
				fmt.Printf("  （管理员授权 %d 签：%s）", len(v.Signers), joinKeyIDs(v.Signers))
			}
			fmt.Println()
		})
		// 持有主题口令时，把封存消息的内层管理员正文解出来并明确标注。
		// 定向广播：只有本节点是收件人时才会触发这个回调。
		n.OnDirectedMessage(func(inner *pb.DirectedKernel, v directed.VerifyResult, outer *pb.Envelope) {
			fmt.Printf("🔒 [定向广播 · 你是收件人 · 管理员授权 %d 签：%s] %s",
				len(v.Signers), joinKeyIDs(v.Signers), inner.GetBody())
			if t := inner.GetTopic(); t != "" {
				fmt.Printf("   topic=%q", t)
			}
			fmt.Printf("   （msg_id %s）\n", housekitchen.GetHash(outer.GetMsgId()).Short())
		})
		n.OnSealedMessage(func(inner *pb.SignedBody, v registry.Verification, outer *pb.Envelope) {
			fmt.Printf("🔓 [封存已解封 · 管理员授权 %d/%d 签：%s] %s",
				len(v.Signers), inner.GetPolicy().GetTotal(), joinKeyIDs(v.Signers),
				inner.GetPayload().GetText().GetBody())
			if t := inner.GetTopic(); t != "" {
				fmt.Printf("   topic=%q", t)
			}
			fmt.Printf("   （外层由节点 %s 发布）\n", housekitchen.GetNodeID(outer.GetBody().GetAuthor()).Short())
		})
	}
	if err := n.Start(); err != nil {
		return err
	}
	defer n.Stop()

	gen, set := n.AdminSet()
	hash, _ := housekitchen.AdminSetHash(set)
	fmt.Printf("FutureCast 节点已启动\n")
	fmt.Printf("  node_id   = %s\n", n.ID())
	if addr := n.LocalAddr(); addr != "" {
		fmt.Printf("  监听      = %s（%s）\n", addr, cfg.Network)
	} else {
		fmt.Printf("  监听      = 无（%s 模式：只出站，不可被扫描）\n", cfg.AdminMode)
	}
	fmt.Printf("  超管模式  = %s\n", cfg.AdminMode)
	fmt.Printf("  验证级别  = %s\n", cfg.VerifyLevel)
	fmt.Printf("  管理员代数= %d（%d/%d）摘要 %s\n", gen, set.GetPolicy().GetThreshold(), set.GetPolicy().GetTotal(), hash.Short())
	fmt.Printf("  seed 地址 = %v（只需 1~3 个即可自动扩张）\n", cfg.Seeds)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\n收到退出信号，正在关闭…")
	return nil
}

// cmdStatus 打印一次节点状态快照后退出。
//
// 实现方式：启动节点、等待收敛、打印、退出。
// 这样无需常驻进程即可观察到邻居与代数，便于脚本与演示。
func cmdStatus(args []string) error {
	fs := newFlagSet("status")
	configPath := fs.String("config", "", "配置文件路径（必填）")
	wait := fs.Duration("wait", 3*time.Second, "收敛等待时间")
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
	// status 同样是临时客户端，用一次性身份以免与运行中的节点撞身份/端口。
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
	defer n.Stop()

	deadline := time.Now().Add(*wait)
	for time.Now().Before(deadline) {
		time.Sleep(150 * time.Millisecond)
	}
	gen, set := n.AdminSet()
	hash, _ := housekitchen.AdminSetHash(set)
	fmt.Printf("node_id    = %s\n", n.ID())
	fmt.Printf("listen     = %s\n", orNone(n.LocalAddr()))
	fmt.Printf("admin_mode = %s\n", cfg.AdminMode)
	fmt.Printf("admin_gen  = %d (%d/%d) %s\n", gen, set.GetPolicy().GetThreshold(), set.GetPolicy().GetTotal(), hash.Short())
	peers := n.Peers()
	fmt.Printf("peers      = %d\n", len(peers))
	for _, p := range peers {
		dir := "in "
		if p.Outbound {
			dir = "out"
		}
		fmt.Printf("  %s %s\n", dir, p.NodeID.Short())
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "（不监听）"
	}
	return s
}

// cmdPublish 发布一条消息。
//
//	public 模式：需要 --key 用管理员密钥签发（门限签名明文，人人可验）
//	sealed/signed：需要 --key 与可用网络连接，走封存投递
func cmdPublish(args []string) error {
	fs := newFlagSet("publish")
	configPath := fs.String("config", "", "配置文件路径（必填）")
	topic := fs.String("topic", "alerts", "主题")
	text := fs.String("text", "", "正文（必填）")
	ttl := fs.Duration("ttl", 7*24*time.Hour, "有效期")
	asNode := fs.Bool("as-node", false, "以普通节点身份发布（非管理员广播）")
	adminKeysFlag := fs.String("admin-keys", "", "管理员密钥文件，逗号分隔（覆盖配置里的 admin_key_paths）")
	noListen := fs.Bool("no-listen", true, "不监听端口（客户端模式；已有节点在跑同一配置时必须保持 true）")
	connectWait := fs.Duration("connect-wait", 10*time.Second, "等待连上节点的时间上限")
	directTo := fs.String("direct-to", "", "定向广播收件人 node_id，逗号分隔（支持唯一前缀）；留空则为普通广播")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *text == "" {
		return usageErrorf("必须提供 --config 与 --text")
	}
	cfg, err := nodefile.Load(*configPath)
	if err != nil {
		return err
	}
	if *noListen {
		// publish 是临时客户端：它只发布一条消息就退出。
		// 若沿用配置里的 listen，会与正在运行的节点抢占同一端口。
		//
		// 关键：如果配置里没有 seeds（典型情况是用种子节点自己的配置来发布），
		// 客户端就没有任何邻居可发，消息会被"接受但 0 个邻居转发"静默丢掉。
		// 因此这里把原 listen 地址当作要连接的目标 —— 也就是连到正在运行的那个节点。
		if len(cfg.Seeds) == 0 && cfg.Listen != "" {
			cfg.Seeds = []string{cfg.Listen}
			fmt.Fprintf(os.Stderr, "提示：配置未指定 seeds，将连接到本机节点 %s 进行发布\n", cfg.Listen)
		}
		cfg.Listen = ""
		cfg.MinPeers = 1
	}
	// 发布客户端使用一次性节点身份：它只是"送信人"，不需要也不应该
	// 长期占用节点身份；这样也彻底避免与运行中节点共用密钥的问题。
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
	defer n.Stop()

	// 发布是"一次性客户端"：必须等 dial 完成，否则消息会被
	// "接受但转发给 0 个邻居"静默丢掉 —— 这正是端到端演示里踩过的坑。
	if len(cfg.Seeds) > 0 {
		deadline := time.Now().Add(*connectWait)
		for time.Now().Before(deadline) && len(n.Peers()) == 0 {
			time.Sleep(100 * time.Millisecond)
		}
		if len(n.Peers()) == 0 {
			return fmt.Errorf("futurecast: %s 内未能连接任何节点（seeds=%v），消息未发布", *connectWait, cfg.Seeds)
		}
	}

	gen, set := n.AdminSet()
	now := time.Now()

	// ---- 定向广播：只有被点名的节点能解密 ----
	if strings.TrimSpace(*directTo) != "" {
		if len(cfg.AdminKeyPaths) == 0 && *adminKeysFlag == "" {
			return usageErrorf("定向广播需要 --admin-keys，或在配置里设置 admin_key_paths")
		}
		keyPaths := cfg.AdminKeyPaths
		if *adminKeysFlag != "" {
			keyPaths = splitNonEmpty(*adminKeysFlag)
		}
		var keys []*identity.AdminKey
		for _, p := range keyPaths {
			k, err := identity.LoadAdminKey(expandHome(p))
			if err != nil {
				return err
			}
			keys = append(keys, k)
		}
		th := int(set.GetPolicy().GetThreshold())
		if len(keys) < th {
			return usageErrorf("本地有 %d 把管理员密钥，门限要求 %d 把", len(keys), th)
		}
		rcpts, err := resolveRecipients(cfg, n, splitNonEmpty(*directTo))
		if err != nil {
			return err
		}
		body, err := directed.NewDirectedBody(set, rcpts, *topic, "text/plain", *text, now, *ttl)
		if err != nil {
			return err
		}
		canonical, err := directed.CanonicalForSigning(body)
		if err != nil {
			return err
		}
		if err := directed.Finalize(body, canonical, keys, th, now); err != nil {
			return err
		}
		// 本地自校验：连自己都验不过的信封绝不发出去。
		if _, err := directed.VerifyBody(body, set, now); err != nil {
			return fmt.Errorf("futurecast: 定向广播自校验失败，未发布: %w", err)
		}
		env := directed.Envelope(body, now)
		// 本地只落库、不重复转发（与 sealed 同理：PublishAndConfirm 负责转发一次）。
		return publishDirected(cfg, n, env, body)
	}

	if *asNode {
		payload := &pb.Payload{Payload: &pb.Payload_Text{Text: &pb.TextPayload{
			MediaType: "text/plain", Body: *text,
		}}}
		body, err := registry.NewNodeMessage(n.Identity(), pb.MessageKind_MESSAGE_KIND_ADMIN_BROADCAST,
			*topic, payload, set, *ttl, now)
		if err != nil {
			return err
		}
		canonical, err := registry.CanonicalForSigning(body)
		if err != nil {
			return err
		}
		if err := registry.FinalizeNodeBody(body, canonical, n.Identity(), now); err != nil {
			return err
		}
		env := registry.WrapEnvelope(body, now)
		ok, delivered := n.PublishAndConfirm(env, 1, 3*time.Second)
		if !ok {
			return fmt.Errorf("futurecast: 本地校验未通过，未发布")
		}
		if delivered == 0 {
			return fmt.Errorf("futurecast: 消息已接受，但没有任何邻居收到（连接可能已断开），未确认送达")
		}
		fmt.Printf("已以节点身份发布 msg_id=%s（确认送达 %d 个邻居）\n",
			housekitchen.GetHash(env.GetMsgId()).Short(), delivered)
		return nil
	}

	if len(cfg.AdminKeyPaths) == 0 && *adminKeysFlag == "" {
		return usageErrorf("管理员广播需要 --admin-keys，或在配置里设置 admin_key_paths")
	}
	keyPaths := cfg.AdminKeyPaths
	if *adminKeysFlag != "" {
		keyPaths = splitNonEmpty(*adminKeysFlag)
	}
	var adminKeys []*identity.AdminKey
	for _, p := range keyPaths {
		k, err := identity.LoadAdminKey(expandHome(p))
		if err != nil {
			return err
		}
		adminKeys = append(adminKeys, k)
	}
	th := int(set.GetPolicy().GetThreshold())
	if len(adminKeys) < th {
		return usageErrorf("本地有 %d 把管理员密钥，门限要求 %d 把", len(adminKeys), th)
	}
	body, err := registry.NewAdminBroadcast(set, *topic, *text, "text/plain", *ttl, now)
	if err != nil {
		return err
	}
	canonical, err := registry.CanonicalForSigning(body)
	if err != nil {
		return err
	}
	if err := registry.FinalizeAdminBody(body, canonical, adminKeys, th, now); err != nil {
		return err
	}
	env := registry.WrapEnvelope(body, now)
	msgID := housekitchen.GetHash(env.GetMsgId())

	if node.AdminMode(cfg.AdminMode) == node.AdminModePublic {
		// 必须等确认送达：一次性客户端发完即退出，不等确认会导致
		// PUSH 在途被连接关闭丢弃，而这里却报告"已广播"。
		ok, delivered := n.PublishAndConfirm(env, 1, 5*time.Second)
		if !ok {
			return fmt.Errorf("futurecast: 本地校验未通过，未发布")
		}
		if delivered == 0 {
			return fmt.Errorf("futurecast: 消息已接受，但 5s 内没有任何邻居收到确认 —— 未发布成功。" +
				"请检查 seeds 与网络连通性")
		}
		fmt.Printf("已广播（public 模式，门限签名明文，任何节点可验证）\n")
		fmt.Printf("  msg_id = %s\n  代数   = %d  签名 = %d/%d  确认送达 = %d 个邻居\n",
			msgID.Short(), gen, len(adminKeys), set.GetPolicy().GetTotal(), delivered)
		return nil
	}

	// signed / sealed：等待连上中继，然后封存投递。
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && len(n.Peers()) == 0 {
		time.Sleep(150 * time.Millisecond)
	}
	if len(n.Peers()) == 0 {
		return fmt.Errorf("futurecast: 15s 内没有连上任何中继，无法投递（检查 seeds 与网络）")
	}
	accepted, err := n.SubmitSealed(body)
	if err != nil {
		return err
	}
	// 安全关键：这里**只本地落库，不转发**。
	//
	// 若调用 n.Publish(env)，会把"明文 + 门限签名 + 超管所在节点"直接推给全网：
	// 内容保密性归零，同时把 sealed 超管暴露成一条普通的明文广播源。
	// sealed 模式下正式传播只走封存投递。
	n.PublishLocalOnly(env)
	// 给封存投递的中继一点时间把回执与副本真正发出。
	time.Sleep(300 * time.Millisecond)
	mode := cfg.AdminMode
	detail := "门限签名封存，仅持主题口令者可验证"
	if cfg.TopicSecret == "" {
		detail = "门限签名明文封存，任何节点可读（未配置 topic_secret）"
	}
	fmt.Printf("已投递（%s 模式）\n", mode)
	fmt.Printf("  msg_id   = %s\n  代数     = %d\n  中继受理 = %d 个\n  说明     = %s\n",
		msgID.Short(), gen, accepted, detail)
	if cfg.TopicSecret == "" {
		fmt.Fprintln(os.Stderr, "⚠️  未配置 topic_secret：sealed 只隐藏提交者，不隐藏内容。")
	}
	return nil
}

// cmdInit 生成一份可直接运行的节点配置。
func cmdInit(args []string) error {
	fs := newFlagSet("init")
	out := fs.String("config", "futurecast.json", "输出配置路径")
	mode := fs.String("mode", "public", "超管模式 public/signed/sealed")
	listen := fs.String("listen", "0.0.0.0:7777", "监听地址（sealed/signed 会被忽略）")
	seeds := fs.String("seeds", "", "种子地址，逗号分隔")
	adminSet := fs.String("admin-set", "", "AdminSet 文件路径")
	topic := fs.String("topic", "alerts", "主题")
	topicSecret := fs.String("topic-secret", "", "主题口令（sealed 建议设置）")
	keys := fs.String("admin-keys", "", "管理员密钥文件，逗号分隔（仅超管节点）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := nodefile.Default()
	cfg.AdminMode = *mode
	cfg.Listen = *listen
	// 关键：同一台机器上跑多个节点时，绝不能共用同一份节点身份密钥。
	// 默认路径是 ~/.futurecast/node.key，若三台节点都用它，它们会拥有同一个
	// node_id，握手时互判为"自己连自己"并拒绝，最终全网邻居数为 0。
	// 因此这里按监听端口派生独立密钥文件。
	if path := defaultNodeKeyPath(*listen, cfg.NodeKeyPath); path != "" {
		cfg.NodeKeyPath = path
	}
	cfg.Topics = []string{*topic}
	cfg.TopicSecret = *topicSecret
	cfg.AdminSetPath = *adminSet
	if *seeds != "" {
		cfg.Seeds = splitNonEmpty(*seeds)
	}
	if *keys != "" {
		cfg.AdminKeyPaths = splitNonEmpty(*keys)
	}
	if mode != nil && (*mode == "sealed" || *mode == "signed") {
		cfg.Listen = ""
	}
	if err := nodefile.Save(*out, cfg); err != nil {
		return err
	}
	fmt.Printf("已写出配置 %s\n", *out)
	fmt.Printf("  admin_mode = %s\n  listen     = %s\n  topics     = %v\n",
		cfg.AdminMode, orNone(cfg.Listen), cfg.Topics)
	if cfg.AdminSetPath == "" {
		fmt.Fprintln(os.Stderr, "\n⚠️  请用 --admin-set 指定 AdminSet（futurecast admin keygen 会生成）")
	}
	return nil
}

// defaultNodeKeyPath 由监听地址派生每节点独立的密钥路径。
//
// 约定：~/.futurecast/node-<port>.key；无法解析端口时退回原默认值。
func defaultNodeKeyPath(listen, fallback string) string {
	port := ""
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		port = listen[i+1:]
	}
	if port == "" || port == "0" {
		return fallback
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return fallback
		}
	}
	return "~/.futurecast/node-" + port + ".key"
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

var _ = context.Background
var _ ed25519.PublicKey
var _ *peer.Table
