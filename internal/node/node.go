// Package node 把信任层、传播层、发现层、传输层组装成一个可运行的节点。
//
// 数据流：
//
//	收到帧 → 校验(registry) → 去重(store) → 落盘 → PUSH 给 fanout 个邻居
//	                                    ↘ 每 3s 对每个 topic 发 INV，邻居回 GET 补齐
//
// 封存流（sealed 超管）：
//
//	超管出站连中继 → SealedSubmit → 中继解封校验 → 抖动后用自己的身份重新签名发布
package node

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/codec"
	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/directed"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
	"github.com/loongqing/FuturecastAlpha/internal/registry"
	"github.com/loongqing/FuturecastAlpha/internal/sealed"
	"github.com/loongqing/FuturecastAlpha/internal/transport"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// Node 是一个运行中的 FutureCast 节点。
type Node struct {
	cfg      Config
	id       *identity.NodeIdentity
	reg      *registry.Registry
	store    MessageStore
	peers    PeerTable
	limiter  func() Limiter
	tr       *transport.Transport
	mailbox  *sealed.Mailbox
	duty     *sealed.RelayDuty
	adminKey *identity.AdminKey
	topicKey []byte
	x25519   crypto.X25519KeyPair
	now      func() time.Time
	rnd      *rand.Rand
	rndMu    sync.Mutex

	mu      sync.Mutex
	conns   map[housekitchen.NodeID]*transport.Conn
	sess    map[housekitchen.NodeID]Session
	dialing map[string]bool
	// lastUp 记录每个种子地址最近一次"连接建立成功"的时间。
	// 用于抑制重连风暴：节点间一旦建立连接，若对端也同时连过来，
	// 两边会各自重连，形成指数级连接抖动。
	lastUp  map[string]time.Time
	started bool
	// connEstablished 统计累计建立成功的连接数。
	// 它的用途是暴露"重连风暴"：稳定网络下这个数应当收敛，
	// 而不是随时间线性增长。
	connEstablished uint64
	// 传播统计，用于量化"消息到底有没有被转出去"，
	// 以及暴露 push 丢失后 anti-entropy 是否补上。
	statRelayNoTarget uint64
	statPushOK        uint64
	statPushFail      uint64
	statInvSent       uint64
	statGetRequested  uint64
	// statBlockedPlaintextAdmin 是被保密性闸门拦下的明文管理员广播次数。
	statBlockedPlaintextAdmin uint64
	stopCh                    chan struct{}
	syncCh                    chan struct{}
	wg                        sync.WaitGroup
	logf                      func(string, ...any)
	handlers                  []func(*pb.Envelope, registry.Verification)
	sealedHandlers            []func(inner *pb.SignedBody, v registry.Verification, outer *pb.Envelope)
	directedHandlers          []func(inner *pb.DirectedKernel, v directed.VerifyResult, outer *pb.Envelope)

	// sealed 超管的待发布队列：中继解封后延迟发布。
	pendingMu sync.Mutex
	pending   []pendingSealed
}

type pendingSealed struct {
	body      *pb.SignedBody
	publishAt time.Time
}

// Session 是一条已建立连接的会话信息。
type Session struct {
	NodeID   housekitchen.NodeID
	Pub      ed25519.PublicKey
	Conn     *transport.Conn
	Outbound bool
}

// New 创建一个节点实例（尚未开始网络活动）。
func New(opts Options) (*Node, error) {
	cfg := opts.Config
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	id := opts.Identity
	if id == nil {
		if cfg.NodeKeyPath == "" {
			return nil, fmt.Errorf("futurecast: 必须提供 Identity 或 NodeKeyPath")
		}
		var err error
		id, err = identity.LoadOrCreateNodeIdentity(cfg.NodeKeyPath)
		if err != nil {
			return nil, err
		}
	}
	if opts.Genesis == nil {
		return nil, fmt.Errorf("futurecast: 必须提供创世 AdminSet")
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	reg, err := registry.New(opts.Genesis, registry.Options{Now: nowFn})
	if err != nil {
		return nil, err
	}
	var seed int64
	if opts.RandomSeed != 0 {
		seed = opts.RandomSeed
	} else {
		seed = int64(housekitchen.RandomUint64())
	}
	logf := opts.Logf
	if logf == nil {
		logf = log.Printf
	}
	xk, err := crypto.GenerateX25519()
	if err != nil {
		return nil, err
	}
	n := &Node{
		cfg:     cfg,
		id:      id,
		reg:     reg,
		tr:      nil,
		mailbox: sealed.NewMailbox(cfg.Relay.MailboxCapacity, cfg.Relay.MailboxTTL),
		duty:    sealed.NewRelayDuty(&pb.RelayPolicy{Mandatory: cfg.Relay.Enabled, PerInboxQuota: uint32(cfg.Relay.MailboxCapacity), MinJitterMs: uint32(cfg.Relay.SealedJitterMin / time.Millisecond), MaxJitterMs: uint32(cfg.Relay.SealedJitterMax / time.Millisecond)}),
		x25519:  xk,
		now:     nowFn,
		rnd:     rand.New(rand.NewSource(seed)),
		conns:   map[housekitchen.NodeID]*transport.Conn{},
		sess:    map[housekitchen.NodeID]Session{},
		dialing: map[string]bool{},
		lastUp:  map[string]time.Time{},
		stopCh:  make(chan struct{}),
		syncCh:  make(chan struct{}, 1),
		logf:    logf,
	}
	if len(opts.AdminKeys) > 0 {
		n.adminKey = opts.AdminKeys[0]
	}
	if cfg.TopicSecret != "" {
		topic := ""
		if len(cfg.Topics) > 0 {
			topic = cfg.Topics[0]
		}
		key, err := sealed.DeriveTopicKey(cfg.TopicSecret, topic)
		if err != nil {
			return nil, err
		}
		n.topicKey = key
	}
	// 创世 AdminSet 里内嵌的主题策略直接生效（相当于"已随创世分发"）。
	for _, tp := range opts.Genesis.GetTopicPolicies() {
		reg.SetTopicPolicy(tp)
	}
	return n, nil
}

// SetStore 注入消息存储（由 cmd 层在创建时提供）。
func (n *Node) SetStore(s MessageStore) { n.store = s }

// SetPeerTable 注入节点表。
func (n *Node) SetPeerTable(t PeerTable) { n.peers = t }

// SetLimiterFactory 注入每连接限速器工厂。
func (n *Node) SetLimiterFactory(f func() Limiter) { n.limiter = f }

// ID 返回本节点标识。
func (n *Node) ID() housekitchen.NodeID { return n.id.ID }

// Registry 暴露管理员集合注册表（只读用途）。
func (n *Node) Registry() *registry.Registry { return n.reg }

// OnMessage 注册收到合法消息时的回调（用于 CLI 展示）。
func (n *Node) OnMessage(f func(*pb.Envelope, registry.Verification)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.handlers = append(n.handlers, f)
}

// OnDirectedMessage 注册"本节点是定向广播收件人且成功解密"的回调。
//
// 只有被点名的节点会触发 —— 这是定向广播与普通广播在节点层的唯一分水岭：
// 其他节点同样会转发并验证它确实来自超管，但永远读不到正文。
func (n *Node) OnDirectedMessage(f func(inner *pb.DirectedKernel, v directed.VerifyResult, outer *pb.Envelope)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.directedHandlers = append(n.directedHandlers, f)
}

// DirectedDecrypt 尝试以本节点身份解密一条定向广播。
//
// 不是收件人时返回的 error 包装 ErrNotAuthorized —— 这是网络上的常态，不是故障。
func (n *Node) DirectedDecrypt(env *pb.Envelope) (*directed.OpenResult, error) {
	body := env.GetDirectedBody()
	if body == nil {
		return nil, fmt.Errorf("%w: 不是定向广播", housekitchen.ErrDirectedInvalid)
	}
	return directed.Open(n.id.KeySeed, n.id.ID, body)
}

// OnSealedMessage 注册"成功解开封存消息"的回调。
//
// 只有在节点持有主题口令时才会触发 —— 这正是 sealed 模式的可验证范围：
// 没有口令的节点只能看到"某节点发布了一条密文消息"，无法判定它来自超管。
func (n *Node) OnSealedMessage(f func(inner *pb.SignedBody, v registry.Verification, outer *pb.Envelope)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sealedHandlers = append(n.sealedHandlers, f)
}

// Debugf 返回本节点的日志函数（测试诊断用）。
func (n *Node) Debugf() func(string, ...any) { return n.logf }

// Start 启动监听与全部后台循环。
func (n *Node) Start() error {
	n.mu.Lock()
	if n.started {
		n.mu.Unlock()
		return fmt.Errorf("futurecast: 节点已启动")
	}
	n.started = true
	n.mu.Unlock()

	tr, err := transport.New(transport.Options{
		Network:    n.cfg.Network,
		Listen:     n.cfg.Listen,
		CommonName: n.id.ID.Short(),
	})
	if err != nil {
		return err
	}
	n.tr = tr
	if tr.Listening() {
		n.logf("futurecast: 节点 %s 监听 %s（%s）", n.id.ID.Short(), tr.LocalAddr(), n.cfg.Network)
		n.spawn(n.acceptLoop)
	} else {
		n.logf("futurecast: 节点 %s 不监听端口（%s 模式：只出站）", n.id.ID.Short(), n.cfg.AdminMode)
	}
	for _, seed := range n.cfg.Seeds {
		if seed != "" {
			n.spawn(func() { n.dialLoop(seed) })
		}
	}
	n.spawn(n.gossipLoop)
	n.spawn(n.invLoop)
	n.spawn(n.gcLoop)
	if n.cfg.Relay.Enabled {
		n.spawn(n.relayPublishLoop)
	}
	return nil
}

// Stop 优雅停止节点。
func (n *Node) Stop() {
	n.mu.Lock()
	if !n.started {
		n.mu.Unlock()
		return
	}
	n.started = false
	select {
	case <-n.stopCh:
	default:
		close(n.stopCh)
	}
	conns := make([]*transport.Conn, 0, len(n.conns))
	for _, c := range n.conns {
		conns = append(conns, c)
	}
	n.mu.Unlock()

	for _, c := range conns {
		_ = c.WriteFrame(codec.NewBye("shutdown"))
	}
	// 必须"先写后优雅关"：直接 Close 会丢弃仍在发送缓冲里的帧
	// （包括刚写进去的 PUSH 与 Bye），一次性发布客户端会因此静默丢消息。
	for _, c := range conns {
		_ = c.CloseGraceful(150 * time.Millisecond)
	}
	if n.tr != nil {
		_ = n.tr.Close()
	}
	n.wg.Wait()
}

// spawn 启动一个受 WaitGroup 跟踪的后台循环。
func (n *Node) spawn(f func()) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		f()
	}()
}

// stopped 返回是否已请求停止。
func (n *Node) stopped() bool {
	select {
	case <-n.stopCh:
		return true
	default:
		return false
	}
}

// sleep 可被停止打断的等待。
func (n *Node) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-n.stopCh:
		return false
	case <-t.C:
		return true
	}
}

func (n *Node) randInt(max int) int {
	if max <= 0 {
		return 0
	}
	n.rndMu.Lock()
	defer n.rndMu.Unlock()
	return n.rnd.Intn(max)
}

// ---------- 连接管理 ----------

func (n *Node) connCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.conns)
}

func (n *Node) registerConn(s Session) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.conns[s.NodeID] = s.Conn
	n.sess[s.NodeID] = s
}

func (n *Node) unregisterConn(id housekitchen.NodeID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.conns, id)
	delete(n.sess, id)
}

// sessions 返回当前会话快照。
func (n *Node) sessions() []Session {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]Session, 0, len(n.sess))
	for _, s := range n.sess {
		out = append(out, s)
	}
	return out
}

// Peers 返回当前邻居的简要信息，供 status 命令使用。
func (n *Node) Peers() []Session { return n.sessions() }

// KnownNodes 返回节点表中已知的全部节点（含间接节点与它们的公钥）。
//
// 用途：定向广播要求超管能拿到收件人的 ed25519 公钥，而收件人往往并不与
// 超管直连。节点表里保存的是握手已证实/邻居通告过的公钥，是唯一可靠来源。
func (n *Node) KnownNodes() []PeerRecord {
	if n.peers == nil {
		return nil
	}
	return n.peers.All()
}

// DiscoverAndRecord 主动向邻居要一轮节点列表，并把已知节点的公钥写入 path。
//
// 返回写入的条目数。地址簿格式为 JSON：{ "peers": { "<node_id_hex>": "<ed25519_pub_b64>" } }
func (n *Node) DiscoverAndRecord(path string) error {
	// 向每个邻居发一轮 FIND_NODE（目标取本节点，对端会回一批它已知的节点）。
	for _, s := range n.sessions() {
		_ = s.Conn.WriteFrame(codec.NewFindNode(n.id.ID, 32))
	}
	// 给对端一点时间回 NODES 帧。
	if !n.sleep(800 * time.Millisecond) {
		return nil
	}
	all := n.KnownNodes()
	book := map[string]string{}
	for _, rec := range all {
		if len(rec.Pub) == 0 {
			continue
		}
		// 自己的记录不是"收件人备选"，写进地址簿只会让 --direct-to 误选自己。
		if rec.NodeID == n.id.ID {
			continue
		}
		book[rec.NodeID.String()] = base64.StdEncoding.EncodeToString(rec.Pub)
	}
	raw, err := json.MarshalIndent(map[string]any{"peers": book}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// LocalAddr 返回监听地址；未监听（sealed/signed 超管）返回空字符串。
func (n *Node) LocalAddr() string {
	if n.tr == nil || !n.tr.Listening() {
		return ""
	}
	if a := n.tr.LocalAddr(); a != nil {
		return a.String()
	}
	return ""
}

// Publish 接受一条本地产出的消息（管理员广播或节点消息）并开始传播。
//
// 本地消息同样要过完整校验管线 —— 本地不是特权路径，
// 否则一个错误的签发流程会在网络上造成"只有自己认"的假象。
func (n *Node) Publish(env *pb.Envelope) bool {
	ok, _ := n.publish(env)
	return ok
}

// PublishAndConfirm 发布并等待确认消息至少被推给 wait 个邻居。
//
// 提供这个方法是必须的：一次性发布客户端（CLI 的 publish）发完就退出，
// 若不等确认，PUSH 帧可能还在 QUIC 缓冲里连接就被关闭，消息静默丢失，
// 而调用方却报告"已发布"。这在真实运行中被稳定复现过。
func (n *Node) PublishAndConfirm(env *pb.Envelope, want int, wait time.Duration) (bool, int) {
	ok, delivered := n.publish(env)
	if !ok {
		return false, 0
	}
	// 同步补发：在窗口内反复重发，不依赖调用方进程继续存活。
	//
	// 为什么必须同步：QUIC 的帧写入是异步的，一次 WriteFrame 返回成功只代表
	// "已交给发送缓冲"，不代表对端已收到。一次性客户端（CLI publish）随进程退出，
	// 后台补发 goroutine 根本没机会运行 —— 实测这正是消息偶发丢失的主因。
	//
	// 重发代价很低（对端按 msg_id 去重），换来的是一次性发布路径的确定性送达。
	deadline := time.Now().Add(wait)
	const minRounds = 4
	rounds := 0
	for {
		rounds++
		if d := n.relayStatsForce(env); d > delivered {
			delivered = d
		}
		if delivered >= want && rounds >= minRounds {
			break
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(120 * time.Millisecond)
	}
	n.syncNow()
	return true, delivered
}

// relayStatsForce 再次尝试转发（用于确认等待期间补发）。
func (n *Node) relayStatsForce(env *pb.Envelope) int { return n.relayStats(env) }

// PublishDirected 接受并转发一条定向广播，等待确认至少 want 个邻居收到。
//
// 定向广播的被签名对象是 DirectedBody，与 SignedBody 不是同一套结构，
// 因此不能复用 accept()/registry.VerifyMessage；这里走 directed 的独立校验路径。
// 校验包含：内容寻址、时间窗、代数与集合绑定、以及**超管门限签名** ——
// 全程不需要解密正文，这正是"中继可验签但读不到内容"的实现基础。
func (n *Node) PublishDirected(env *pb.Envelope, want int, wait time.Duration) (bool, int) {
	body := env.GetDirectedBody()
	if body == nil {
		return false, 0
	}
	set, ok := n.reg.SetForGeneration(body.GetAdminSetGeneration())
	if !ok {
		n.logf("futurecast: 定向广播声明的代数 %d 本地不认识", body.GetAdminSetGeneration())
		return false, 0
	}
	if _, err := directed.VerifyBody(body, set, n.now()); err != nil {
		n.logf("futurecast: 定向广播校验失败：%v", err)
		return false, 0
	}
	msgID := housekitchen.GetHash(env.GetMsgId())
	if n.store != nil {
		if !n.store.Seen(msgID, n.now()) {
			return false, 0
		}
		if err := n.store.Put(env, n.now()); err != nil {
			n.logf("futurecast: 定向广播落库失败：%v", err)
			return false, 0
		}
	}
	// 本地收件人也要能解出来（超管自己可能就是收件人）。
	n.onDirected(env)
	delivered := n.relayStats(env)
	if delivered < want {
		deadline := time.Now().Add(wait)
		for time.Now().Before(deadline) && delivered < want {
			time.Sleep(25 * time.Millisecond)
			delivered = n.relayStats(env)
		}
	}
	n.syncNow()
	return true, delivered
}

// PublishLocalOnly 只做校验与本地落库，**不向任何邻居转发**。
//
// 用途：sealed 模式下超管不应把自己的明文管理员广播直接推给网络 ——
// 那会同时破坏内容保密（全网都能读到明文）与发送方匿名（暴露超管所在机器）。
// 超管只需要本地留一份记录，正式传播走封存投递。
func (n *Node) PublishLocalOnly(env *pb.Envelope) bool {
	if env == nil {
		return false
	}
	self := Session{NodeID: n.id.ID, Pub: n.id.Pub}
	v, err := n.verify(self, env)
	if err != nil {
		n.logf("futurecast: 本地消息校验失败：%v", err)
		return false
	}
	msgID := housekitchen.GetHash(env.GetMsgId())
	if n.store != nil {
		if !n.store.Seen(msgID, n.now()) {
			return false
		}
		if err := n.store.Put(env, n.now()); err != nil {
			n.logf("futurecast: 本地落库失败：%v", err)
			return false
		}
	}
	n.mu.Lock()
	hs := append([]func(*pb.Envelope, registry.Verification){}, n.handlers...)
	n.mu.Unlock()
	for _, h := range hs {
		h(env, v)
	}
	return true
}

// publish 是 Publish 的内部实现，额外返回成功推送给邻居的数量。
func (n *Node) publish(env *pb.Envelope) (bool, int) {
	if env == nil {
		return false, 0
	}
	self := Session{NodeID: n.id.ID, Pub: n.id.Pub}
	return n.acceptAndRelay(self, env, "local")
}

// Identity 返回本节点身份（供 CLI 签发节点消息使用）。
func (n *Node) Identity() *identity.NodeIdentity { return n.id }

// IdentityPublic 返回本节点 ed25519 公钥（诊断与测试用）。
func (n *Node) IdentityPublic() ed25519.PublicKey { return n.id.Pub }

// AdminSet 返回当前代数与管理员集合。
func (n *Node) AdminSet() (uint64, *pb.AdminSet) { return n.reg.Current() }

// ---------- 握手 ----------

func (n *Node) buildHello() (*pb.Hello, error) {
	gen, set := n.reg.Current()
	setHash, err := housekitchen.AdminSetHash(set)
	if err != nil {
		return nil, err
	}
	var addrs []string
	if !n.cfg.AdminMode.HidesAddress() && n.tr != nil && n.tr.Listening() {
		addrs = append(addrs, n.tr.LocalAddr().String())
	}
	h := &pb.Hello{
		ProtoVersion:       housekitchen.ProtoVersion,
		MinProto:           housekitchen.MinProtoVersion,
		NodeId:             housekitchen.PBNodeID(n.id.ID),
		PublicKey:          &pb.PubKey{Ed25519: n.id.Pub},
		ListenAddrs:        addrs,
		AdminSetHash:       housekitchen.PBHash(setHash),
		AdminSetGeneration: gen,
		IssuedAtUnixNanos:  n.now().UnixNano(),
		Nonce:              housekitchen.RandomUint64(),
	}
	sig, err := n.id.SignHello(h)
	if err != nil {
		return nil, err
	}
	h.SelfSignature = sig
	return h, nil
}

// handshake 完成入站或出站连接的握手。outbound 表示本端是否主动发起。
func (n *Node) handshake(c *transport.Conn, outbound bool) (Session, error) {
	hello, err := n.buildHello()
	if err != nil {
		return Session{}, err
	}
	if err := c.WriteFrame(codec.NewHello(hello)); err != nil {
		return Session{}, fmt.Errorf("futurecast: 发送 HELLO 失败: %w", err)
	}
	f, err := c.ReadFrame()
	if err != nil {
		return Session{}, fmt.Errorf("futurecast: 等待 HELLO 失败: %w", err)
	}
	peerHello := f.GetHello()
	if peerHello == nil {
		return Session{}, fmt.Errorf("futurecast: 握手首帧不是 HELLO，实为 %s", codec.KindName(f))
	}
	if peerHello.GetProtoVersion() < housekitchen.MinProtoVersion {
		return Session{}, fmt.Errorf("%w: 对端协议版本 %d", housekitchen.ErrProtocolVersion, peerHello.GetProtoVersion())
	}
	if err := identity.VerifyHello(peerHello); err != nil {
		return Session{}, err
	}
	peerID := housekitchen.GetNodeID(peerHello.GetNodeId())
	if peerID == n.id.ID {
		return Session{}, fmt.Errorf(
			"futurecast: 对端与本节点 node_id 相同（%s）—— 通常意味着两个节点共用了同一份身份密钥文件 %s；"+
				"请为每个节点设置独立的 node_key_path", peerID.Short(), n.cfg.NodeKeyPath)
	}
	// 对端声明了管理员代数：若不匹配只需记录（它的消息会各自被校验拒绝）。
	if peerHello.GetAdminSetGeneration() != 0 {
		if _, ok := n.reg.SetAt(peerHello.GetAdminSetGeneration()); !ok {
			n.logf("futurecast: 警告：对端 %s 声明代数 %d，本地不认识", peerID.Short(), peerHello.GetAdminSetGeneration())
		}
	}
	pub := ed25519.PublicKey(peerHello.GetPublicKey().GetEd25519())
	sess := Session{NodeID: peerID, Pub: pub, Conn: c, Outbound: outbound}

	if n.peers != nil {
		addrs := peerHello.GetListenAddrs()
		if len(addrs) == 0 {
			addrs = []string{c.RemoteAddr.String()}
		}
		_ = n.peers.Upsert(PeerRecord{
			NodeID: peerID, Pub: pub, Addrs: addrs,
			LastSeen: n.now(), Outbound: outbound,
		})
	}
	// PING 探测一次，用于初始化延迟。
	nonce := housekitchen.RandomUint64()
	if err := c.WriteFrame(codec.NewPing(nonce, n.now().UnixNano())); err != nil {
		return Session{}, err
	}
	n.registerConn(sess)
	sentAt := n.now()
	for {
		pf, err := c.ReadFrame()
		if err != nil {
			n.unregisterConn(peerID)
			return Session{}, fmt.Errorf("futurecast: 等待 PONG 失败: %w", err)
		}
		if pong := pf.GetPong(); pong != nil && pong.GetNonce() == nonce {
			if n.peers != nil {
				n.peers.Touch(peerID, n.now().Sub(sentAt), n.now())
			}
			break
		}
		// 握手期间可能先收到别的帧（例如对端同时发 PING），处理掉继续等。
		n.handleFrame(sess, pf)
	}
	n.mu.Lock()
	n.connEstablished++
	n.mu.Unlock()
	n.logf("futurecast: 与 %s 建立连接（%s，%s）", peerID.Short(), c.Network, dirLabel(outbound))
	return sess, nil
}

// Stats 是传播层的累计计数，用于诊断与测试。
type Stats struct {
	// RelayNoTarget 是有消息要转发、但当前一个邻居都没有的次数。
	RelayNoTarget uint64
	// PushOK / PushFail 是 PUSH 发送成功 / 失败的次数。
	PushOK, PushFail uint64
	// InvSent 是发出的 INV 轮数；GetRequested 是因 INV 缺口而请求的消息条数。
	InvSent      uint64
	GetRequested uint64
	// BlockedPlaintextAdmin 是被"保密性闸门"拦下的明文管理员广播次数。
	// 该值应恒为 0；非 0 说明有代码路径试图在 sealed/signed 模式下明文外发广播。
	BlockedPlaintextAdmin uint64
}

// Stats 返回传播统计快照。
func (n *Node) Stats() Stats {
	n.mu.Lock()
	defer n.mu.Unlock()
	return Stats{
		RelayNoTarget:         n.statRelayNoTarget,
		PushOK:                n.statPushOK,
		PushFail:              n.statPushFail,
		InvSent:               n.statInvSent,
		GetRequested:          n.statGetRequested,
		BlockedPlaintextAdmin: n.statBlockedPlaintextAdmin,
	}
}

// ConnectionsEstablished 返回累计成功建立的连接数（含重复连接）。
//
// 稳定网络中这个数字应当收敛；若它持续线性增长，说明节点间存在
// "互相重连"的风暴，需要检查 dialLoop 的冷却逻辑。
func (n *Node) ConnectionsEstablished() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.connEstablished
}

func dirLabel(outbound bool) string {
	if outbound {
		return "出站"
	}
	return "入站"
}

// acceptLoop 接受入站连接。
func (n *Node) acceptLoop() {
	for !n.stopped() {
		ctx, cancel := contextWithTimeout(n.stopCh, 2*time.Second)
		c, err := n.tr.Accept(ctx)
		cancel()
		if err != nil {
			if n.stopped() {
				return
			}
			continue
		}
		if n.connCount() >= n.cfg.MaxPeers {
			_ = c.WriteFrame(codec.NewBye("peer limit reached"))
			_ = c.Close()
			continue
		}
		n.spawn(func() { n.serveConn(c, false) })
	}
}

// serveConn 完成握手并进入帧处理循环。
func (n *Node) serveConn(c *transport.Conn, outbound bool) {
	sess, err := n.handshake(c, outbound)
	if err != nil {
		if !n.stopped() {
			n.logf("futurecast: 握手失败（%s）：%v", c.RemoteAddr, err)
		}
		_ = c.Close()
		return
	}
	defer func() {
		n.unregisterConn(sess.NodeID)
		_ = c.Close()
	}()
	var lim Limiter
	if n.limiter != nil {
		lim = n.limiter()
	}
	for !n.stopped() {
		f, err := c.ReadFrame()
		if err != nil {
			if !n.stopped() && !isClosedErr(err) {
				n.logf("futurecast: 与 %s 的连接结束：%v", sess.NodeID.Short(), err)
			}
			return
		}
		if lim != nil && !lim.Allow(1, n.now()) {
			if n.peers != nil {
				if banned := n.peers.Penalize(sess.NodeID, -20, "rate limit exceeded"); banned {
					n.logf("futurecast: 节点 %s 超速，已临时封禁", sess.NodeID.Short())
					return
				}
			}
			continue
		}
		n.handleFrame(sess, f)
	}
}

// stableAfter 是"这条连接算稳定"的存活时长阈值。
const stableAfter = 5 * time.Second

// lastUpTime 返回某地址最近一次建连成功的时间。
func (n *Node) lastUpTime(addr string) time.Time {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.lastUp[addr]
}

// dialLoop 维持与某个种子地址的连接。
func (n *Node) dialLoop(addr string) {
	backoff := 500 * time.Millisecond
	for !n.stopped() {
		if n.connCount() >= n.cfg.MaxPeers {
			if !n.sleep(2 * time.Second) {
				return
			}
			continue
		}
		n.mu.Lock()
		busy := n.dialing[addr]
		if !busy {
			n.dialing[addr] = true
		}
		n.mu.Unlock()
		if busy {
			if !n.sleep(time.Second) {
				return
			}
			continue
		}
		// 刚刚建过连（例如对端同时连过来并已完成握手），不要重复建连。
		if since := n.now().Sub(n.lastUpTime(addr)); since >= 0 && since < stableAfter {
			n.mu.Lock()
			delete(n.dialing, addr)
			n.mu.Unlock()
			if !n.sleep(stableAfter - since) {
				return
			}
			continue
		}
		ctx, cancel := contextWithTimeout(n.stopCh, 10*time.Second)
		c, err := n.tr.Dial(ctx, addr)
		cancel()
		n.mu.Lock()
		delete(n.dialing, addr)
		n.mu.Unlock()
		if err != nil {
			if !n.stopped() {
				n.logf("futurecast: 连接种子 %s 失败：%v（%s 后重试）", addr, err, backoff)
			}
			if !n.sleep(backoff) {
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		n.mu.Lock()
		n.lastUp[addr] = n.now()
		n.mu.Unlock()
		n.serveConn(c, true)

		// 抑制重连风暴：若这条连接存活超过 stableAfter，
		// 说明它是一次正常断线，短暂冷却后重连即可；
		// 若秒断，说明两端在互相重复建连，需要更长的退避。
		lifetime := n.now().Sub(n.lastUpTime(addr))
		n.mu.Lock()
		delete(n.lastUp, addr)
		n.mu.Unlock()
		if lifetime > stableAfter {
			if !n.sleep(stableAfter) {
				return
			}
			continue
		}
		if !n.sleep(backoff) {
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, transport.ErrClosed) {
		return true
	}
	s := err.Error()
	return contains(s, "closed") || contains(s, "EOF") || contains(s, "reset")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
