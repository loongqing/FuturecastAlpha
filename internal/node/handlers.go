package node

import (
	"context"
	"fmt"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/codec"
	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/directed"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
	"github.com/loongqing/FuturecastAlpha/internal/registry"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// contextWithTimeout 返回一个在 stopCh 关闭或超时后取消的 context。
func contextWithTimeout(stopCh <-chan struct{}, d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	go func() {
		select {
		case <-stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// handleFrame 按帧类型分发处理。
func (n *Node) handleFrame(sess Session, f *pb.Frame) {
	switch body := f.GetBody().(type) {
	case *pb.Frame_Ping:
		_ = sess.Conn.WriteFrame(codec.NewPong(body.Ping.GetNonce(), n.now().UnixNano()))

	case *pb.Frame_Pong:
		if n.peers != nil {
			n.peers.Touch(sess.NodeID, 0, n.now())
		}

	case *pb.Frame_FindNode:
		n.onFindNode(sess, body.FindNode)

	case *pb.Frame_Nodes:
		n.onNodes(body.Nodes)

	case *pb.Frame_PeerExchange:
		n.onPeerExchange(sess, body.PeerExchange)

	case *pb.Frame_Push:
		n.onPush(sess, body.Push.GetEnvelope())

	case *pb.Frame_Inv:
		n.onInv(sess, body.Inv)

	case *pb.Frame_Get:
		n.onGet(sess, body.Get)

	case *pb.Frame_Msg:
		for _, env := range body.Msg.GetEnvelopes() {
			n.onPush(sess, env)
		}

	case *pb.Frame_SealedSubmit:
		n.onSealedSubmit(sess, body.SealedSubmit)

	case *pb.Frame_MailboxGet:
		n.onMailboxGet(sess, body.MailboxGet)

	case *pb.Frame_MailboxStore:
		n.onMailboxStore(sess, body.MailboxStore)

	case *pb.Frame_GetContent:
		n.onGetContent(sess, body.GetContent)

	case *pb.Frame_ContentChunk:
		n.onContentChunk(sess, body.ContentChunk)

	case *pb.Frame_Bye:
		_ = sess.Conn.Close()

	case *pb.Frame_Error:
		n.logf("futurecast: 对端 %s 返回错误：%s", sess.NodeID.Short(), body.Error.GetMessage())
	}
}

// onDirected 处理一条定向广播。
//
// 关键：**任何节点都能验证它确实来自超管**（外层明文 + 门限签名），
// 但只有被点名的收件人能解出正文。中继因此可以在完全不解密的前提下
// 参与转发 —— 这是把"可验签外层"与"机密内层"分开的直接收益。
func (n *Node) onDirected(env *pb.Envelope) bool {
	body := env.GetDirectedBody()
	if body == nil {
		return false
	}

	_, set := n.reg.Current()
	if set == nil {
		return false
	}
	if _, err := directed.VerifyBody(body, set, n.now()); err != nil {
		n.logf("futurecast: 丢弃定向广播 %s：%v", housekitchen.GetHash(env.GetMsgId()).Short(), err)
		return false
	}
	v := directed.VerifyResult{Generation: body.GetAdminSetGeneration()}
	res, err := n.DirectedDecrypt(env)
	if err != nil {
		// 绝大多数节点走这里：不是收件人。
		// 这不是错误 —— 它们仍然完成了门限验签并继续转发，只是读不到内容。
		// 记一条不含任何内容的回执行，便于运营侧确认"消息确实到了，只是打不开"。
		n.logf("futurecast: 定向广播 %s 已验签并转发（本节点非收件人，无法解密）",
			housekitchen.GetHash(env.GetMsgId()).Short())
		return true
	}
	n.logf("futurecast: 定向广播 %s 解密成功（本节点是收件人，槽位 %d，代数 %d）",
		housekitchen.GetHash(env.GetMsgId()).Short(), res.Slot, v.Generation)
	n.mu.Lock()
	hs := append([]func(*pb.DirectedKernel, directed.VerifyResult, *pb.Envelope){}, n.directedHandlers...)
	n.mu.Unlock()
	for _, h := range hs {
		h(res.Kernel, v, env)
	}
	return true
}

// verify 执行完整校验管线。
func (n *Node) verify(sess Session, env *pb.Envelope) (registry.Verification, error) {
	v, err := n.reg.VerifyMessage(env, registry.Session{
		AuthorNodeID: sess.NodeID,
		AuthorPub:    sess.Pub,
		Now:          n.now(),
	})
	if err != nil {
		return v, err
	}
	// 节点消息允许来自任何已知对端；管理员消息的 author 必须为空
	// （已在 registry 中强制）。这里额外执行验证级别与主题策略。
	body := env.GetBody()
	switch n.cfg.VerifyLevel {
	case VerifyStrict:
		if !v.AdminAuthorized && body.GetKind() != pb.MessageKind_MESSAGE_KIND_SEALED {
			return v, fmt.Errorf("%w: strict 模式要求管理员门限签名", housekitchen.ErrThresholdNotMet)
		}
	case VerifyOpen:
		// open 模式不做额外限制
	default:
		// 封存消息是特例：外层由中继自签、内层带管理员门限签名，
		// 而**内层的管理员授权必须由持有主题密钥的订阅者解封后才能确认**。
		// 因此这里不能用外层 topic 策略去否定它，否则 sealed 模式无法工作。
		// 内层的主题策略在 Unseal 内、由订阅者按解密结果判定。
		// 中继侧的配额与速率限制仍然生效（见 onSealedSubmit）。
		if body.GetKind() == pb.MessageKind_MESSAGE_KIND_SEALED {
			return v, nil
		}
		// 控制类消息（节点动态 / 邻居互推 / 在线心跳 / 内容分片）不属于任何
		// 业务主题，主题策略对它们无意义，否则空 topic 会被误判为"未授权主题"。
		if !v.AdminAuthorized && !isControlKind(body.GetKind()) &&
			!n.reg.TopicAllowed(body.GetTopic(), false) {
			return v, fmt.Errorf("%w: 主题 %q 不允许节点写入", housekitchen.ErrUnknownTopic, body.GetTopic())
		}
	}
	return v, nil
}

// isAdminKind 判断是否为需要管理员门限签名的消息类型。
func isAdminKind(k pb.MessageKind) bool {
	switch k {
	case pb.MessageKind_MESSAGE_KIND_ADMIN_BROADCAST,
		pb.MessageKind_MESSAGE_KIND_ADMIN_SET,
		pb.MessageKind_MESSAGE_KIND_TOPIC_POLICY:
		return true
	default:
		return false
	}
}

// isControlKind 判断是否为不承载业务主题的控制类消息。
func isControlKind(k pb.MessageKind) bool {
	switch k {
	case pb.MessageKind_MESSAGE_KIND_NODE_ANNOUNCE,
		pb.MessageKind_MESSAGE_KIND_PEER_EXCHANGE,
		pb.MessageKind_MESSAGE_KIND_LIVENESS,
		pb.MessageKind_MESSAGE_KIND_CONTENT_MANIFEST,
		pb.MessageKind_MESSAGE_KIND_CHUNK:
		return true
	default:
		return false
	}
}

// accept 校验 → 去重 → 落盘 → 回调 → 转发。返回是否为新消息。
func (n *Node) accept(sess Session, env *pb.Envelope, source string) bool {
	ok, _ := n.acceptAndRelay(sess, env, source)
	return ok
}

// acceptAndRelay 与 accept 相同，但额外返回转发成功的邻居数。
func (n *Node) acceptAndRelay(sess Session, env *pb.Envelope, source string) (bool, int) {
	v, err := n.verify(sess, env)
	if err != nil {
		n.logf("futurecast: 丢弃来自 %s 的消息：%v", source, err)
		if sess.NodeID != (housekitchen.NodeID{}) && n.peers != nil {
			n.peers.Penalize(sess.NodeID, -10, err.Error())
		}
		return false, 0
	}
	msgID := housekitchen.GetHash(env.GetMsgId())
	if n.store != nil {
		if !n.store.Seen(msgID, n.now()) {
			return false, 0
		}
		if err := n.store.Put(env, n.now()); err != nil {
			if err != errDuplicate(err) {
				n.logf("futurecast: 存储消息 %s 失败：%v", msgID.Short(), err)
			}
			return false, 0
		}
	}
	n.logf("futurecast: 接受消息 %s（%s，主题 %q，管理员授权=%v）",
		msgID.Short(), env.GetBody().GetKind(), env.GetBody().GetTopic(), v.AdminAuthorized)

	n.mu.Lock()
	hs := append([]func(*pb.Envelope, registry.Verification){}, n.handlers...)
	inner := append([]func(*pb.SignedBody, registry.Verification, *pb.Envelope){}, n.sealedHandlers...)
	n.mu.Unlock()
	for _, h := range hs {
		h(env, v)
	}
	// 封存消息：持有主题口令的节点在这里把内层管理员正文解出来并上报。
	// 没有口令的节点会静默跳过 —— 它只看到一条普通节点消息。
	if env.GetBody().GetKind() == pb.MessageKind_MESSAGE_KIND_SEALED && len(inner) > 0 {
		ib, iv, err := n.Unseal(env)
		n.logf("futurecast: [诊断] 节点 %s 解封 SEALED：err=%v 管理员授权=%v",
			n.id.ID.Short(), err, iv.AdminAuthorized)
		if err == nil && iv.AdminAuthorized {
			for _, h := range inner {
				h(ib, iv, env)
			}
		}
	}
	n.logf("futurecast: [诊断D] 接受 kind=%v msg=%s author=%s source=%s",
		n.id.ID.Short(), env.GetBody().GetKind(),
		housekitchen.GetHash(env.GetMsgId()).Short(),
		housekitchen.GetNodeID(env.GetBody().GetAuthor()).Short())
	delivered := n.relayStats(env)
	// PUSH 是"尽力而为"：一次性客户端发完就断、或对端刚好在重连，都可能丢掉。
	// 因此每次接受新消息后**立即补一轮 INV**，让邻居马上能发现缺口并回 GET，
	// 而不是干等 3s 的定时器。这把"最终一致"的收敛时间从"最多一个 INV 周期"
	// 压到"一次往返"，同时保留了丢包自愈能力。
	n.syncNow()
	return true, delivered
}

func errDuplicate(err error) error {
	if err == nil {
		return nil
	}
	if err == housekitchen.ErrDuplicate {
		return err
	}
	return nil
}

// relay 把消息 PUSH 给 fanout 个随机出站邻居。
func (n *Node) relay(env *pb.Envelope) { n.relayStats(env) }

// relayStats 转发一条消息并返回成功 PUSH 的邻居数。
//
// 返回值的用途：一次性发布客户端必须在退出前确认"至少有一个邻居收到了"。
// 否则会出现真实的丢消息场景 —— 客户端写完 PUSH 立刻关闭连接，
// 帧还在 QUIC 缓冲里就被丢弃，而本地却报告"已发布"。
func (n *Node) relayStats(env *pb.Envelope) int {
	// ---- 纵深防御：转发层的保密性闸门 ----
	//
	// sealed/signed 超管绝不允许把**明文管理员广播**转发给网络。
	// 一旦转发，内容保密归零，同时把超管所在节点暴露成一条普通明文广播源。
	//
	// 为什么要在转发层设闸而不只在 CLI 设闸：发布路径可能因为后续改动再次
	// 引入明文外发（这正是本项目真实踩过的 bug）。闸门放在唯一的转发出口处，
	// 任何新增的发布路径都无法绕过。
	if n.cfg.AdminMode.HidesAddress() && isAdminKind(env.GetBody().GetKind()) {
		n.mu.Lock()
		n.statBlockedPlaintextAdmin++
		n.mu.Unlock()
		n.logf("futurecast: 拒绝转发明文管理员广播（%s 模式下必须走封存投递，否则内容保密与发送方匿名同时失效）",
			n.cfg.AdminMode)
		return 0
	}
	next := n.bumpHops(env)
	if next == nil {
		return 0
	}
	targets := n.gossipTargets(housekitchen.DefaultFanout)
	if len(targets) == 0 {
		n.mu.Lock()
		n.statRelayNoTarget++
		n.mu.Unlock()
		return 0
	}
	ok := 0
	for _, s := range targets {
		if err := s.Conn.WriteFrame(codec.NewPush(next)); err != nil {
			n.mu.Lock()
			n.statPushFail++
			n.mu.Unlock()
			n.logf("futurecast: 转发给 %s 失败：%v", s.NodeID.Short(), err)
			continue
		}
		ok++
		n.mu.Lock()
		n.statPushOK++
		n.mu.Unlock()
	}
	return ok
}

// bumpHops 递增跳数并重新计算 relay_tag。超过 max_hops 返回 nil。
func (n *Node) bumpHops(env *pb.Envelope) *pb.Envelope {
	maxHops := env.GetMaxHops()
	if maxHops == 0 {
		maxHops = housekitchen.DefaultMaxHops
	}
	hops := env.GetHops() + 1
	if hops > maxHops {
		return nil
	}
	next := &pb.Envelope{
		MsgId:              env.GetMsgId(),
		Hops:               hops,
		MaxHops:            maxHops,
		FirstSeenUnixNanos: env.GetFirstSeenUnixNanos(),
		RelayTag:           crypto.RelayTag(sealedDailyKey(n), housekitchen.GetHash(env.GetMsgId()), env.GetRelayTag()),
		Cipher:             env.GetCipher(),
		Body:               env.GetBody(),
		// 定向广播走 directed_body 分支。**必须在重建时一并带上**：
		// 漏掉它会让转发出去的信封变成"空信封"（body 与 directed_body 都为空），
		// 对端既验不了签也解不了密，表现为消息静默消失。
		DirectedBody: env.GetDirectedBody(),
	}
	if next.FirstSeenUnixNanos == 0 {
		next.FirstSeenUnixNanos = n.now().UnixNano()
	}
	return next
}

// gossipTargets 返回最多 k 个随机出站邻居；不足时用入站邻居补齐。
func (n *Node) gossipTargets(k int) []Session {
	all := n.sessions()
	if len(all) == 0 {
		return nil
	}
	out := make([]Session, 0, len(all))
	in := make([]Session, 0, len(all))
	for _, s := range all {
		if s.Outbound {
			out = append(out, s)
		} else {
			in = append(in, s)
		}
	}
	n.shuffleSessions(out)
	n.shuffleSessions(in)
	res := append(out, in...)
	if len(res) > k {
		res = res[:k]
	}
	return res
}

func (n *Node) shuffleSessions(s []Session) {
	n.rndMu.Lock()
	defer n.rndMu.Unlock()
	n.rnd.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
}

// ---------- 发现 ----------

func (n *Node) onFindNode(sess Session, req *pb.FindNode) {
	target := housekitchen.GetNodeID(req.GetTarget())
	want := int(req.GetWant())
	if want <= 0 {
		want = 8
	}
	var infos []*pb.NodeInfo
	if n.peers != nil {
		for _, rec := range n.peers.Closest(target, want) {
			infos = append(infos, n.recordToInfoWithSession(rec))
		}
	}
	_ = sess.Conn.WriteFrame(codec.NewNodes(target, infos))
}

func (n *Node) onNodes(msg *pb.Nodes) {
	if n.peers == nil || msg == nil {
		return
	}
	for _, info := range msg.GetNodes() {
		n.learnNode(info)
	}
}

// learnNode 学习一个邻居地址。注意：sealed/signed 超管不公布地址，
// 因此这里的 addrs 为空时不会被写入地址簿。
func (n *Node) learnNode(info *pb.NodeInfo) {
	id := housekitchen.GetNodeID(info.GetNodeId())
	if id.IsZero() || id == n.id.ID {
		return
	}
	// 公钥必须自洽：SHA-256(pub) 必须等于 node_id。
	// 否则任何人都能往网络里塞"某人 = 我的公钥"的假条目 ——
	// 那会让定向广播把内容加密给攻击者。
	pub := info.GetPub()
	if len(pub) > 0 && housekitchen.NodeIDFromPub(pub) != id {
		return
	}
	if info.GetAddr() == "" && len(pub) == 0 {
		return
	}
	rec := PeerRecord{NodeID: id, Pub: pub, LastSeen: n.now(), Outbound: false}
	if a := info.GetAddr(); a != "" {
		rec.Addrs = []string{a}
	}
	_ = n.peers.Upsert(rec)
}

func (n *Node) onPeerExchange(sess Session, pe *pb.PeerExchange) {
	if pe == nil || n.peers == nil {
		return
	}
	if err := identity.VerifyPeerExchange(sess.Pub, pe); err != nil {
		n.peers.Penalize(sess.NodeID, -30, "peer exchange signature invalid")
		n.logf("futurecast: 来自 %s 的邻居互推签名无效：%v", sess.NodeID.Short(), err)
		return
	}
	// 单次通告条数上限，防止路由投毒。
	nodes := pe.GetNodes()
	if len(nodes) > 64 {
		nodes = nodes[:64]
	}
	for _, info := range nodes {
		n.learnNode(info)
	}
	n.peers.Reward(sess.NodeID, 1)
	if n.peers.NeedMorePeers() {
		n.dialSomePeers()
	}
}

// dialSomePeers 从地址簿挑几个未知地址主动连接。
func (n *Node) dialSomePeers() {
	if n.peers == nil || n.connCount() >= n.cfg.MaxPeers {
		return
	}
	closest := n.peers.Closest(n.id.ID, 16)
	tried := 0
	for _, rec := range closest {
		if tried >= 3 {
			return
		}
		n.mu.Lock()
		_, connected := n.conns[rec.NodeID]
		n.mu.Unlock()
		if connected || len(rec.Addrs) == 0 {
			continue
		}
		addr := rec.Addrs[0]
		n.mu.Lock()
		busy := n.dialing[addr]
		if !busy {
			n.dialing[addr] = true
		}
		n.mu.Unlock()
		if busy {
			continue
		}
		tried++
		go func(a string) {
			ctx, cancel := contextWithTimeout(n.stopCh, 10*time.Second)
			defer cancel()
			c, err := n.tr.Dial(ctx, a)
			n.mu.Lock()
			delete(n.dialing, a)
			n.mu.Unlock()
			if err != nil {
				return
			}
			n.serveConn(c, true)
		}(addr)
	}
}

// announceSelf 构造并广播一条节点动态。
func (n *Node) announceSelf() {
	if n.peers == nil {
		return
	}
	gen, set := n.reg.Current()
	var addrs []string
	if !n.cfg.AdminMode.HidesAddress() && n.tr != nil && n.tr.Listening() {
		addrs = append(addrs, n.tr.LocalAddr().String())
	}
	ann := &pb.NodeAnnounce{
		NodeId:            housekitchen.PBNodeID(n.id.ID),
		Addrs:             addrs,
		AddressPublic:     !n.cfg.AdminMode.HidesAddress(),
		Seq:               n.now().UnixNano(),
		IssuedAtUnixNanos: n.now().UnixNano(),
	}
	// 安全决策（G3）：这里**不**填充 RendezvousHint。
	//
	// 该字段若只在 sealed 模式出现，就等于给观察者一个"此节点是 sealed 超管"
	// 的身份类别标记 —— 每代轮换只能防长期关联，防不了身份分类。
	// 因此一律留空：sealed 超管与普通节点在线格式上完全一致。
	sig, err := n.id.SignNodeAnnounce(ann)
	if err != nil {
		return
	}
	ann.SelfSignature = sig

	payload := &pb.Payload{Payload: &pb.Payload_NodeAnnounce{NodeAnnounce: ann}}
	body, err := registry.NewNodeMessage(n.id, pb.MessageKind_MESSAGE_KIND_NODE_ANNOUNCE, "", payload, set, time.Hour, n.now())
	if err != nil {
		return
	}
	canonical, err := registry.CanonicalForSigning(body)
	if err != nil {
		return
	}
	if err := registry.FinalizeNodeBody(body, canonical, n.id, n.now()); err != nil {
		return
	}
	env := registry.WrapEnvelope(body, n.now())
	if n.store != nil {
		if !n.store.Seen(housekitchen.GetHash(env.GetMsgId()), n.now()) {
			return
		}
		_ = n.store.Put(env, n.now())
	}
	_ = gen
	n.relay(env)
}

// ---------- 后台循环 ----------

func (n *Node) gossipLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	if !n.sleep(2 * time.Second) {
		return
	}
	n.announceSelf()
	for !n.stopped() {
		select {
		case <-n.stopCh:
			return
		case <-t.C:
			n.announceSelf()
			n.maintainPeers()
		}
	}
}

// maintainPeers 做地址过期清理与连接数补充。
func (n *Node) maintainPeers() {
	if n.peers == nil {
		return
	}
	for _, id := range n.peers.Expire(n.now()) {
		n.mu.Lock()
		if c, ok := n.conns[id]; ok {
			_ = c.Close()
		}
		n.mu.Unlock()
	}
	if n.peers.NeedMorePeers() {
		n.dialSomePeers()
	}
}

func (n *Node) invLoop() {
	t := time.NewTicker(time.Duration(housekitchen.DefaultGossipIntervalMS) * time.Millisecond)
	defer t.Stop()
	for !n.stopped() {
		select {
		case <-n.stopCh:
			return
		case <-t.C:
			n.sendInvs()
		}
	}
}

// syncNow 触发一轮即时的 anti-entropy（不等定时器）。
//
// 非阻塞：多个消息连续到达时只会有一次实际的 INV 轮，
// 避免每收一条消息就向所有邻居广播一次清单造成放大。
func (n *Node) syncNow() {
	select {
	case n.syncCh <- struct{}{}:
	default: // 已经有一轮排队，合并掉
	}
}

// sendInvs 对已知主题发送 INV 清单，触发缺口补齐。
//
// 关键：主题列表取自**本地存储中实际存在的主题**，而不是只看配置的订阅列表。
// 早先只遍历 cfg.Topics，导致两条真实后果：
//   - 用 "" 作为"全部主题"的通配并不成立（store.List 对非空 topic 做精确匹配）；
//   - 配置里没有列出的主题，其消息永远不会被 INV 广告出去，
//     于是"最终一致"对它们失效（演示里表现为消息偶尔永远到不了某些节点）。
func (n *Node) sendInvs() {
	if n.store == nil {
		return
	}
	topics := n.store.Topics()
	if len(topics) == 0 {
		return
	}
	for _, topic := range topics {
		envs := n.store.List(topic, n.now().Add(-time.Hour), 100)
		if len(envs) == 0 {
			continue
		}
		ids := make([]housekitchen.Hash, 0, len(envs))
		for _, e := range envs {
			ids = append(ids, housekitchen.GetHash(e.GetMsgId()))
		}
		frame := codec.NewInv(topic, ids, n.now().Add(-time.Hour).UnixNano())
		sent := 0
		for _, s := range n.sessions() {
			if err := s.Conn.WriteFrame(frame); err == nil {
				sent++
			}
		}
		if sent > 0 {
			n.mu.Lock()
			n.statInvSent++
			n.mu.Unlock()
		}
	}
}

// onInv 对比本地缺失的消息并请求。
func (n *Node) onInv(sess Session, inv *pb.Inv) {
	if inv == nil || n.store == nil {
		return
	}
	var missing []housekitchen.Hash
	for _, h := range inv.GetMsgIds() {
		id := housekitchen.GetHash(h)
		if id.IsZero() {
			continue
		}
		if _, ok := n.store.Get(id); !ok {
			missing = append(missing, id)
			if len(missing) >= 32 {
				break
			}
		}
	}
	if len(missing) == 0 {
		return
	}
	n.mu.Lock()
	n.statGetRequested += uint64(len(missing))
	n.mu.Unlock()
	_ = sess.Conn.WriteFrame(codec.NewGet(missing))
}

// onGet 应答缺失消息请求。
func (n *Node) onGet(sess Session, req *pb.Get) {
	if req == nil || n.store == nil {
		return
	}
	var out []*pb.Envelope
	for _, h := range req.GetMsgIds() {
		if env, ok := n.store.Get(housekitchen.GetHash(h)); ok {
			out = append(out, env)
		}
	}
	if len(out) > 0 {
		_ = sess.Conn.WriteFrame(codec.NewMsg(out))
	}
}

func (n *Node) gcLoop() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for !n.stopped() {
		select {
		case <-n.stopCh:
			return
		case <-t.C:
			if n.store != nil {
				if removed := n.store.GC(n.now()); removed > 0 {
					n.logf("futurecast: 消息存储清理 %d 条过期条目", removed)
				}
			}
			n.mailbox.GC(n.now())
		}
	}
}

// ---------- 内容分片 ----------

func (n *Node) onGetContent(sess Session, req *pb.GetContent) {
	if req == nil || n.store == nil {
		return
	}
	id := housekitchen.GetHash(req.GetContentId())
	from := req.GetFromIndex()
	count := req.GetCount()
	if count == 0 || count > 16 {
		count = 16
	}
	for i := from; i < from+count; i++ {
		data, ok := n.store.GetChunk(id, i)
		if !ok {
			break
		}
		_ = sess.Conn.WriteFrame(codec.NewContentChunk(&pb.ContentChunk{
			ContentId: housekitchen.PBHash(id), Index: i, Data: data,
		}))
	}
}

func (n *Node) onContentChunk(sess Session, c *pb.ContentChunk) {
	if c == nil || n.store == nil {
		return
	}
	// 分片内容寻址：下标合法性与内容摘要都必须在 store 层被校验。
	// 这里先把明显非法的下标挡掉，避免污染存储。
	if len(c.GetData()) == 0 {
		return
	}
	id := housekitchen.GetHash(c.GetContentId())
	if err := n.store.PutChunk(id, c.GetIndex(), c.GetData()); err != nil {
		if n.peers != nil {
			n.peers.Penalize(sess.NodeID, -20, "chunk rejected: "+err.Error())
		}
	}
}

// recordToInfoWithSession 把节点表记录转换为线上表示，并在记录缺公钥时
// 用当前会话的公钥兜底。
//
// 为什么需要兜底：节点表可能被不含公钥的邻居通告覆盖/新建，而**会话公钥是
// 握手时已证实的**，是网络上最可靠的身份来源。定向广播依赖公钥分发，
// 少了这层兜底，间接节点的公钥就会在网络上传播不开。
func (n *Node) recordToInfoWithSession(rec PeerRecord) *pb.NodeInfo {
	info := recordToInfo(rec)
	if len(info.GetPub()) == 0 {
		n.mu.Lock()
		if s, ok := n.sess[rec.NodeID]; ok {
			info.Pub = s.Pub
		}
		n.mu.Unlock()
	}
	return info
}

// recordToInfo 把节点表记录转换为线上表示。
func recordToInfo(rec PeerRecord) *pb.NodeInfo {
	addr := ""
	if len(rec.Addrs) > 0 {
		addr = rec.Addrs[0]
	}
	return &pb.NodeInfo{
		NodeId:             housekitchen.PBNodeID(rec.NodeID),
		Addr:               addr,
		LastSeenUnixNanos:  rec.LastSeen.UnixNano(),
		ExpiresAtUnixNanos: rec.LastSeen.Add(15 * time.Minute).UnixNano(),
		Seq:                rec.LastSeen.UnixNano(),
	}
}
