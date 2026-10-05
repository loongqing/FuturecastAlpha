package node

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/loongqing/FuturecastAlpha/internal/codec"
	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/registry"
	"github.com/loongqing/FuturecastAlpha/internal/sealed"
	"github.com/loongqing/FuturecastAlpha/internal/transport"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// ---------- 普通消息路径 ----------

// onPush 处理一条推送消息。source 仅用于日志。
func (n *Node) onPush(sess Session, env *pb.Envelope) {
	if env == nil {
		return
	}
	// 定向广播走独立路径：它的被签名对象是 DirectedBody，不是 SignedBody。
	if env.GetDirectedBody() != nil {
		// 去重必须在**转发之前**：定向广播同样会在全网扩散，
		// 若不去重，同一条消息会被邻居反复推回、反复转发（实测放大到数百次），
		// 既浪费带宽又让日志与统计彻底失真。
		msgID := housekitchen.GetHash(env.GetMsgId())
		if n.store != nil {
			if !n.store.Seen(msgID, n.now()) {
				return
			}
			_ = n.store.Put(env, n.now())
		}
		n.onDirected(env)
		n.relay(env)
		n.syncNow()
		return
	}
	n.accept(sess, env, "push")
}

// ---------- 封存路径 ----------

// onSealedSubmit 处理"超管 → 中继"的封存投递。
//
// 中继在这里做的事：
//  1. 用自己的 X25519 私钥解封，得到内层 SignedBody（含完整 2-of-3 门限签名）
//  2. 用内层正文做完整校验 —— 中继无法伪造，因为门限签名在内层
//  3. 按 jitter_hint 安排延迟发布（打散时间关联）
//  4. 落信箱，等待 relayPublishLoop 用**中继自己的节点身份**重新签名发布
func (n *Node) onSealedSubmit(sess Session, sub *pb.SealedSubmit) {
	if sub == nil || sub.GetSealed() == nil {
		return
	}
	if !n.duty.ShouldRelay() && !n.cfg.Relay.Enabled {
		_ = sess.Conn.WriteFrame(codec.NewError(403, "relay duty disabled", false))
		return
	}
	sp := sub.GetSealed()
	rendezvous := housekitchen.GetHash(sp.GetInboxRendezvousId())

	if err := n.duty.Admit(rendezvous, n.now()); err != nil {
		_ = sess.Conn.WriteFrame(codec.NewError(429, err.Error(), true))
		n.logf("futurecast: 拒绝封存投递（配额）：%v", err)
		return
	}
	// 本节点的 X25519 私钥标量由 ed25519 种子确定性派生，
	// 与超管用 Ed25519ToX25519(本节点公钥) 得到的加密公钥天然配对。
	selfScalar, err := crypto.Ed25519SeedToX25519Scalar(n.id.KeySeed)
	if err != nil {
		n.logf("futurecast: 派生本节点 X25519 私钥失败：%v", err)
		return
	}
	body, err := sealed.Open(selfScalar, sp)
	if err != nil {
		n.logf("futurecast: 解封失败（可能不是给我的副本）：%v", err)
		_ = sess.Conn.WriteFrame(codec.NewError(400, "cannot open sealed payload", false))
		return
	}
	inner := &pb.Envelope{
		MsgId:              body.GetMsgId(),
		Hops:               0,
		MaxHops:            uint32(body.GetMaxHops()),
		FirstSeenUnixNanos: n.now().UnixNano(),
		Body:               body,
	}
	// 中继独立校验内层门限签名：中继不"信任"提交者。
	v, err := n.reg.VerifyMessage(inner, registry.Session{Now: n.now()})
	if err != nil {
		n.logf("futurecast: 封存内层校验失败：%v", err)
		_ = sess.Conn.WriteFrame(codec.NewError(400, "inner verification failed", false))
		return
	}
	if !v.AdminAuthorized {
		n.logf("futurecast: 封存内层未达管理员门限，拒绝")
		_ = sess.Conn.WriteFrame(codec.NewError(403, "inner not admin-authorized", false))
		return
	}

	// 抖动：在策略区间内随机延迟发布，切断"提交 → 发布"的时间关联。
	minJ, maxJ := n.duty.JitterBounds()
	d := sealed.Jitter(minJ, maxJ)
	if hint := sp.GetJitterHintMs(); hint > 0 {
		hintD := time.Duration(hint) * time.Millisecond
		if hintD < d {
			d = hintD
		}
	}
	publishAt := n.now().Add(d)

	n.pendingMu.Lock()
	n.pending = append(n.pending, pendingSealed{body: body, publishAt: publishAt})
	n.pendingMu.Unlock()

	_ = sess.Conn.WriteFrame(codec.NewSealedReceipt(&pb.SealedReceipt{
		InboxRendezvousId:  housekitchen.PBHash(rendezvous),
		AcceptedMsgId:      body.GetMsgId(),
		ScheduledPublishMs: uint64(d / time.Millisecond),
		RelayNodeId:        housekitchen.PBNodeID(n.id.ID),
	}))
	n.logf("futurecast: 受理封存副本，将在 %s 后以本节点身份发布", d.Round(time.Millisecond))
}

// relayPublishLoop 把到期的封存副本用自己的节点身份重新签名发布。
//
// 关键点：发布出去的是 author=本中继 的**新**节点消息，
// 内层管理员签名被封存在 payload 里。公网观察者只看到"某个普通节点发了条消息"。
func (n *Node) relayPublishLoop() {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for !n.stopped() {
		select {
		case <-n.stopCh:
			return
		case <-t.C:
			n.flushPending()
		}
	}
}

func (n *Node) flushPending() {
	now := n.now()
	n.pendingMu.Lock()
	due := make([]pendingSealed, 0, len(n.pending))
	keep := n.pending[:0]
	for _, p := range n.pending {
		if !p.publishAt.After(now) {
			due = append(due, p)
			continue
		}
		keep = append(keep, p)
	}
	n.pending = keep
	n.pendingMu.Unlock()

	for _, p := range due {
		n.publishAsRelay(p.body)
	}
}

// publishAsRelay 把内层管理员正文包成外层节点消息并发布。
func (n *Node) publishAsRelay(inner *pb.SignedBody) {
	_, set := n.reg.Current()
	// 关键：只填 inner_body，不填任何在多个中继副本之间**共享的明文字段**。
	// 若把内层 msg_id 或 signer_set_hash 明文放进来，观察者就能靠它把
	// 若干份副本关联到同一次发布，从而反推"谁在当中继"。
	innerBytes := mustMarshal(inner)
	if innerBytes == nil {
		n.logf("futurecast: 内层正文序列化失败，放弃中继发布")
		return
	}
	sp := &pb.SealedPayload{
		// 承诺值：把内层正文绑到外层节点消息的签名覆盖范围内。
		// 没有它，中继可以保留合法外层、把内层调包成任意内容。
		InboxRendezvousId: housekitchen.PBHash(housekitchen.ChunkHash(innerBytes)),
	}
	if len(n.topicKey) > 0 {
		// 内容保密层：没有主题口令的观察者与中继只能看到密文，
		// 因此连"这是一条超管广播"都无法判定（设计文档 §5.6）。
		ct, nonce, err := sealed.EncryptInner(n.topicKey, innerBytes, inner.GetTopic())
		if err != nil {
			n.logf("futurecast: 内层加密失败，放弃中继发布：%v", err)
			return
		}
		sp.InnerCiphertext = ct
		sp.InnerNonce = nonce
		sp.TopicKeyId = housekitchen.PBKeyID(sealed.TopicKeyID(n.topicKey))
		sp.InnerBody = nil
	} else {
		// 安全关键：中继没有主题密钥时**不允许**把内层正文以明文重新发布。
		//
		// 否则会发生"静默降级"：超管以为发的是加密封存，网络上实际流通的却是明文，
		// 而对超管没有任何提示。机密性缺失必须是显式失败，不能是隐式行为。
		//
		// 请配置 topic_secret；入口中继必须持有它才能完成门限校验与重发布
		// （原因见 docs/DESIGN.md §5.6）。
		n.logf("futurecast: 拒绝发布封存副本：本节点无主题口令，无法在不泄露明文的前提下重发布" +
			"（请为本节点配置 topic_secret，或让超管改用 public/signed 模式）")
		return
	}
	payload := &pb.Payload{Payload: &pb.Payload_Sealed{Sealed: sp}}
	outer, err := registry.NewNodeMessage(n.id, pb.MessageKind_MESSAGE_KIND_SEALED,
		inner.GetTopic(), payload, set, time.Duration(housekitchen.DefaultMsgTTLNanos), n.now())
	if err != nil {
		n.logf("futurecast: 组装中继消息失败：%v", err)
		return
	}
	canonical, err := registry.CanonicalForSigning(outer)
	if err != nil {
		return
	}
	if err := registry.FinalizeNodeBody(outer, canonical, n.id, n.now()); err != nil {
		return
	}
	env := registry.WrapEnvelope(outer, n.now())
	// 关键：hops 与 relay_tag 随机化到"普通消息"的取值区间，
	// 使这条副本与网络中其他消息在字段上无法区分。
	env.Hops = uint32(n.randInt(3))
	env.RelayTag = housekitchen.RandomUint64()
	if n.store != nil {
		if !n.store.Seen(housekitchen.GetHash(env.GetMsgId()), n.now()) {
			return
		}
		_ = n.store.Put(env, n.now())
	}
	n.logf("futurecast: 以中继身份 %s 发布封存副本 %s（主题 %q）",
		n.id.ID.Short(), housekitchen.GetHash(env.GetMsgId()).Short(), inner.GetTopic())
	n.relay(env)
}

// ---------- 信箱 ----------

func (n *Node) onMailboxStore(sess Session, ms *pb.MailboxStore) {
	if ms == nil {
		return
	}
	rendezvous := housekitchen.GetHash(ms.GetRendezvousId())
	for _, env := range ms.GetEnvelopes() {
		if err := n.mailbox.Store(rendezvous, env, n.now()); err != nil && err != housekitchen.ErrDuplicate {
			n.logf("futurecast: 信箱写入失败：%v", err)
		}
	}
	n.logf("futurecast: 信箱 %s 收到 %d 条", rendezvous.Short(), len(ms.GetEnvelopes()))
}

func (n *Node) onMailboxGet(sess Session, mg *pb.MailboxGet) {
	if mg == nil {
		return
	}
	rendezvous := housekitchen.GetHash(mg.GetRendezvousId())
	limit := int(mg.GetLimit())
	if limit <= 0 {
		limit = 64
	}
	since := time.Unix(0, mg.GetSinceUnixNanos())
	if mg.GetSinceUnixNanos() == 0 {
		since = time.Time{}
	}
	envs := n.mailbox.Fetch(rendezvous, since, limit)
	_ = sess.Conn.WriteFrame(codec.NewMailboxData(&pb.MailboxData{
		RendezvousId: housekitchen.PBHash(rendezvous),
		Envelopes:    envs,
		HasMore:      false,
	}))
}

// ---------- 超管侧：sealed 投递 ----------

// SubmitSealed 由 sealed 超管调用：把一条已在本地签好的管理员正文，
// 通过出站连接交给 k 个中继，然后返回被受理的回执数。
//
// 本节点不监听端口，因此外部无法主动联系它 —— 方向始终是超管主动出站。
func (n *Node) SubmitSealed(body *pb.SignedBody) (int, error) {
	if n.adminKey == nil {
		return 0, fmt.Errorf("futurecast: 本节点未配置管理员密钥")
	}
	if !n.cfg.AdminMode.HidesAddress() {
		return 0, fmt.Errorf("futurecast: 只有 signed/sealed 模式需要走封存投递")
	}
	epoch := sealed.EpochFor(n.now(), n.cfg.Relay.EpochDuration)
	rendezvous, err := sealed.RendezvousFor(n.adminKey.KeySeed, epoch)
	if err != nil {
		return 0, err
	}
	candidates := n.relayCandidates(n.cfg.Relay.Relays, rendezvous)
	if len(candidates) == 0 {
		return 0, fmt.Errorf("futurecast: 当前没有可用中继（先连上任何节点）")
	}
	jitterHint := uint64(n.cfg.Relay.SealedJitterMax / time.Millisecond)

	accepted := 0
	for _, cand := range candidates {
		sp, err := sealed.Seal(cand.X25519Pub, body, rendezvous, epoch, jitterHint)
		if err != nil {
			n.logf("futurecast: 封存失败（中继 %s）：%v", cand.NodeID.Short(), err)
			continue
		}
		sub := &pb.SealedSubmit{Sealed: sp}
		// 提交方自证：证明"这一帧确实是本连接对端提交的"。
		// 中继不依赖它来验证管理员身份（那由内层门限签名保证），
		// 它只用于把封存投递绑定到具体连接，防止第三方重放投递。
		if canonical := mustCanonicalSealed(sp); canonical != nil {
			sub.SubmitterSelfSignature = crypto.SignCanonical(n.id.Priv, canonical)
		}
		frame := codec.NewSealedSubmit(sub)
		if err := n.sendFrameTo(cand.NodeID, frame); err != nil {
			n.logf("futurecast: 向中继 %s 投递失败：%v", cand.NodeID.Short(), err)
			continue
		}
		accepted++
	}
	if accepted == 0 {
		return 0, fmt.Errorf("futurecast: 所有中继投递均失败")
	}
	n.logf("futurecast: 封存投递完成，%d/%d 个中继受理（信箱 %s，代 %d）",
		accepted, len(candidates), rendezvous.Short(), epoch)
	return accepted, nil
}

// relayCandidates 从已知邻居中选出 k 个中继，并派生它们的 X25519 公钥。
//
// X25519 公钥由 ed25519 公钥确定性转换得到（见 crypto.Ed25519ToX25519），
// 因此协议无需为每个节点额外携带密钥字段。
func (n *Node) relayCandidates(k int, rendezvous housekitchen.Hash) []sealed.RelayCandidate {
	if k <= 0 {
		k = 4
	}
	sessions := n.sessions()
	byID := make(map[housekitchen.NodeID]Session, len(sessions))
	cands := make([]sealed.RelayCandidate, 0, len(sessions))
	for _, s := range sessions {
		x, err := crypto.Ed25519ToX25519(s.Pub)
		if err != nil {
			continue
		}
		byID[s.NodeID] = s
		cands = append(cands, sealed.RelayCandidate{NodeID: s.NodeID, X25519Pub: x})
	}
	// 没有邻居时退回地址簿（仍可主动出站连接）。
	if len(cands) == 0 && n.peers != nil {
		for _, rec := range n.peers.Closest(n.id.ID, k*2) {
			if len(rec.Pub) != crypto.PubKeySize {
				continue
			}
			x, err := crypto.Ed25519ToX25519(rec.Pub)
			if err != nil {
				continue
			}
			cands = append(cands, sealed.RelayCandidate{NodeID: rec.NodeID, X25519Pub: x})
		}
	}
	// 以 rendezvous 点为目标做 XOR 距离排序：任何知道该代 rendezvous 的
	// 节点都会选出同一个中继集合（前提是它们看到的在线集合一致）。
	return sealed.SelectRelays(rendezvous, cands, k)
}

// sendFrameTo 向指定节点发送一帧；没有现成连接时主动出站建立。
func (n *Node) sendFrameTo(id housekitchen.NodeID, f *pb.Frame) error {
	n.mu.Lock()
	c, ok := n.conns[id]
	n.mu.Unlock()
	if ok {
		return c.WriteFrame(f)
	}
	// 尝试从地址簿拿地址主动连接。
	if n.peers == nil {
		return fmt.Errorf("futurecast: 没有到 %s 的连接，也没有地址簿", id.Short())
	}
	rec, found := n.peers.Get(id)
	if !found || len(rec.Addrs) == 0 {
		return fmt.Errorf("futurecast: 没有到 %s 的连接，且地址簿无地址", id.Short())
	}
	ctx, cancel := contextWithTimeout(n.stopCh, 10*time.Second)
	defer cancel()
	nc, err := n.tr.Dial(ctx, rec.Addrs[0])
	if err != nil {
		return fmt.Errorf("futurecast: 出站连接 %s 失败: %w", id.Short(), err)
	}
	sess, err := n.handshake(nc, true)
	if err != nil {
		_ = nc.Close()
		return err
	}
	if sess.NodeID != id {
		_ = nc.Close()
		n.unregisterConn(sess.NodeID)
		return fmt.Errorf("futurecast: 对端身份不符（期望 %s，实为 %s）", id.Short(), sess.NodeID.Short())
	}
	go n.serveConnNoHandshake(nc, sess)
	return nc.WriteFrame(f)
}

// serveConnNoHandshake 在已握手完成的连接上继续读循环。
func (n *Node) serveConnNoHandshake(c *transport.Conn, sess Session) {
	defer func() {
		n.unregisterConn(sess.NodeID)
		_ = c.Close()
	}()
	for !n.stopped() {
		f, err := c.ReadFrame()
		if err != nil {
			return
		}
		n.handleFrame(sess, f)
	}
}

// Unseal 尝试解开一条封存消息的内层管理员正文。
//
// 只有持有主题密钥的订阅者能走到这里做"管理员身份确认" —— 这正是
// sealed 模式的核心权衡：外部观察者连"这是超管发的"都无法判定。
// 本函数不依赖主题密钥（内容级加密由 envelope.cipher 承担），
// 它负责的是内层来源验证与承诺值绑定校验。
//
// 返回 nil 表示这条消息不是封存消息或不满足约束，调用方应保持沉默
// （只转发不展示），避免把错误当信号回传。
func (n *Node) Unseal(env *pb.Envelope) (*pb.SignedBody, registry.Verification, error) {
	body := env.GetBody()
	if body == nil || body.GetKind() != pb.MessageKind_MESSAGE_KIND_SEALED {
		return nil, registry.Verification{}, fmt.Errorf("futurecast: 不是封存消息")
	}
	sp := body.GetPayload().GetSealed()
	if sp == nil {
		return nil, registry.Verification{}, fmt.Errorf("futurecast: 封存载荷为空")
	}
	// 加密模式下 inner_body 必须为空（明文只走 inner_ciphertext），
	// 因此这里不能按"inner_body 非空"判定载荷有效。
	if len(sp.GetInnerBody()) == 0 && !sealed.IsEncrypted(sp) {
		return nil, registry.Verification{}, fmt.Errorf("futurecast: 封存载荷既无明文也无密文")
	}
	// 1. 取出内层明文字节：可能是明文，也可能是用主题密钥加密的密文。
	innerBytes := sp.GetInnerBody()
	if sealed.IsEncrypted(sp) {
		if len(n.topicKey) == 0 {
			return nil, registry.Verification{}, fmt.Errorf(
				"%w: 该封存消息已加密，但本节点未配置主题口令（无法判定内容，也不会展示）",
				housekitchen.ErrSealedInvalid)
		}
		plain, err := sealed.DecryptInner(n.topicKey, sp.GetInnerCiphertext(), sp.GetInnerNonce(), body.GetTopic())
		if err != nil {
			return nil, registry.Verification{}, fmt.Errorf("%w: 内层解密失败: %v", housekitchen.ErrSealedInvalid, err)
		}
		innerBytes = plain
	}
	if len(innerBytes) == 0 {
		return nil, registry.Verification{}, fmt.Errorf("%w: 封存内层为空", housekitchen.ErrSealedInvalid)
	}
	// 2. 承诺值必须匹配 —— 阻断中继调包内层正文。
	commitment := housekitchen.GetHash(sp.GetInboxRendezvousId())
	if commitment != housekitchen.ChunkHash(innerBytes) {
		return nil, registry.Verification{}, fmt.Errorf("%w: 内层正文承诺值不匹配", housekitchen.ErrSealedInvalid)
	}
	// 3. 解析内层正文。
	inner, err := unmarshalBody(innerBytes)
	if err != nil {
		return nil, registry.Verification{}, fmt.Errorf("%w: 内层正文无法解析: %v", housekitchen.ErrSealedInvalid, err)
	}
	// 3. 内层不允许再嵌套封存，避免无限套娃消耗验证资源。
	if inner.GetKind() == pb.MessageKind_MESSAGE_KIND_SEALED {
		return nil, registry.Verification{}, fmt.Errorf("%w: 内层不得再嵌套封存消息", housekitchen.ErrSealedInvalid)
	}
	// 4. 用完整校验管线验证内层管理员门限签名。
	innerEnv := &pb.Envelope{
		MsgId:   inner.GetMsgId(),
		Body:    inner,
		Hops:    0,
		MaxHops: uint32(inner.GetMaxHops()),
	}
	v, err := n.reg.VerifyMessage(innerEnv, registry.Session{Now: n.now()})
	if err != nil {
		return nil, registry.Verification{}, fmt.Errorf("%w: 内层校验失败: %v", housekitchen.ErrSealedInvalid, err)
	}
	if !v.AdminAuthorized {
		return nil, registry.Verification{}, fmt.Errorf("%w: 内层未达管理员门限", housekitchen.ErrSealedInvalid)
	}
	// 5. 内外主题必须一致，防止中继把封存内容"搬到"另一个主题上。
	if inner.GetTopic() != body.GetTopic() {
		return nil, registry.Verification{}, fmt.Errorf("%w: 内外主题不一致", housekitchen.ErrSealedInvalid)
	}
	return inner, v, nil
}

// ---------- 辅助 ----------

// sealedRendezvous 返回本节点作为 sealed 超管时的当前信箱 ID。
func sealedRendezvous(n *Node) (housekitchen.Hash, error) {
	if n.adminKey == nil {
		return housekitchen.Hash{}, fmt.Errorf("futurecast: 未配置管理员密钥")
	}
	return sealed.RendezvousFor(n.adminKey.KeySeed, sealed.EpochFor(n.now(), n.cfg.Relay.EpochDuration))
}

// sealedDailyKey 返回当日轮换的 relay_tag 密钥。
func sealedDailyKey(n *Node) []byte { return sealed.DailyKey(n.id.KeySeed, n.now()) }

// mustCanonicalSealed 计算封存载荷的规范化字节。
func mustCanonicalSealed(sp *pb.SealedPayload) []byte {
	b, err := housekitchen.CanonicalSealedPayload(sp)
	if err != nil {
		return nil
	}
	return b
}

// unmarshalBody 解析内层管理员正文。
func unmarshalBody(b []byte) (*pb.SignedBody, error) {
	out := &pb.SignedBody{}
	if err := proto.Unmarshal(b, out); err != nil {
		return nil, err
	}
	return out, nil
}

// mustMarshal 用确定性序列化把 protobuf 消息编码为字节。
// 封存内层必须可复现，因此这里与 housekitchen 使用同样的确定性选项。
func mustMarshal(m proto.Message) []byte {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil
	}
	return b
}
