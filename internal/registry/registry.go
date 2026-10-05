// Package registry 维护超级管理员集合（AdminSet）链，并执行全部门限校验规则。
//
// 校验规则（对应设计文档 §4.2）：
//  1. msg_id 必须与重新计算的正文摘要一致
//  2. signer_set_hash 必须等于本代数 AdminSet 的规范化摘要
//  3. admin_set_generation 必须落在本地接受的代数集合内
//  4. 每个签名必须属于该代 root_key_ids，同一 key_id 只计一次，时间戳在容差内
//  5. 有效且互异签名数 >= threshold
//  6. 管理员消息不得携带 author 字段（避免与节点消息混淆）
package registry

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// DefaultGraceGenerations 是保留的历史代数（宽限窗），用于验证换代前签发的消息。
const DefaultGraceGenerations = 4

// Registry 持有 AdminSet 链与本地验证策略。
type Registry struct {
	mu             sync.RWMutex
	sets           map[uint64]*pb.AdminSet
	current        uint64
	graceGens      uint64
	now            func() time.Time
	requireAdminOn map[pb.MessageKind]bool
	topics         map[string]*pb.TopicPolicy
}

// Options 配置 Registry。
type Options struct {
	// GraceGenerations 保留的历史代数，默认 4。
	GraceGenerations uint64
	// Now 时间源，默认 time.Now。
	Now func() time.Time
	// RequireAdminKinds 覆盖"必须由管理员签名的消息类型"集合。
	RequireAdminKinds []pb.MessageKind
}

// adminRequiredKinds 是默认必须带管理员门限签名的消息类型。
var adminRequiredKinds = []pb.MessageKind{
	pb.MessageKind_MESSAGE_KIND_ADMIN_BROADCAST,
	pb.MessageKind_MESSAGE_KIND_ADMIN_SET,
	pb.MessageKind_MESSAGE_KIND_TOPIC_POLICY,
}

// New 用创世 AdminSet 创建 Registry。
func New(genesis *pb.AdminSet, opts Options) (*Registry, error) {
	if genesis == nil {
		return nil, fmt.Errorf("futurecast: 创世 AdminSet 不能为空")
	}
	if err := ValidateGenesis(genesis); err != nil {
		return nil, err
	}
	grace := opts.GraceGenerations
	if grace == 0 {
		grace = DefaultGraceGenerations
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	kinds := adminRequiredKinds
	if len(opts.RequireAdminKinds) > 0 {
		kinds = opts.RequireAdminKinds
	}
	req := make(map[pb.MessageKind]bool, len(kinds))
	for _, k := range kinds {
		req[k] = true
	}
	r := &Registry{
		sets:           map[uint64]*pb.AdminSet{genesis.GetGeneration(): genesis},
		current:        genesis.GetGeneration(),
		graceGens:      grace,
		now:            nowFn,
		requireAdminOn: req,
		topics:         map[string]*pb.TopicPolicy{},
	}
	return r, nil
}

// ValidateGenesis 校验创世集：代数必须为 1，且不得带 previous_set_hash。
func ValidateGenesis(set *pb.AdminSet) error {
	if set.GetGeneration() != 1 {
		return fmt.Errorf("%w: 创世代数必须为 1，实为 %d", housekitchen.ErrGenerationMismatch, set.GetGeneration())
	}
	if !housekitchen.GetHash(set.GetPreviousSetHash()).IsZero() {
		return fmt.Errorf("%w: 创世集不得携带 previous_set_hash", housekitchen.ErrGenerationMismatch)
	}
	return validateSetShape(set)
}

func validateSetShape(set *pb.AdminSet) error {
	p := set.GetPolicy()
	if p == nil {
		return fmt.Errorf("futurecast: AdminSet 缺少 SigningPolicy")
	}
	if p.GetScheme() != pb.SigningScheme_SIGNING_SCHEME_ED25519_MULTISIG {
		return fmt.Errorf("futurecast: 暂不支持的签名方案 %v", p.GetScheme())
	}
	if p.GetThreshold() == 0 {
		return fmt.Errorf("futurecast: threshold 必须为正数")
	}
	if p.GetTotal() == 0 {
		return fmt.Errorf("futurecast: total 必须为正数")
	}
	if p.GetThreshold() > p.GetTotal() {
		return fmt.Errorf("futurecast: threshold(%d) 不得大于 total(%d)", p.GetThreshold(), p.GetTotal())
	}
	if int(p.GetTotal()) != len(set.GetKeys()) {
		return fmt.Errorf("futurecast: total(%d) 与 keys 数量(%d) 不一致", p.GetTotal(), len(set.GetKeys()))
	}
	if len(p.GetRootKeyIds()) == 0 {
		return fmt.Errorf("futurecast: root_key_ids 不能为空")
	}
	// keys 与 root_key_ids 必须一一对应，防止"成员表与门限表不一致"这类混淆攻击。
	inKeys := map[housekitchen.KeyID]bool{}
	for _, k := range set.GetKeys() {
		id := housekitchen.GetKeyID(k.GetKeyId())
		if housekitchen.KeyIDFromPub(k.GetPublicKey().GetEd25519()) != id {
			return fmt.Errorf("futurecast: key %s 的 key_id 与其公钥不匹配", id.Short())
		}
		inKeys[id] = true
	}
	if len(inKeys) != len(set.GetKeys()) {
		return fmt.Errorf("futurecast: AdminSet 中存在重复 key_id")
	}
	for _, rid := range p.GetRootKeyIds() {
		if !inKeys[housekitchen.GetKeyID(rid)] {
			return fmt.Errorf("futurecast: root_key_id %s 不在 keys 中", housekitchen.GetKeyID(rid).Short())
		}
	}
	return nil
}

// ValidateAdminSet 校验一次轮换：必须由 previous 集合的 >=threshold 把密钥签名。
func ValidateAdminSet(set, previous *pb.AdminSet, now time.Time) error {
	if previous == nil {
		return ValidateGenesis(set)
	}
	if err := validateSetShape(set); err != nil {
		return err
	}
	if set.GetGeneration() != previous.GetGeneration()+1 {
		return fmt.Errorf("%w: 代数必须严格 +1（旧 %d，新 %d）",
			housekitchen.ErrGenerationMismatch, previous.GetGeneration(), set.GetGeneration())
	}
	canonical, err := housekitchen.CanonicalAdminSet(set)
	if err != nil {
		return err
	}
	wantHash, err := housekitchen.AdminSetHash(previous)
	if err != nil {
		return err
	}
	if housekitchen.GetHash(set.GetPreviousSetHash()) != wantHash {
		return fmt.Errorf("%w: previous_set_hash 与上一代不符", housekitchen.ErrGenerationMismatch)
	}
	policy := previous.GetPolicy()
	skew := time.Duration(policy.GetClockSkewToleranceNanos())
	if skew <= 0 {
		skew = time.Duration(housekitchen.DefaultClockSkewNanos)
	}
	_, ok, err := crypto.MultisigVerify(canonical, set.GetSigners(), identity.RootKeyIDs(previous),
		identity.PubKeyResolver(previous), int(policy.GetThreshold()), now, skew)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: 轮换需要旧集合 %d 把密钥签名", housekitchen.ErrThresholdNotMet, policy.GetThreshold())
	}
	return nil
}

// Install 安装一个新代数的 AdminSet（会做完整链式校验）。
func (r *Registry) Install(set *pb.AdminSet) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	gen := set.GetGeneration()
	if existing, exists := r.sets[gen]; exists {
		// F8：同代但内容不同意味着发生了 equivocation（分裂视图）。
		// 早先这里静默返回 nil，会把攻击痕迹吞掉。必须显式报错。
		oldHash, err := housekitchen.AdminSetHash(existing)
		if err != nil {
			return err
		}
		newHash, err := housekitchen.AdminSetHash(set)
		if err != nil {
			return err
		}
		if oldHash != newHash {
			return fmt.Errorf("%w: 第 %d 代已存在不同内容（本地 %s，收到 %s）",
				housekitchen.ErrGenerationMismatch, gen, oldHash.Short(), newHash.Short())
		}
		return nil // 幂等
	}
	prev, ok := r.sets[gen-1]
	if !ok {
		return fmt.Errorf("%w: 缺少第 %d 代 AdminSet，无法校验第 %d 代",
			housekitchen.ErrGenerationMismatch, gen-1, gen)
	}
	if err := ValidateAdminSet(set, prev, r.now()); err != nil {
		return err
	}
	r.sets[gen] = set
	if gen > r.current {
		r.current = gen
	}
	r.pruneLocked()
	return nil
}

// pruneLocked 丢弃宽限窗之外的旧代数。
func (r *Registry) pruneLocked() {
	for gen := range r.sets {
		if r.current > gen && r.current-gen > r.graceGens {
			delete(r.sets, gen)
		}
	}
}

// Current 返回当前代数与集合。
func (r *Registry) Current() (uint64, *pb.AdminSet) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current, r.sets[r.current]
}

// SetAt 返回指定代数的集合。
func (r *Registry) SetAt(gen uint64) (*pb.AdminSet, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sets[gen]
	return s, ok
}

// SetForGeneration 返回指定代数的 AdminSet，用于需要按消息声明代数取集合的场景
// （例如定向广播：它的被签名对象是 DirectedBody，走独立校验路径）。
func (r *Registry) SetForGeneration(gen uint64) (*pb.AdminSet, bool) { return r.SetAt(gen) }

// Accepts 判断某代数是否在本地接受范围内（当前代或宽限窗内的历史代）。
func (r *Registry) Accepts(gen uint64) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.sets[gen]
	return ok
}

// AdminSetHashValid 校验 signer_set_hash 是否等于指定代数集合的摘要。
func (r *Registry) AdminSetHashValid(gen uint64, claimed housekitchen.Hash) (bool, error) {
	set, ok := r.SetAt(gen)
	if !ok {
		return false, fmt.Errorf("%w: 未知代数 %d", housekitchen.ErrGenerationMismatch, gen)
	}
	want, err := housekitchen.AdminSetHash(set)
	if err != nil {
		return false, err
	}
	return want == claimed, nil
}

// Session 描述一次消息校验所需的上下文。
//
// 关键设计：**作者身份是自证的，不由连接对端代表**。
// 消息在 Gossip 网络中会被中继转发，接收方的直接对端是转发者而不是作者，
// 因此无法用"连接对端 = 作者"来判定。作者身份由两件事共同保证：
//  1. SignedBody.author_pub 必须哈希出 SignedBody.author；
//  2. SignedBody.author_pub 对应的私钥必须对 canonical 签过名。
//
// AuthorNodeID / AuthorPub 仅作为**可选的一致性提示**：当调用方确实知道
// 直接对端的身份，且该身份恰好等于消息作者时，可以用来做交叉验证。
type Session struct {
	// AuthorNodeID 是连接对端的身份，可选。
	AuthorNodeID housekitchen.NodeID
	// AuthorPub 是连接对端的公钥，可选。
	AuthorPub ed25519.PublicKey
	// Now 覆盖当前时间，零值表示用 Registry 的时间源。
	Now time.Time
}

// Verification 是一次校验的结果详情。
type Verification struct {
	// AdminAuthorized 表示该消息已通过管理员门限校验。
	AdminAuthorized bool
	// Signers 是有效管理员签名者的 key_id。
	Signers []housekitchen.KeyID
	// Generation 是使用的管理员集合代数。
	Generation uint64
	// NodeSigned 表示该消息由普通节点自签。
	NodeSigned bool
}

// VerifyMessage 执行完整校验管线，失败返回具体错误。
func (r *Registry) VerifyMessage(env *pb.Envelope, sess Session) (Verification, error) {
	var out Verification
	if env == nil {
		return out, fmt.Errorf("futurecast: Envelope 为空")
	}
	body := env.GetBody()
	if body == nil {
		return out, fmt.Errorf("futurecast: Envelope 缺少 SignedBody")
	}
	// 0. 协议版本（F6：此前完全未校验，version=999 会被接受）
	if v := body.GetProtoVersion(); v < housekitchen.MinProtoVersion || v > housekitchen.ProtoVersion {
		return out, fmt.Errorf("%w: 正文声明版本 %d，本地支持 [%d, %d]",
			housekitchen.ErrProtocolVersion, v, housekitchen.MinProtoVersion, housekitchen.ProtoVersion)
	}
	// 1. 内容寻址
	if err := housekitchen.VerifyMsgID(body); err != nil {
		return out, err
	}
	if housekitchen.GetHash(env.GetMsgId()) != housekitchen.GetHash(body.GetMsgId()) {
		return out, fmt.Errorf("%w: 信封 msg_id 与正文不一致", housekitchen.ErrMsgIDMismatch)
	}
	// 2. 时间窗与过期
	now := sess.Now
	if now.IsZero() {
		now = r.now()
	}
	nowNanos := now.UnixNano()
	created := body.GetCreatedAtUnixNanos()
	exp := body.GetExpiresAtUnixNanos()
	// F10：不再把 expires_at==0 当作"永不过期"。
	// 曾经的含义会让一条签发于十年前、声明永不过期的消息永久有效，
	// 攻击者只要拿到一把旧密钥即可无限期重放。现在两个时间戳都必须有界。
	if created <= 0 {
		return out, fmt.Errorf("%w: created_at 必须为正数", housekitchen.ErrClockSkew)
	}
	if exp <= created {
		return out, fmt.Errorf("%w: expires_at(%d) 必须晚于 created_at(%d)", housekitchen.ErrExpired, exp, created)
	}
	if nowNanos > exp {
		return out, fmt.Errorf("%w: 消息已于 %s 过期", housekitchen.ErrExpired, time.Unix(0, exp).Format(time.RFC3339))
	}
	if created > nowNanos+int64(time.Duration(housekitchen.DefaultClockSkewNanos)) {
		return out, fmt.Errorf("%w: created_at 超前", housekitchen.ErrClockSkew)
	}
	// 3. 代数必须被接受
	gen := body.GetAdminSetGeneration()
	set, ok := r.SetAt(gen)
	if !ok {
		return out, fmt.Errorf("%w: 消息声明的代数 %d 不在接受范围内", housekitchen.ErrGenerationMismatch, gen)
	}
	out.Generation = gen
	// 4. signer_set_hash 必须绑定该代集合
	okHash, err := r.AdminSetHashValid(gen, housekitchen.GetHash(body.GetSignerSetHash()))
	if err != nil {
		return out, err
	}
	if !okHash {
		return out, fmt.Errorf("%w: signer_set_hash 与第 %d 代集合不符", housekitchen.ErrSignerSetMismatch, gen)
	}

	canonical, err := housekitchen.CanonicalSignedBody(body)
	if err != nil {
		return out, err
	}
	rootIDs := identity.RootKeyIDs(set)

	// 5. 依据消息类型决定验证通道
	//
	// **安全关键（F4）**：门限、root_key_ids 与方案一律取自**本地**该代 AdminSet，
	// 绝不使用 body.GetPolicy()。body.policy 是签名者自填的字段，虽然它被签名
	// 保护（改它会让 msg_id 与签名失配），但签名者完全可以在**签发时**就把
	// threshold 写成 1 —— 那样一把管理员密钥即可自签一条"合法"广播，2-of-3 名存实亡。
	// 因此这里只允许 body.policy 与本地集合**一致**，不一致直接拒绝。
	localPolicy := set.GetPolicy()
	if bodyPolicy := body.GetPolicy(); bodyPolicy != nil {
		if err := policyMatchesLocal(bodyPolicy, localPolicy); err != nil {
			return out, err
		}
	}
	needsAdmin := r.requireAdminOn[body.GetKind()]
	if needsAdmin {
		policy := localPolicy
		skew := time.Duration(policy.GetClockSkewToleranceNanos())
		if skew <= 0 {
			skew = time.Duration(housekitchen.DefaultClockSkewNanos)
		}
		res, thresholdMet, err := crypto.MultisigVerify(canonical, body.GetSigners(), rootIDs,
			identity.PubKeyResolver(set), int(policy.GetThreshold()), now, skew)
		if err != nil {
			return out, err
		}
		out.Signers = res.Signers
		if !thresholdMet {
			return out, fmt.Errorf("%w: %s 需要 %d/%d 签名，实际有效 %d（被忽略 %d）",
				housekitchen.ErrThresholdNotMet, body.GetKind(), policy.GetThreshold(), policy.GetTotal(),
				res.Valid, len(res.Rejected))
		}
		if !housekitchen.GetNodeID(body.GetAuthor()).IsZero() {
			return out, fmt.Errorf("%w: 管理员消息不得携带 author 字段", housekitchen.ErrNotAuthorized)
		}
		out.AdminAuthorized = true
		return out, nil
	}

	// 节点消息：必须由声明的作者用自己的节点密钥自签。
	authorID := housekitchen.GetNodeID(body.GetAuthor())
	if authorID.IsZero() {
		return out, fmt.Errorf("%w: 节点消息缺少 author", housekitchen.ErrNotAuthorized)
	}
	authorPub, err := authorPublicKey(body, authorID, sess)
	if err != nil {
		return out, err
	}
	authorSig := firstSignatureFor(body, authorPub)
	if authorSig == nil {
		return out, fmt.Errorf("%w: 节点消息缺少作者自签", housekitchen.ErrInvalidSignature)
	}
	if err := crypto.VerifySignature(authorPub, canonical, authorSig); err != nil {
		return out, fmt.Errorf("%w: 节点自签校验失败: %v", housekitchen.ErrInvalidSignature, err)
	}
	out.NodeSigned = true

	// 节点消息如果同时满足管理员门限，额外标记为管理员授权（例如超管以节点身份发布）。
	policy := localPolicy
	skew := time.Duration(policy.GetClockSkewToleranceNanos())
	if skew <= 0 {
		skew = time.Duration(housekitchen.DefaultClockSkewNanos)
	}
	if res, met, err := crypto.MultisigVerify(canonical, body.GetSigners(), rootIDs,
		identity.PubKeyResolver(set), int(policy.GetThreshold()), now, skew); err == nil {
		out.Signers = res.Signers
		if met {
			out.AdminAuthorized = true
		}
	}
	return out, nil
}

// policyMatchesLocal 要求消息自带的 policy 与本地该代集合完全一致。
//
// 这是 F4 的防线：门限只认本地集合，签名者自填的 policy 只能"一致或被拒"。
func policyMatchesLocal(bodyPolicy, local *pb.SigningPolicy) error {
	if local == nil {
		return fmt.Errorf("futurecast: 本地 AdminSet 缺少 policy")
	}
	if bodyPolicy.GetThreshold() != local.GetThreshold() {
		return fmt.Errorf("%w: 正文声明 threshold=%d，本地为 %d",
			housekitchen.ErrThresholdNotMet, bodyPolicy.GetThreshold(), local.GetThreshold())
	}
	if bodyPolicy.GetTotal() != local.GetTotal() {
		return fmt.Errorf("%w: 正文声明 total=%d，本地为 %d",
			housekitchen.ErrThresholdNotMet, bodyPolicy.GetTotal(), local.GetTotal())
	}
	if bodyPolicy.GetScheme() != local.GetScheme() {
		return fmt.Errorf("%w: 正文声明 scheme=%v，本地为 %v",
			housekitchen.ErrThresholdNotMet, bodyPolicy.GetScheme(), local.GetScheme())
	}
	want := make(map[housekitchen.KeyID]struct{}, len(local.GetRootKeyIds()))
	for _, k := range local.GetRootKeyIds() {
		want[housekitchen.GetKeyID(k)] = struct{}{}
	}
	got := make(map[housekitchen.KeyID]struct{}, len(bodyPolicy.GetRootKeyIds()))
	for _, k := range bodyPolicy.GetRootKeyIds() {
		got[housekitchen.GetKeyID(k)] = struct{}{}
	}
	if len(want) != len(got) {
		return fmt.Errorf("%w: 正文声明的 root_key_ids 数量与本地不一致", housekitchen.ErrThresholdNotMet)
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			return fmt.Errorf("%w: 正文声明了本地集合中不存在的 root_key_id %s", housekitchen.ErrThresholdNotMet, k.Short())
		}
	}
	return nil
}

// authorPublicKey 解析并校验节点消息的作者公钥。
//
// 优先级：消息自带的 author_pub（可独立验证，支持中继转发）
// 高于连接对端提供的 AuthorPub（仅用于交叉验证）。
func authorPublicKey(body *pb.SignedBody, authorID housekitchen.NodeID, sess Session) (ed25519.PublicKey, error) {
	pub := body.GetAuthorPub()
	if len(pub) > 0 {
		if len(pub) != crypto.PubKeySize {
			return nil, fmt.Errorf("%w: author_pub 长度非法", housekitchen.ErrInvalidSignature)
		}
		key := ed25519.PublicKey(pub)
		if housekitchen.NodeIDFromPub(key) != authorID {
			return nil, fmt.Errorf("%w: author_pub 与 author 不匹配", housekitchen.ErrPeerIDMismatch)
		}
		// 若调用方知道直接对端身份，做一个交叉校验：
		// 只有当对端恰好就是作者时才施加约束，中继转发场景不适用。
		if !sess.AuthorNodeID.IsZero() && sess.AuthorNodeID == authorID &&
			len(sess.AuthorPub) == crypto.PubKeySize &&
			housekitchen.NodeIDFromPub(sess.AuthorPub) != authorID {
			return nil, fmt.Errorf("%w: 对端自称是作者但公钥不符", housekitchen.ErrPeerIDMismatch)
		}
		return key, nil
	}
	// 兼容路径：消息未携带公钥时，只能用连接对端的身份。
	if len(sess.AuthorPub) != crypto.PubKeySize {
		return nil, fmt.Errorf("%w: 缺少 author_pub 且连接对端公钥不可用", housekitchen.ErrNotAuthorized)
	}
	if housekitchen.NodeIDFromPub(sess.AuthorPub) != authorID {
		return nil, fmt.Errorf("%w: author 与连接对端身份不符，且消息未携带 author_pub", housekitchen.ErrPeerIDMismatch)
	}
	return sess.AuthorPub, nil
}

// firstSignatureFor 找到由给定公钥派生的 key_id 对应的签名。
func firstSignatureFor(body *pb.SignedBody, pub ed25519.PublicKey) *pb.Signature {
	want := housekitchen.KeyIDFromPub(pub)
	for _, s := range body.GetSigners() {
		if housekitchen.GetKeyID(s.GetKeyId()) == want {
			return s
		}
	}
	return nil
}

// SetTopicPolicy 记录一个已通过校验的主题策略。
func (r *Registry) SetTopicPolicy(p *pb.TopicPolicy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.topics[p.GetTopic()] = p
}

// TopicPolicy 查询主题策略。
func (r *Registry) TopicPolicy(topic string) (*pb.TopicPolicy, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.topics[topic]
	return p, ok
}

// TopicAllowed 判断在给定验证结果下，消息是否被主题策略允许。
func (r *Registry) TopicAllowed(topic string, adminAuthorized bool) bool {
	p, ok := r.TopicPolicy(topic)
	if !ok {
		// 未声明策略的主题：仅管理员可写。
		return adminAuthorized
	}
	switch p.GetWritePolicy() {
	case pb.WritePolicy_WRITE_POLICY_ADMIN_ONLY:
		return adminAuthorized
	case pb.WritePolicy_WRITE_POLICY_NODE_ALLOWED:
		return true
	case pb.WritePolicy_WRITE_POLICY_KEYRING:
		return adminAuthorized
	default:
		return adminAuthorized
	}
}
