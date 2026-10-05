// Package sealed 实现"封存信封 + 中继转发 + rendezvous 信箱"。
//
// 设计目标（见 docs/DESIGN.md §5.2–5.5）：
//   - 超级管理员在 sealed 模式下不监听任何端口，只主动出站连接中继；
//   - 中继无法读取内层内容（端到端加密），也无法判断提交者是谁；
//   - 每个中继解封后用**自己的节点身份**重新签名发布，因此公网上看到的是
//     若干个互不相关的普通节点各自发布了一条消息，无法据此定位超管。
package sealed

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// adPrefix 是 AEAD 关联数据的域分隔前缀。
//
// 冻结值：AD = "futurecast/v1/sealed\x00" || rendezvous_id(32B) || u64be(epoch)
const adPrefix = "futurecast/v1/sealed\x00"

// sealedInfo 是封存密钥派生的 HKDF info（冻结值）。
const sealedInfo = "fc/v1/sealed"

// inboxInfoPrefix 是 rendezvous_id 派生的 HKDF info 前缀。
//
// 冻结值：info = "fc/v1/inbox" || "/" || 十进制(epoch)
// 采用十进制文本是为了让不同语言实现不必猜测整数编码；epoch 本身是公开值，
// 不构成秘密，因此不需要定长二进制编码。
const inboxInfoPrefix = housekitchen.DomainInbox

// EpochFor 返回给定时间所属的信箱代（按 epochDuration 取整）。
func EpochFor(at time.Time, epochDuration time.Duration) uint64 {
	if epochDuration <= 0 {
		epochDuration = 24 * time.Hour
	}
	return uint64(at.Unix() / int64(epochDuration.Seconds()))
}

// RendezvousFor 计算某代数的信箱 ID。
//
//	rendezvous_id = HKDF-SHA256(adminSeed, salt=nil, info=DomainInbox, 32) 的 epoch 轮
//
// 通过把 epoch 编入 info，不同代之间不可关联；任何人知道 epoch 都能算出同一个集合。
func RendezvousFor(adminSeed []byte, epoch uint64) (housekitchen.Hash, error) {
	info := fmt.Sprintf("%s/%d", inboxInfoPrefix, epoch)
	raw, err := crypto.HKDF(adminSeed, nil, info, housekitchen.HashSize)
	if err != nil {
		return housekitchen.Hash{}, err
	}
	var h housekitchen.Hash
	copy(h[:], raw)
	return h, nil
}

// associatedData 构造 AEAD 关联数据，把密文绑定到具体信箱与代。
func associatedData(rendezvous housekitchen.Hash, epoch uint64) []byte {
	out := make([]byte, 0, len(adPrefix)+housekitchen.HashSize+8)
	out = append(out, adPrefix...)
	out = append(out, rendezvous.Bytes()...)
	out = append(out, housekitchen.Uint64BE(epoch)...)
	return out
}

// Seal 用收件人中继的 X25519 公钥加密一个 SignedBody。
//
// 返回的 SealedPayload 里的 Ciphertext 已包含 nonce 前缀（crypto.SealForRecipient 的约定）。
func Seal(recipientX25519Pub []byte, body *pb.SignedBody, rendezvous housekitchen.Hash,
	epoch uint64, jitterHintMS uint64) (*pb.SealedPayload, error) {

	if body == nil {
		return nil, fmt.Errorf("%w: 待封存的 SignedBody 为空", housekitchen.ErrSealedInvalid)
	}
	if len(recipientX25519Pub) != crypto.X25519KeySize {
		return nil, fmt.Errorf("%w: 中继 X25519 公钥长度应为 %d", housekitchen.ErrSealedInvalid, crypto.X25519KeySize)
	}
	plaintext, err := housekitchen.CanonicalSignedBody(body)
	if err != nil {
		return nil, err
	}
	// 规范化字节清空了 msg_id 与 signers，封存时必须把二者一并带回，
	// 因此这里序列化的是"带签名的完整 body"。
	full, err := marshalFullBody(body)
	if err != nil {
		return nil, err
	}
	_ = plaintext

	eph, err := crypto.GenerateX25519()
	if err != nil {
		return nil, err
	}
	ephPub, ct, err := crypto.SealForRecipient(eph.Private, recipientX25519Pub, full,
		associatedData(rendezvous, epoch), sealedInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", housekitchen.ErrSealedInvalid, err)
	}
	return &pb.SealedPayload{
		InboxRendezvousId: housekitchen.PBHash(rendezvous),
		Epoch:             epoch,
		EphemeralX25519:   ephPub,
		Ciphertext:        ct,
		JitterHintMs:      jitterHintMS,
	}, nil
}

// Open 用本节点 X25519 私钥解封，返回内层完整的 SignedBody（含 msg_id 与 signers）。
func Open(selfX25519Priv []byte, sp *pb.SealedPayload) (*pb.SignedBody, error) {
	if sp == nil {
		return nil, fmt.Errorf("%w: SealedPayload 为空", housekitchen.ErrSealedInvalid)
	}
	if len(selfX25519Priv) != crypto.X25519KeySize {
		return nil, fmt.Errorf("%w: 本节点 X25519 私钥长度非法", housekitchen.ErrSealedInvalid)
	}
	rendezvous := housekitchen.GetHash(sp.GetInboxRendezvousId())
	plaintext, err := crypto.OpenFromSender(selfX25519Priv, sp.GetEphemeralX25519(), sp.GetCiphertext(),
		associatedData(rendezvous, sp.GetEpoch()), sealedInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", housekitchen.ErrSealedInvalid, err)
	}
	body, err := unmarshalFullBody(plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", housekitchen.ErrSealedInvalid, err)
	}
	return body, nil
}

// CiphertextDigest 返回封存密文的摘要，用于中继侧去重（同一封存重复投递只发布一次）。
func CiphertextDigest(sp *pb.SealedPayload) housekitchen.Hash {
	return housekitchen.HashOf([]byte("futurecast/v1/sealeddigest\x00"), sp.GetCiphertext())
}

// RelayCandidate 是一个候选中继。
type RelayCandidate struct {
	NodeID    housekitchen.NodeID
	X25519Pub []byte
}

// SelectRelays 按 XOR 距离选取离 rendezvous 最近的 k 个候选。
//
// 确定性：任何节点只要知道 rendezvous 与候选集合，算出的结果完全一致。
// 但候选集合本身取决于"谁在线"，因此实际中继对不会长期固定。
func SelectRelays(rendezvous housekitchen.Hash, candidates []RelayCandidate, k int) []RelayCandidate {
	if k <= 0 || len(candidates) == 0 {
		return nil
	}
	target := housekitchen.NodeID(rendezvous)
	out := make([]RelayCandidate, len(candidates))
	copy(out, candidates)
	sort.SliceStable(out, func(i, j int) bool {
		return housekitchen.CompareNodeID(target, out[i].NodeID, out[j].NodeID) < 0
	})
	if k > len(out) {
		k = len(out)
	}
	return out[:k]
}

// Jitter 在 [min, max] 内返回一个随机抖动时长。
//
// 抖动的目的：打散"超管提交 → 中继发布"的时间关联。
// 默认区间 [200ms, 2500ms]：上限刻意压在 INV 周期（3s）之内，
// 使封存副本最迟也能在同一轮 anti-entropy 里被补齐，时效性不受损。
func Jitter(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(rand.Int63n(int64(max-min)))
}

// ---------- 信箱（rendezvous mailbox） ----------

type mailboxEntry struct {
	env *pb.Envelope
	at  time.Time
}

// Mailbox 是中继侧保存封存消息的本地信箱。
type Mailbox struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	entries  map[housekitchen.Hash][]mailboxEntry
	order    []housekitchen.Hash // 简易 FIFO，用于超容量淘汰
}

// NewMailbox 创建信箱。
func NewMailbox(capacity int, ttl time.Duration) *Mailbox {
	if capacity <= 0 {
		capacity = 128
	}
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	return &Mailbox{capacity: capacity, ttl: ttl, entries: map[housekitchen.Hash][]mailboxEntry{}}
}

// Store 保存一条待发布/待拉取的封存消息。
func (m *Mailbox) Store(rendezvous housekitchen.Hash, env *pb.Envelope, at time.Time) error {
	if env == nil {
		return fmt.Errorf("%w: 信封为空", housekitchen.ErrSealedInvalid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gcLocked(at)

	list := m.entries[rendezvous]
	for _, e := range list {
		if housekitchen.GetHash(e.env.GetMsgId()) == housekitchen.GetHash(env.GetMsgId()) {
			return housekitchen.ErrDuplicate
		}
	}
	m.entries[rendezvous] = append(list, mailboxEntry{env: env, at: at})
	m.order = append(m.order, rendezvous)

	// 超出容量：从最旧的信箱条目开始淘汰。
	for m.totalLocked() > m.capacity && len(m.order) > 0 {
		oldest := m.order[0]
		m.order = m.order[1:]
		l := m.entries[oldest]
		if len(l) == 0 {
			continue
		}
		m.entries[oldest] = l[1:]
		if len(m.entries[oldest]) == 0 {
			delete(m.entries, oldest)
		}
	}
	return nil
}

// Fetch 按时间窗拉取某个信箱的消息。
func (m *Mailbox) Fetch(rendezvous housekitchen.Hash, since time.Time, limit int) []*pb.Envelope {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.entries[rendezvous]
	out := make([]*pb.Envelope, 0, len(list))
	for _, e := range list {
		if e.at.After(since) || e.at.Equal(since) {
			out = append(out, e.env)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

// GC 清除过期条目，返回清除数量。
func (m *Mailbox) GC(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gcLocked(now)
}

func (m *Mailbox) gcLocked(now time.Time) int {
	removed := 0
	for r, list := range m.entries {
		kept := list[:0]
		for _, e := range list {
			if now.Sub(e.at) > m.ttl {
				removed++
				continue
			}
			kept = append(kept, e)
		}
		if len(kept) == 0 {
			delete(m.entries, r)
		} else {
			m.entries[r] = kept
		}
	}
	return removed
}

func (m *Mailbox) totalLocked() int {
	n := 0
	for _, l := range m.entries {
		n += len(l)
	}
	return n
}

// Len 返回信箱内总条目数。
func (m *Mailbox) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.totalLocked()
}

// ---------- 统一中继义务 ----------

type quotaEntry struct {
	count int
	seen  time.Time
}

// RelayDuty 实现"所有节点平等承担中继义务"的配额控制。
//
// 之所以让每个节点都当中继，是为了让"某节点在搬运封存消息"这件事
// 本身不构成任何信号（见设计文档 §5.4）。
type RelayDuty struct {
	mu       sync.Mutex
	policy   *pb.RelayPolicy
	perInbox map[housekitchen.Hash]*quotaEntry
	window   time.Duration
}

// NewRelayDuty 由中继策略创建义务控制器。
func NewRelayDuty(policy *pb.RelayPolicy) *RelayDuty {
	if policy == nil {
		policy = &pb.RelayPolicy{
			Mandatory:     false,
			PerInboxQuota: 128,
			MinJitterMs:   200,
			MaxJitterMs:   5000,
		}
	}
	if policy.GetPerInboxQuota() == 0 {
		policy.PerInboxQuota = 128
	}
	return &RelayDuty{
		policy:   policy,
		perInbox: map[housekitchen.Hash]*quotaEntry{},
		window:   time.Hour,
	}
}

// ShouldRelay 返回本节点是否必须承担中继义务。
//
// 注意：即使 mandatory=false，节点仍然"可以"转发封存消息
// （因为封存消息对转发者就是普通节点消息），只是不强制保留信箱副本。
func (d *RelayDuty) ShouldRelay() bool { return d.policy.GetMandatory() }

// Policy 返回当前策略副本。
func (d *RelayDuty) Policy() *pb.RelayPolicy {
	d.mu.Lock()
	defer d.mu.Unlock()
	cp, _ := proto.Clone(d.policy).(*pb.RelayPolicy)
	return cp
}

// Admit 判断某个信箱是否还能接收新条目，超配额返回 ErrRateLimited。
func (d *RelayDuty) Admit(rendezvous housekitchen.Hash, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.perInbox[rendezvous]
	if !ok || at.Sub(e.seen) > d.window {
		d.perInbox[rendezvous] = &quotaEntry{count: 1, seen: at}
		return nil
	}
	if e.count >= int(d.policy.GetPerInboxQuota()) {
		return fmt.Errorf("%w: 信箱 %s 已达配额 %d", housekitchen.ErrRateLimited,
			rendezvous.Short(), d.policy.GetPerInboxQuota())
	}
	e.count++
	e.seen = at
	return nil
}

// JitterBounds 返回策略允许的抖动区间。
func (d *RelayDuty) JitterBounds() (time.Duration, time.Duration) {
	min := time.Duration(d.policy.GetMinJitterMs()) * time.Millisecond
	max := time.Duration(d.policy.GetMaxJitterMs()) * time.Millisecond
	if max <= 0 {
		max = 5 * time.Second
	}
	if min < 0 {
		min = 0
	}
	return min, max
}

// ---------- 内部：完整 body 的序列化 ----------

func marshalFullBody(body *pb.SignedBody) ([]byte, error) {
	return marshalProto(body)
}

func unmarshalFullBody(b []byte) (*pb.SignedBody, error) {
	out := &pb.SignedBody{}
	if err := unmarshalProto(b, out); err != nil {
		return nil, err
	}
	return out, nil
}

// dailyKey 由节点密钥派生当日轮换标签密钥，供 crypto.RelayTag 使用。
func DailyKey(seed []byte, at time.Time) []byte {
	day := uint64(at.Unix() / 86400)
	sum := sha256.Sum256(append(append([]byte("futurecast/v1/dailykey\x00"), seed...), housekitchen.Uint64BE(day)...))
	return sum[:]
}
