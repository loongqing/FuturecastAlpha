# FutureCast 冻结接口契约（v0.2-P0）

> **本文件由 Lead 维护，是并行开发的唯一接口依据。**
> 任何包都不得修改他人写域内的文件；需要新增能力时，请向 Lead 提请求而不是直接改。

## 0. 环境（必须）

```bash
export GOPROXY=https://goproxy.cn,direct   # 公网 proxy.golang.org 不可达，必须用镜像
export GOSUMDB=off
export PATH=$PATH:/root/go/bin             # protoc-gen-go
```

- Go `1.22.2 linux/arm64`；`protoc` `libprotoc 3.21.12`。
- 依赖：`github.com/quic-go/quic-go v0.48.2`、`golang.org/x/crypto v0.26.0`、`google.golang.org/protobuf v1.34.2`。
- 生成代码在 `gen/futurecastv1/`，**勿手改**。改协议请改 `proto/futurecast/v1/*.proto` 后运行 `make proto`。

## 1. 包依赖方向（禁止反向依赖）

```
housekitchen  ← 基础，无内部依赖
crypto        → housekitchen
identity      → crypto, housekitchen
registry      → crypto, identity, housekitchen
store         → housekitchen
peer          → housekitchen, crypto
sealed        → crypto, housekitchen, identity, registry
transport     → housekitchen, crypto, identity, registry
node          → 全部
```

**`store` 与 `peer` 不得导入 `registry` / `identity` / `node`。**

## 2. `internal/housekitchen`（Lead 所有，冻结）

```go
// 定长 ID
type Hash [32]byte;  type KeyID [16]byte;  type NodeID [32]byte
func Sum256(b []byte) Hash
func HashOf(parts ...[]byte) Hash
func KeyIDFromPub(pub []byte) KeyID
func NodeIDFromPub(pub []byte) NodeID
func (h Hash) Bytes() []byte;  func (h Hash) Short() string;  func (h Hash) String() string
func KeyIDFromBytes(b []byte) (KeyID, error);  func NodeIDFromBytes(...);  func HashFromBytes(...)
func KeyIDFromHex(s string) (KeyID, error);    func NodeIDFromHex(...);    func HashFromHex(...)
func XorDistance(a, b NodeID) NodeID
func CommonPrefixLen(a, b NodeID) int           // Kademlia 桶序号
func CompareNodeID(target, a, b NodeID) int     // -1: a 更近
func ConstantTimeEqual(a, b []byte) bool
func RandomBytes(n int) []byte;  func RandomNonce() []byte;  func RandomUint64() uint64
func Uint64BE(v uint64) []byte;  func Uint32BE(b []byte) uint32

// 规范化编码（签名/哈希的唯一依据）
func CanonicalSignedBody(b *pb.SignedBody) ([]byte, error)   // 清空 msg_id + signers
func CanonicalAdminSet(s *pb.AdminSet) ([]byte, error)       // 清空 signers
func CanonicalNodeAnnounce(a *pb.NodeAnnounce) ([]byte, error)
func CanonicalPeerExchange(p *pb.PeerExchange) ([]byte, error)
func CanonicalHello(h *pb.Hello) ([]byte, error)
func CanonicalSealedPayload(s *pb.SealedPayload) ([]byte, error)
func CanonicalEnvelope(e *pb.Envelope) ([]byte, error)
func AdminSetHash(s *pb.AdminSet) (Hash, error)
func MsgIDFromCanonical(canonical []byte) Hash
func MsgID(b *pb.SignedBody) (Hash, error)
func VerifyMsgID(b *pb.SignedBody) error
func SignInput(canonical []byte, keyID KeyID, signedAtUnixNanos int64) Hash
func GetHash(*pb.Hash) Hash;  func GetKeyID(*pb.KeyID) KeyID;  func GetNodeID(*pb.NodeID) NodeID
func PBHash(Hash) *pb.Hash;   func PBKeyID(KeyID) *pb.KeyID;   func PBNodeID(NodeID) *pb.NodeID

// 常量
ProtoVersion, MinProtoVersion
DefaultMaxFrameSize=1MiB, DefaultMaxHops=32, DefaultFanout=6
DefaultMinPeers=8, DefaultMaxPeers=64
DefaultGossipIntervalMS=3000, DefaultBucketRefreshMS=30000, DefaultLivenessMS=90000
DefaultMsgTTLNanos, DefaultClockSkewNanos, DefaultDedupCapacity=50000
DomainHello, DomainNodeAnnounce, DomainPeerExchange, DomainSealedPayload,
DomainInbox="fc/v1/inbox", DomainRelayTag, DomainTopicKey

// 错误哨兵（一律 errors.Is 判定）
ErrInvalidSignature, ErrThresholdNotMet, ErrGenerationMismatch, ErrSignerSetMismatch,
ErrMsgIDMismatch, ErrExpired, ErrClockSkew, ErrMaxHops, ErrUnknownTopic, ErrDuplicate,
ErrRateLimited, ErrBanned, ErrFrameTooLarge, ErrProtocolVersion, ErrPeerIDMismatch,
ErrSealedInvalid, ErrNotAuthorized
```

## 3. `internal/crypto`（Lead 所有，冻结）

```go
const SeedSize=32, PubKeySize=32, SigSize=64, X25519KeySize=32

func Sign(priv ed25519.PrivateKey, msg []byte) []byte
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool
func KeyFromSeed(seed []byte) (ed25519.PrivateKey, error)
func GenerateSeed() ([]byte, error)

func SignBody(priv ed25519.PrivateKey, canonical []byte, keyID housekitchen.KeyID, signedAt time.Time) *pb.Signature
func VerifySignature(pub ed25519.PublicKey, canonical []byte, sig *pb.Signature) error

type MultisigResult struct { Valid int; Signers []housekitchen.KeyID; Rejected []RejectedSignature }
type RejectedSignature struct { KeyID housekitchen.KeyID; Reason string }
func MultisigVerify(canonical []byte, sigs []*pb.Signature, rootKeys []housekitchen.KeyID,
	pubKeyOf func(housekitchen.KeyID) (ed25519.PublicKey, bool),
	threshold int, now time.Time, skew time.Duration) (MultisigResult, bool, error)

func SignWithDomain(priv ed25519.PrivateKey, domain string, canonical []byte) []byte
func VerifyWithDomain(pub ed25519.PublicKey, domain string, canonical, sig []byte) bool

type X25519KeyPair struct { Public, Private []byte }
func GenerateX25519() (X25519KeyPair, error)
func X25519Shared(priv, peerPub []byte) ([]byte, error)
func HKDF(secret, salt []byte, info string, length int) ([]byte, error)
func SealAEAD(key, plaintext, associatedData []byte) ([]byte, error)   // 输出 nonce||ct
func OpenAEAD(key, sealed, associatedData []byte) ([]byte, error)
func SealForRecipient(ephPriv, recipientPub, plaintext, associatedData []byte, info string) (ephemeralPub, sealed []byte, err error)
func OpenFromSender(recipientPriv, ephemeralPub, sealed, associatedData []byte, info string) ([]byte, error)
func RelayTag(dailyKey []byte, msgID housekitchen.Hash, previousTag uint64) uint64
func WrapTopicKey(ephPriv, recipientPub, topicKey, associatedData []byte) ([]byte, error)
func UnwrapTopicKey(recipientPriv, ephemeralPub, wrapped, associatedData []byte) ([]byte, error)
```

## 4. `internal/identity`（Lead 所有，冻结）

```go
type NodeIdentity struct { ID housekitchen.NodeID; Priv ed25519.PrivateKey; Pub ed25519.PublicKey; KeySeed []byte }
func NewNodeIdentity() (*NodeIdentity, error)
func NodeIdentityFromSeed(seed []byte) (*NodeIdentity, error)
func LoadOrCreateNodeIdentity(path string) (*NodeIdentity, error)   // 0600，magic 文本格式
func (n *NodeIdentity) SignHello(h *pb.Hello) ([]byte, error)
func VerifyHello(h *pb.Hello) error
func (n *NodeIdentity) SignNodeAnnounce(a *pb.NodeAnnounce) ([]byte, error)
func VerifyNodeAnnounceWithPub(pub ed25519.PublicKey, a *pb.NodeAnnounce) error
func (n *NodeIdentity) SignPeerExchange(pe *pb.PeerExchange) ([]byte, error)
func VerifyPeerExchange(pub ed25519.PublicKey, pe *pb.PeerExchange) error

type AdminKey struct { KeyID housekitchen.KeyID; Label string; Role pb.AdminRole
                       Priv ed25519.PrivateKey; Pub ed25519.PublicKey; KeySeed []byte }
func NewAdminKey(label string, role pb.AdminRole) (*AdminKey, error)
func AdminKeyFromSeed(seed []byte, label string, role pb.AdminRole) (*AdminKey, error)
func (k *AdminKey) Public() *pb.AdminKey
func (k *AdminKey) Sign(canonical []byte, at time.Time) *pb.Signature

type Keyring struct { Keys map[housekitchen.KeyID]*AdminKey }
func NewKeyring() *Keyring
func (r *Keyring) Add(k *AdminKey);  func (r *Keyring) Get(id housekitchen.KeyID) (*AdminKey, bool)
func (r *Keyring) BuildAdminSet(generation uint64, threshold, total uint32, label string) (*pb.AdminSet, error)
func PubKeyResolver(set *pb.AdminSet) func(housekitchen.KeyID) (ed25519.PublicKey, bool)
func RootKeyIDs(set *pb.AdminSet) []housekitchen.KeyID
```

## 5. `internal/registry`（Lead 所有，冻结）

```go
type Options struct { GraceGenerations uint64; Now func() time.Time; RequireAdminKinds []pb.MessageKind }
func New(genesis *pb.AdminSet, opts Options) (*Registry, error)
func ValidateGenesis(set *pb.AdminSet) error
func ValidateAdminSet(set, previous *pb.AdminSet, now time.Time) error
func (r *Registry) Install(set *pb.AdminSet) error          // 幂等；链式校验
func (r *Registry) Current() (uint64, *pb.AdminSet)
func (r *Registry) SetAt(gen uint64) (*pb.AdminSet, bool)
func (r *Registry) Accepts(gen uint64) bool

type Session struct { AuthorNodeID housekitchen.NodeID; AuthorPub ed25519.PublicKey; Now time.Time }
type Verification struct { AdminAuthorized bool; Signers []housekitchen.KeyID; Generation uint64; NodeSigned bool }
func (r *Registry) VerifyMessage(env *pb.Envelope, sess Session) (Verification, error)

func (r *Registry) SetTopicPolicy(p *pb.TopicPolicy)
func (r *Registry) TopicPolicy(topic string) (*pb.TopicPolicy, bool)
func (r *Registry) TopicAllowed(topic string, adminAuthorized bool) bool

// 签发侧
func NewAdminBroadcast(set *pb.AdminSet, topic, text, mediaType string, ttl time.Duration, now time.Time) (*pb.SignedBody, error)
func NewNodeMessage(author *identity.NodeIdentity, kind pb.MessageKind, topic string, payload *pb.Payload, set *pb.AdminSet, ttl time.Duration, now time.Time) (*pb.SignedBody, error)
func CanonicalForSigning(body *pb.SignedBody) ([]byte, error)
func FinalizeAdminBody(body *pb.SignedBody, canonical []byte, keys []*identity.AdminKey, threshold int, now time.Time) error
func FinalizeNodeBody(body *pb.SignedBody, canonical []byte, author *identity.NodeIdentity, now time.Time) error
func WrapEnvelope(body *pb.SignedBody, now time.Time) *pb.Envelope
func SignAdminSet(next, prev *pb.AdminSet, keys []*identity.AdminKey, threshold int, now time.Time) error
```

### 5.1 验证管线顺序（已实现，勿改语义）

1. `VerifyMsgID(body)` → `ErrMsgIDMismatch`（**最先**，篡改优先于一切语义检查）
2. 信封 `msg_id` 与正文一致
3. `expires_at` / `created_at` 时间窗 → `ErrExpired` / `ErrClockSkew`
4. `admin_set_generation` 必须在本地接受集合内 → `ErrGenerationMismatch`
5. `signer_set_hash` == 该代 AdminSet 摘要 → `ErrSignerSetMismatch`
6. 管理员类型消息（`ADMIN_BROADCAST`/`ADMIN_SET`/`TOPIC_POLICY`）：门限校验 → `ErrThresholdNotMet`；且**不得携带 author**
7. 节点消息：必须由 `author` 本人自签（会话公钥必须匹配 `author`）→ `ErrNotAuthorized`/`ErrPeerIDMismatch`/`ErrInvalidSignature`

## 6. 待实现包的必需签名（**并行方按此实现，Lead 按此集成**）

### 6.1 `internal/store`（T2）

```go
// 内容寻址存储 + 去重。全部并发安全。
type Store struct { /* ... */ }
func New(capacity int, ttl time.Duration) *Store

// 去重：若 msgID 首次出现返回 true 并记录；重复返回 false。
func (s *Store) Seen(msgID housekitchen.Hash, at time.Time) bool

// 消息存取
func (s *Store) Put(env *pb.Envelope, at time.Time) error
func (s *Store) Get(msgID housekitchen.Hash) (*pb.Envelope, bool)
func (s *Store) List(topic string, since time.Time, limit int) []*pb.Envelope
func (s *Store) Len() int
func (s *Store) GC(now time.Time) int          // 返回清除条数

// 大内容分片
func (s *Store) PutChunk(contentID housekitchen.Hash, index uint32, data []byte) error
func (s *Store) GetChunk(contentID housekitchen.Hash, index uint32) ([]byte, bool)
func (s *Store) HasContent(contentID housekitchen.Hash, count uint32) bool
func (s *Store) MissingChunks(contentID housekitchen.Hash, count uint32) []uint32

// 分片校验：CommitManifest 逐片校验 SHA-256，任一不符返回 ErrInvalidSignature
func (s *Store) CommitManifest(m *pb.ContentManifest) error
```

要求：`Seen` 必须是 LRU + 滑动时间窗，容量到达上限时淘汰最旧条目。
`List` 按 `first_seen` 升序返回。`Put` 遇到相同 msgID 直接返回 `ErrDuplicate`。

### 6.2 `internal/sealed`（T2）

```go
// 封存信封：超管 → 中继。
type Payload struct { Rendezvous housekitchen.Hash; Epoch uint64; EphemeralX25519 []byte
                      Ciphertext []byte; JitterHintMS uint64 }

// Seal 用收件人中继的 X25519 公钥加密一个 SignedBody。
func Seal(recipientX25519Pub []byte, body *pb.SignedBody, rendezvous housekitchen.Hash,
	epoch uint64, jitterHintMS uint64, now time.Time) (*pb.SealedPayload, error)

// Open 用本节点 X25519 私钥解封，返回内层 SignedBody。
func Open(selfX25519Priv []byte, sp *pb.SealedPayload) (*pb.SignedBody, error)

// RendezvousFor 计算某代数的信箱 ID：HKDF(adminSeed, DomainInbox, epoch)。
func RendezvousFor(adminSeed []byte, epoch uint64) (housekitchen.Hash, error)

// SelectRelays 按 XOR 距离选取离 rendezvous 最近的 k 个候选（确定性，任何节点算出的结果一致）。
type RelayCandidate struct { NodeID housekitchen.NodeID; X25519Pub []byte }
func SelectRelays(rendezvous housekitchen.Hash, candidates []RelayCandidate, k int) []RelayCandidate

// Jitter 在 [min,max] 内返回一个随机抖动时长。
func Jitter(min, max time.Duration) time.Duration

// ---- 信箱（rendezvous mailbox）----
type Mailbox struct { /* ... */ }
func NewMailbox(capacity int, ttl time.Duration) *Mailbox
func (m *Mailbox) Store(rendezvous housekitchen.Hash, env *pb.Envelope, at time.Time) error
func (m *Mailbox) Fetch(rendezvous housekitchen.Hash, since time.Time, limit int) []*pb.Envelope
func (m *Mailbox) GC(now time.Time) int

// ---- 统一中继义务 ----
type RelayDuty struct { /* ... */ }
func NewRelayDuty(policy *pb.RelayPolicy) *RelayDuty
func (d *RelayDuty) ShouldRelay() bool
func (d *RelayDuty) Admit(rendezvous housekitchen.Hash, at time.Time) error  // 超配额返回 ErrRateLimited
```

`Open` 失败一律返回包装了 `housekitchen.ErrSealedInvalid` 的错误。
`SelectRelays` 必须用 `housekitchen.CompareNodeID` 排序，保证确定性。

### 6.3 `internal/peer`（T2）

```go
// 节点表 + 地址簿 + 评分封禁 + 令牌桶。全部并发安全。
type NodeRecord struct {
	NodeID    housekitchen.NodeID
	Pub       ed25519.PublicKey
	Addrs     []string
	LastSeen  time.Time
	Failures  int
	Score     int
	LatencyMS int64
	Outbound  bool
	Announce  *pb.NodeAnnounce      // 最近一次已验签的动态
}

type Table struct { /* ... */ }
func NewTable(self housekitchen.NodeID, opts TableOptions) *Table
type TableOptions struct {
	K             int           // 每桶容量，默认 8
	MinPeers      int           // 默认 8
	MaxPeers      int           // 默认 64
	AddrTTL       time.Duration // 默认 15min
	MaxPerSubnet  int           // 默认 2（防日蚀）
	BanDuration   time.Duration // 默认 24h
}

func (t *Table) Upsert(rec NodeRecord) error                 // 地址过期/子网配额在此校验
func (t *Table) Remove(id housekitchen.NodeID)
func (t *Table) Get(id housekitchen.NodeID) (NodeRecord, bool)
func (t *Table) Touch(id housekitchen.NodeID, rtt time.Duration, at time.Time)
func (t *Table) MarkFailure(id housekitchen.NodeID, at time.Time) (evicted bool)
func (t *Table) Len() int
func (t *Table) NeedMorePeers() bool
func (t *Table) Closest(target housekitchen.NodeID, k int) []NodeRecord   // Kademlia 最近 k 个
func (t *Table) Bucket(target housekitchen.NodeID) int
func (t *Table) EmptyBuckets() []int
func (t *Table) Expire(now time.Time) []housekitchen.NodeID              // 返回被移除的节点

// 评分与封禁
func (t *Table) Reward(id housekitchen.NodeID, delta int)
func (t *Table) Penalize(id housekitchen.NodeID, delta int, reason string) (banned bool)
func (t *Table) IsBanned(id housekitchen.NodeID, at time.Time) bool
func (t *Table) BannedUntil(id housekitchen.NodeID) time.Time

// 令牌桶限速（每连接一个）
type Limiter struct { /* ... */ }
func NewLimiter(ratePerSec float64, burst int) *Limiter
func (l *Limiter) Allow(n int, at time.Time) bool

// 子网分组：同一 /24（IPv4）或 /48（IPv6）视为同组
func SubnetKey(addr string) string
```

要求：`Upsert` 对同一 `/24` 超过 `MaxPerSubnet` 的新地址返回 `ErrRateLimited`。
`Penalize` 累计到阈值（默认 -100）时封禁 `BanDuration` 并返回 true。

## 7. 验收命令

```bash
make build     # go build ./...
make test      # go test ./... （必须全绿）
make race      # go test -race ./...
make demo      # 三节点本机广播演示
```

Lead 会在集成后运行全部验收，**不接受未跑通的"应该能行"**。

---

## 8. 契约修订记录（P0 之后，均为**追加/纠错**，已全部实装并测试）

以下修订由并行开发期间的实际发现驱动，全部已落地在代码里。
新加入者请以本节为准，不要依赖早期版本的描述。

### 8.1 验证管线新增/修正的步骤（覆盖 §5.1）

| 步骤 | 内容 | 错误哨兵 |
|------|------|---------|
| 0（新增） | `proto_version` 必须落在 `[MinProtoVersion, ProtoVersion]` | `ErrProtocolVersion` |
| 1 | `VerifyMsgID`（**最先**，篡改优先于一切语义检查） | `ErrMsgIDMismatch` |
| 3 | `created_at > 0` 且 `expires_at > created_at`（**不再有"0 = 永不过期"**） | `ErrClockSkew` / `ErrExpired` |
| 6 | **门限、root_key_ids、方案一律取自本地 AdminSet**；消息自带的 `policy` 只允许"与本地一致或被拒" | `ErrThresholdNotMet` |
| 6 | 管理员消息携带 `author` → 包装哨兵 | `ErrNotAuthorized` |
| 7 | 节点消息的作者**自证**（见 8.2） | `ErrNotAuthorized` / `ErrPeerIDMismatch` |

**为什么第 6 步必须取本地集合**：`body.policy` 虽然被签名保护（改它会让 msg_id 与签名失配），
但签名者可以在**签发时**就把 `threshold` 写成 1 —— 那样一把管理员密钥即可自签一条
"合法"广播，2-of-3 名存实亡。实测确认过该路径。

### 8.2 节点消息的作者身份模型（重要修订）

**旧描述（错误，已废除）**："会话公钥必须匹配 author"。

**现行模型**：作者自证，两件事共同保证：
1. `SignedBody.author_pub`（**新增 field 15**，在签名覆盖内）哈希出 `author`；
2. `author_pub` 的私钥对 `SIGNED_BYTES` 签过名。

原因：Gossip 中消息会被中继转发，接收方的直接对端是**转发者**而非**作者**。
按旧模型，任何转发都会被拒（实测：3 节点网络里所有广播都被丢弃）。

`Session.AuthorNodeID` / `AuthorPub` 降级为**可选交叉校验**：
仅当对端自称就是作者时才核对。

### 8.3 域分隔（F1/F2/F5/F11 修复）

- 新增 `DomainAdminSet = "futurecast/v1/adminset\x00"`；`AdminSet` 摘要**不再**复用 `DomainSignedBody`。
- 新增 `DomainSealedPayload = "futurecast/v1/sealedpayload\x00"`（替换硬编码字面量）。
- **域前缀只出现一次**：`CanonicalXxx` 的返回值已含域前缀。
  签名的域参数被**彻底移除**，函数改名为 `crypto.SignCanonical` / `VerifyCanonical`，
  使调用方在类型层面无法重复施加域。

### 8.4 共享记录类型下沉

`NodeRecord` 定义在 **`internal/housekitchen`**（`records.go`），
`peer.NodeRecord` 与 `node.PeerRecord` 都只是别名。

原因：`node` 声明 `PeerTable` 接口时需要引用该类型，而 `node` 不应导入 `peer`
（反向依赖 + 潜在循环）。下沉到共同底座是唯一无环解法。
方法集因此完全一致，`node.PeerTable` 可被 `*peer.Table` 直接满足
（`internal/node/wiring_test.go` 有编译期断言）。

### 8.5 `SealedPayload` 是一个结构、两种用途（F12）

- **提交通道**（超管→中继）：`ciphertext` 承载对收件人中继加密的完整 `SignedBody`。
- **发布通道**（中继→公网，kind=`MESSAGE_KIND_SEALED`）：
  只填 `inner_body`（明文）**或** `inner_ciphertext`+`inner_nonce`+`topic_key_id`（加密）。

`inbox_rendezvous_id` 在发布通道被复用为**内层正文的 SHA-256 承诺值**，位于外层签名覆盖内，
用于阻止中继调包内层正文。完整规范见 `docs/PROTOCOL.md` 附录 C。

### 8.6 其它需知的实现事实

- `crypto.Ed25519SeedToX25519Scalar(seed)` 返回**私钥标量**；
  `Ed25519SeedToX25519Public(seed)` / `Ed25519ToX25519(pub)` 返回**公钥**。
  早期版本把前者实现成返回公钥，导致解密方拿公钥当私钥用（握手正常、解封必失败）。
- 抖动默认区间为 **[200ms, 2500ms]**，上限刻意压在 INV 周期（3s）之内。
- `peer.Penalize(id, delta, reason)` 的 `delta` 是**带符号**的 `Score += delta`；
  调用方传负数扣分。正数也会被按扣分处理（`Penalize` 永不加分，加分走 `Reward`）。
- `store` 的 `CommitManifest` 对"分片未到齐"返回**不包装** `ErrInvalidSignature` 的专用错误；
  调用方必须区分"校验失败"与"还没到齐"（见 PROTOCOL 附录 A）。
- `node` 的方言：`Publish` 让本地消息也走完整校验管线（本地不是特权路径）；
  `ConnectionsEstablished()` 用于暴露重连风暴；`LocalAddr()` 在 sealed/signed 模式下返回空串。

### 8.7 环境事实（影响验收方式）

- `go test -race` 在本机（Android12 GKI aarch64 内核，39 位 VA）**不可用**：
  `FATAL: ThreadSanitizer: unsupported VMA range / Found 39 - Supported 48`。
  这对全项目所有包同样成立，是环境限制而非代码问题。
  替代验收：`go test ./...`、`go vet ./...`、`go test -count=50`、`-cpu=1,2,4,8`。
- 本环境的 `write` 工具偶尔会产出指向已消失 tmpdir 的**断链符号链接**。
  遇到 `file no longer exists` 时改用 `bash` heredoc 写入。

### 8.8 定向广播（新增能力，v1）

新增包 `internal/directed`：只有指定收件人能解密的管理员广播。设计见
`docs/DESIGN.md` §5.6，线格式规范见 `docs/PROTOCOL.md` 附录 E。

```go
type Recipient struct { NodeID housekitchen.NodeID; Ed25519Pub []byte }

func NewDirectedBody(set *pb.AdminSet, recipients []Recipient, topic, mediaType, text string,
	now time.Time, ttl time.Duration) (*pb.DirectedBody, error)
func CanonicalForSigning(body *pb.DirectedBody) ([]byte, error)
func Finalize(body *pb.DirectedBody, canonical []byte, keys []*identity.AdminKey, threshold int, now time.Time) error
func Envelope(body *pb.DirectedBody, now time.Time) *pb.Envelope
func VerifyBody(body *pb.DirectedBody, set *pb.AdminSet, now time.Time) (VerifyResult, error)
func Open(selfSeed []byte, selfNodeID housekitchen.NodeID, body *pb.DirectedBody) (*OpenResult, error)
```

节点侧：`Node.PublishDirected(env, want, wait)`、`Node.OnDirectedMessage(f)`、
`Node.DirectedDecrypt(env)`；信封走 `Envelope.directed_body`（字段 8），
与 `Envelope.body`（字段 7）**二选一**。

**调用顺序约束（易错，务必遵守）**：`Seal` 依赖 `blind_salt` 做 AAD 绑定，
而 `blind_salt` 在 `Seal` 内部生成。因此必须"先把所有进签名覆盖范围的字段填齐
（`admin_set_generation` / `signer_set_hash` / `policy`），再调用 `Seal` 封装，
最后 `Finalize` 签名"。顺序反了会让收件人重算的 AAD 对不上、全部解不开。

**AAD 用 `blind_salt` 而不是外层摘要**：外层摘要覆盖 `ciphertext`，而 `ciphertext`
又需要 AAD，用摘要会形成循环依赖。`blind_salt` 每消息随机且被签名覆盖，同样安全。

**外层必须检查 `blind_salt` 长度**（16 字节）。只在收件人解密时检查是不够的：
重签过的短盐消息会通过所有中继的外层校验并被全网转发。

新增/变更的 housekitchen 符号：
`DomainDirectedBody`、`DomainDirectedKernel`、`DomainDirectedWrap`、
`DomainDirectedBlind`、`DomainDirectedTag`、`ErrDirectedInvalid`、
`CanonicalDirectedBody`、`CanonicalDirectedKernel`、`DirectedMsgID`、`VerifyDirectedMsgID`。
（`DomainDirectedKey` 与 `DirectedBodyHash` 曾在早期版本存在，因无调用方已删除。）

### 8.9 传播收敛修复（v1，2026-10）

**根因**：一次性发布客户端（CLI `publish`）在 `WriteFrame` 返回后立刻退出，
`transport` 用 `conn.CloseWithError()` 断开连接。quic-go 语义下这等价于
`CancelWrite` —— **已写入但未发出的数据不保证送达**，于是 PUSH 帧被丢弃，
而调用方已报告"已发布"。

**修复**：

- `transport.Conn.CloseGraceful(grace time.Duration) error`：先 `SendStream.Close()`
  （可靠送出已写入数据），再关连接。`Node.Stop()` 改为"先写 Bye → 再逐个优雅关闭
  （150ms 宽限）"。
- `Node.PublishAndConfirm` 改为在窗口内**同步**重发至少 4 轮（间隔 120ms）。
  原先的后台补发 goroutine 无效：进程退出会立刻关连接，它没机会运行。
  `Node.StartRedelivery` 已删除。

**新增测试**：`internal/node/oneshot_test.go` 的 `TestOneShotPublisherAlwaysDelivers`
（8 轮"发布即退出"）。该测试已确认具备抓 bug 能力：回退上述修复后立刻失败。
