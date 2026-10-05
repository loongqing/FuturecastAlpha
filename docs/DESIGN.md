# FutureCast — 去中心化网络广播系统 · 设计说明书

版本 v0.2（规划稿 · 含匿名超管与封存中继）· 目标读者：实现者 / 运维者 / 安全评审

---

## 0. 一句话定义

FutureCast 是一个**无中心服务器**的广播网络：任意数量节点互相连接、自动发现彼此。
网络内持有「超级管理员」门限密钥的一组人（默认 **2-of-3**）可以签发广播，
该广播在可容忍丢包、断连、部分节点作恶的条件下**最终到达每一个在线节点**，
且每个节点都能独立验证「这条消息确实来自超级管理员，且内容未被改动」。

**所有节点地位完全平等**：同一个二进制、同一套职责、同一份配额；
`AdminSet` 里只有公钥，不存在"特权节点"这种角色。
超级管理员**可以选择是否公开自己的 IP**；不公开时，它与网络的连接关系不可被外部观察者判定。

---

## 1. 核心设计判断

| # | 原则 | 理由 |
|---|------|------|
| P1 | **管理权 = 门限签名，不是"谁是管理员"** | 节点只需知道当前 `AdminSet` 的公钥与门限 M。身份可识别 = 签名可验证。 |
| P2 | **签名覆盖"内容"，不覆盖"路由"** | 中转节点必须能改写信封（跳数、来源掩码），但不能改动被签名的正文。 |
| P3 | **消息内容寻址（msg_id = hash(正文)）** | 去重、断点续传、请求缺失消息、防止内容替换，全部免费获得。 |
| P4 | **最终一致而非同时到达** | 不求同一时刻全员收到，求"只要有一个诚实邻居，消息就不会丢"。 |
| P5 | **默认不可信网络** | 传输层 TLS 只解决链路，端点身份一律靠 Ed25519 签名。 |
| P6 | **节点同构，无特权角色** | 所有节点跑同一份代码、同样的中继义务、同样的限额 —— 这既是公平性，也是匿名性的前提。 |
| P7 | **协议即契约** | `.proto` 唯一真相源；`protoc` 生成 Go 绑定。 |
| P8 | **一切可丢弃** | 无效签名、过期、超跳数、超配额一律静默丢弃，不给发送方任何反馈。 |

---

## 2. 系统架构

```
┌─────────────────────────────────────────────────────────────────────┐
│  应用层      CLI / 本地 HTTP API(127.0.0.1) / Web UI / 音频广播      │
├─────────────────────────────────────────────────────────────────────┤
│  信任层      AdminRegistry(2-of-3 门限) · TopicPolicy · 封存解封     │
├─────────────────────────────────────────────────────────────────────┤
│  语义层      SignedBody(被签名) ⟷ Envelope(可改写) · MessageStore     │
├─────────────────────────────────────────────────────────────────────┤
│  传播层      Gossip 推 · Anti-entropy 拉(INV/GET) · 去重 · 配额      │
├─────────────────────────────────────────────────────────────────────┤
│  中继层      封存投递(Sealed Relay) · 等时抖动 · 统一中继义务         │
├─────────────────────────────────────────────────────────────────────┤
│  发现层      Kademlia 路由表(256 桶) · PING/FIND_NODE · PEER_EXCHANGE │
├─────────────────────────────────────────────────────────────────────┤
│  传输层      QUIC(TLS 1.3) 主 · TLS-over-TCP 备 · ws 备 · 长度帧      │
├─────────────────────────────────────────────────────────────────────┤
│  身份层      NodeID = SHA-256(Ed25519 公钥) · AdminKeyID · 盲化 RID   │
└─────────────────────────────────────────────────────────────────────┘
```

节点启动 → 可用的完整流程：

1. 加载/生成节点身份密钥（`~/.futurecast/node.key`，ed25519，0600）。
2. 加载 `AdminSet`：配置内嵌创世 3 个管理员公钥，或一份已签名的管理员清单；校验门限与代数。
3. 读取种子列表（可多个），发起 QUIC/TLS 连接 → `HELLO`（node_id + 公钥 + 自签证明 + 版本）。
4. `PING` 探活，`FIND_NODE(随机目标)` 与 `PEER_EXCHANGE` 扩张路由表。
5. 连接数爬到 `min_peers`(8) → `max_peers`(64)。
6. 进入稳态：push 接收 / 每 3s INV 同步 / 每 30s 刷新路由桶 / 每 5min 存活探测 / 封存投递与信箱轮询。

---

## 3. 三层数据模型

```
传输帧 Frame(长度前缀 + protobuf)
   └── Envelope                     ← 中转节点可改写
         ├── msg_id                 = SHA-256(DomainSep || SignedBody)
         ├── hops, relay_tag, first_seen   ← 每跳更新，不参与签名
         ├── cipher                 ← 可选主题级 AES-256-GCM
         └── SignedBody             ← 签名保护的全部内容
               ├── version, kind, topic, msg_id
               ├── created_at, expires_at, nonce
               ├── admin_set_generation, signer_set_hash, policy
               ├── author(NodeID) · signers[] = {key_id, sig, signed_at}
               └── payload = oneof{ text | binary | admin_set | node_announce
                                    | peer_exchange | sealed | ... }
```

**为什么必须三层**：只签一层 → 中转无法加跳数，Gossip 退化成固定路由；
签路由信息 → `msg_id` 每跳变化，去重失效。因此 `msg_id` 与签名**只看 `SignedBody`**。

```
SIGNED_BYTES = "futurecast/v1/signedbody\x00" || deterministic_proto(SignedBody 去 msg_id 去 signers)
MSG_ID       = SHA-256("futurecast/v1/msgid\x00" || SIGNED_BYTES)
SIGN_INPUT   = SHA-256("futurecast/v1/signinput\x00" || SIGNED_BYTES || key_id || u64be(signed_at))

ADMIN_SET_HASH = SHA-256("futurecast/v1/adminset\x00" || deterministic_proto(AdminSet 去 signers))
```

**域分隔原则（v1 冻结）**：每种被签名/被哈希的结构使用**各自独立**的域前缀，
且该前缀在计算中**只出现一次**。节点自证类消息（Hello / NodeAnnounce / PeerExchange /
SealedPayload）的规范化字节即 `DOMAIN || deterministic_proto(msg)`，签名直接作用于它。

**relay_tag 不泄露拓扑**：不是"上一跳是谁"，而是 `HMAC(节点当日密钥, 消息ID||上一跳tag)[:8]`，
每 24h 轮换。它只用于路径上去重与环路检测，外部无法反查经过哪些节点。

---

## 4. 超级管理员：2-of-3 门限多签

### 4.1 为什么用「多签收集」而不是 FROST 单签

| 方案 | 消息体积 | 实现难度 | 公开可验证 | 升级路径 |
|------|---------|---------|-----------|---------|
| **N-of-M 多签收集（本方案）** | 每签 64B，2-of-3 约 150B | 低，纯 ed25519 | ✅ | 已兼容 |
| FROST 门限 Ed25519 单签 | 64B 固定 | 高（DKG + 两级 nonce + 拉格朗日插值，易错） | ✅ | 需独立审计 |
| 断路器二次签 | 64B | 中 | ✅ 但引入第二信任点 | 可选 |

**决策：MVP 用多签收集。** `SigningPolicy.scheme` 预留 `SCHEME_FROST_ED25519`，
将来切换只改验证分支，签名正文格式与 `msg_id` 完全不变。

**防签名搬运**：签名输入不是裸正文，而是

```
SIGN_INPUT = SHA-256( "futurecast/v1/signinput\x00" || SIGNED_BYTES || key_id || u64be(signed_at) )
```

一条签名无法被搬到另一条消息，也无法复制成两个不同 signer 的签名来凑门限。

> ⚠️ 完整且**唯一**的派生公式定义在 §3。本节与 §3 若不一致，以 §3 与
> `docs/PROTOCOL.md` 为准 —— 早期版本这里漏写了域前缀，按本节实现会导致
> 签名被全网拒绝（跨语言实现必踩）。

### 4.2 门限校验规则

```
校验 AdminSet(policy{M=2,N=3,root_key_ids}, generation) 下的一条消息：
 1. signer_set_hash == SHA256(AdminSet)                   否则拒
 2. admin_set_generation 与本地一致（或在宽限窗内）        否则拒
 3. 每个 signer：key_id ∈ root_key_ids、签名有效、
    同一 key_id 只计一次、signed_at 在 ±300s 窗内         否则忽略该签名
 4. 有效且互异签名数 ≥ M（默认 2）                          否则拒
 5. kind==ADMIN_BROADCAST 时 topic 必须在 TopicPolicy 内    否则拒
```

### 4.3 轮换 / 吊销 / 找回

- 创世 `AdminSet(generation=1)` 的 3 个公钥内嵌在配置/发行版里（导出 24 词助记词备份）。
- 轮换：新集合必须由**旧集合 ≥M 把密钥**签名，代数严格 +1；节点拒绝回退。
- 吊销 = 轮换（把泄露的 key 移出新集合）。宽限期保留最近 4 代，旧密钥签发的消息在 `expires_at` 前仍可验证，之后彻底失效。
- 冷存建议：3 把私钥分放 3 台离线机 / 3 张硬件密钥，签发走离线收集流程。

---

## 5. 超级管理员 IP 可见性（可配置）· 本次新增核心

### 5.1 三种模式

```yaml
admin:
  mode: sealed        # public | signed | sealed
  key_id: <hex>
  listen: ""          # public 模式填 "0.0.0.0:7777" 做种子；sealed/signed 留空 = 不监听
  rendezvous:
    enabled: true
    relays: 4         # 每代选 4 个中继邻居
    epoch: 24h        # 每 24h 轮换中继与信箱
    jitter_ms: [200, 2500]   # 上限须 < INV 周期(3s)
```

| | **public** | **signed** | **sealed** |
|---|---|---|---|
| 公布自己的 IP | ✅ 进 `NODE_ANNOUNCE` 与 `PEER_EXCHANGE` | ❌ 从不发布地址 | ❌ 从不发布地址 |
| 监听端口 | ✅（可做种子） | ❌ 只出站 | ❌ 只出站 |
| 消息中的门限签名 | 明文，任何人可验 | 明文，任何人可验 | **封存**，仅密钥持有者可验 |
| 公众可见的事实 | "超管 IP 发布了 X" | "某节点转发了超管签名的 X" | 只看到"某节点发布了一条封存消息" |
| 关联分析难度 | 低 | 中 | 高 |
| 第三方独立验证 | ✅ | ✅ | ❌（需主题密钥） |

### 5.2 sealed 模式：封存信封 + 中继转发

```
AdminSet.Inbox(rotating, epoch=24h)
   rendezvous_id = HKDF(admin_seed, "fc/v1/inbox" || epoch)[:32]

超管执行 publish（sealed）：
  1. 组装并收集 2-of-3 签名 → SignedBody（含 topic/kind/expires）
  2. 取本 epoch 的中继集合 R = RendezvousHash(rendezvous_id, 活跃节点证书池)，|R| = 4
     选法：与 rendezvous_id 异或距离最近的 4 个在线节点 —— 任何知道 epoch 的人都能算出同一集合
  3. 对每个 r ∈ R：X25519(admin_eph, r_node_pub) → HKDF → AES-256-GCM 加密
     明文 = SignedBody（完整门限签名）；AD = rendezvous_id || epoch
  4. 通过 QUIC 出站连接把 SealedEnvelope 交给 r（点对点，中继不知道对方是谁）
  5. r 校验、落信箱，按 jitter_hint 随机抖动 [200ms, 5s]（需 < INV 周期以保时效）
  6. r 用**自己的节点密钥**签名外层，author = r.NodeID，relay_tag 随机，
     first_seen/hops 随机化到正常区间，然后按普通消息 gossip 出去
```

到达其他节点后：

- 外层是普通节点消息 → 通过 `standard` 模式校验 → **正常转发**，与任何消息无差别。
- 有主题密钥的订阅者解封 → 验证内层 2-of-3 门限 → UI 标记为**已验证的管理员广播**。
- 没有密钥的节点 → 只看到「节点 r 发布了一条封存消息」，**无法证明它来自超管**。

> ⚠️ **入口中继是例外**：它必须解封才能校验内层门限签名，因此能看到明文。
> 精确的威胁模型与部署要求见 §5.6。

### 5.3 为什么外部观察者判不出「哪台机器连着超管」

| 观察手段 | 结果 |
|---|---|
| 扫超管 IP | sealed 模式不监听任何端口，扫不到 |
| 谁在向超管投递 | 没有人向超管投递 —— 是超管主动出站连到中继，方向是反的 |
| 中继的流量特征 | 中继和其他节点完全一样：同样端口、同样握手、同样的 gossip。它只是"收到过一个客户端连接" |
| 消息的发送者字段 | 每个中继发的是**不同 msg_id 的不同副本**，author 是自己的 NodeID；没有共享字段能把它们串起来 |
| 时间关联 | 引入抖动 + 所有节点都履行中继义务 |
| 长期配对关系 | 中继集合每 24h 按 epoch 轮换，没有固定搭档 |
| 全文字节比对 | 每份副本的 `hops`、`first_seen`、`relay_tag` 都不同 |

### 5.4 统一中继义务（让"当中继"这件事本身不特殊）

- `AdminSet.relay_policy` 在存在 sealed admin 时生效；
- 每个在线节点为**当前代的所有 sealed 信箱**保留容量上限（如 128 条 / 32 MiB）；
- 节点定时向自己负责的信箱发起增量同步；
- **结果**：任何时刻都有大量节点在搬运封存消息，"某节点在当中继"不构成任何信号。
- 代价：公网流量上升；容量按主题配额限制。

### 5.5 超管离线时的信箱（rendezvous mailbox）

超管不必常在线。任一节点收到封存消息后：

```
store 到 XOR 距离 rendezvous_id 最近的 k 个节点（Kademlia STORE/GET）
超管上线后主动向这些节点 GET 拉取 → 合并 → 去重
```

- 超管拉取时可轮换 `rendezvous_id`，断开"同一个 ID 长期被查询"的关联。
- 额外隐私：节点可定期对随机 dummy rendezvous 做一次 GET（掩护查询），削弱"谁在查哪个信箱"的信号。
- **诚实声明**：如果对手能观察 DHT 内部查询，仍可能做统计关联；此层只做弱化，不做数学保证。

### 5.6 定向广播：只有被点名的节点能解密

管理员可以指定**收件人集合**，只有集合内的节点能解出正文；其他节点
（包括中继）能验证"这确实来自超管"，但读不到任何内容。

**两层结构**（这是让中继"可验签却读不到"的关键）：

```
Envelope.directed_body = DirectedBody     ← 明文，被超管 2-of-3 门限签名
   ├─ signers / generation / signer_set_hash      任何节点可独立验签
   ├─ ciphertext + content_nonce                  用一次性 content_key 加密的内层
   ├─ blind_salt (16B)                            每消息随机，参与 AAD 与名单派
   └─ recipients[] = { eph_pub, wrapped_key, recipient_tag }
         └── DirectedKernel（只有收件人能解）
               └─ topic / media_type / body / 时间戳 / nonce
```

**为什么必须两层**：如果整条消息都被加密，中继就无法验证门限签名，
"所有消息经签名"这条性质在定向广播上就失效了。因此把**可验证的部分**（外层）
与**机密的部分**（内层）分开：外层明文且被签名，内层用 `content_key` 加密。

**密钥派生（v1 冻结）**：

```
content_key   = 32B 随机（一次性，只用于这一条消息）
blind_key     = HKDF-SHA256(content_key, salt=blind_salt, info="fc/v1/directedblind", 32)
recipient_tag = HMAC-SHA256(blind_key, "futurecast/v1/dirtag\0" || node_id)[:16]
wrap_key      = HKDF-SHA256(X25519(eph_priv, 收件人 X25519 公钥),
                            salt=nil, info="fc/v1/directedwrap", 32)
wrapped_key   = AES-256-GCM(wrap_key, content_key)   AD = "futurecast/v1/dirwrap\0" || blind_salt || u64be(槽位)
ciphertext    = AES-256-GCM(content_key, CanonicalDirectedKernel)  AD = "futurecast/v1/directedkernel\0" || blind_salt
```

收件人的 X25519 公钥由它已公布的 ed25519 公钥**确定性派生**（`Ed25519ToX25519`），
超管无需与收件人预先交换加密密钥。

#### 名单隐私的实现与边界

**消息里不出现任何收件人的 node_id 或公钥。** 每个槽位只有：

- `eph_pub`：每消息重新生成 → 跨消息不可关联；
- `wrapped_key`：只有对应私钥能解；
- `recipient_tag`：由 `content_key` 派生的 `blind_key` 与本节点 `node_id` 算出。

收件人逐个槽位尝试解封，成功后**再用自己算出的 tag 回验槽位**（常数时间比较），
确认"这个槽位确实是给我的"，而不是构造错误槽位造成的假象。

| 角色 | 能知道什么 |
|------|-----------|
| 完全的外部观察者 | 存在一条定向广播、有 K 个槽位；**不知道收件人是谁** |
| 中继 / 任意其他节点 | 同上；可验证门限签名，无法解密 |
| 被点名的收件人 | 解出正文；能确认自己在名单内 |
| 拿到 `content_key` 的攻击者 | 能算出所有 tag、枚举名单（但拿到 content_key 本身已意味着解密能力） |

**诚实边界**（不做过度承诺）：

1. 隐藏的是**收件人身份**，不是公钥材料。`eph_pub` 与 `wrapped_key` 是密文，
   不泄露收件人；但槽位数量 K 是公开的，因此"发给了几个人"可见。
2. **广播范围仍然全网。** 当前实现把定向广播按普通消息在全网 gossip，
   因此"存在一条定向广播、有 K 个槽位"对全网可见。要让连"存在性"都不可见，
   需要按收件人身份做定向路由（DHT 寻址 + 覆盖流量），那是独立的一层，v1 不做。
3. 收件人解密后**可以转发**（技术上无法阻止复制粘贴）。约定上建议转发时标注
   来源为"定向广播"，便于审计。

#### 与 sealed 模式的关系

两者正交，可同时使用：

| | sealed | directed |
|---|---|---|
| 隐藏什么 | 发送方是谁、超管在哪台机器 | 收件人是谁、内容给谁 |
| 谁需要密钥 | 订阅者需主题口令 | 收件人需自己的私钥 |
| 中继能看到 | 明文（必须解封验签，见 §5.7） | 只有密文（验签不需要解密） |

也就是说：**定向广播是中继唯一"读了也读不懂"的模式** —— 它连入口中继都读不到，
因为验签只需要外层明文。

---

### 5.7 ⚠️ 已知限制：入口中继必须解封，因此能看到明文

**这是当前实现必须如实说明的安全限制，不允许被"sealed 模式"这个名字掩盖。**

封存投递的流程是：超管把**完整的 SignedBody（含 2-of-3 门限签名）**加密交给入口中继；
中继解封 → 校验门限 → 用自己的身份重新签名发布。中继之所以必须解封，是因为
它必须独立校验"这条消息确实获得了管理员门限授权" —— 它不能盲信提交者。

**后果（精确表述）：**

| 角色 | 能看到什么 |
|------|-----------|
| 入口中继（为其提交的那一份副本） | **完整明文** + 明文门限签名 |
| 公网其他节点 / 被动观察者 | 只有密文；能看出"存在一条封存消息"，**无法验证也无法判定来源** |
| 持主题口令的订阅者 | 密文 + 解封后的明文 + 可验证的 2-of-3 签名 |
| 无口令但订阅该主题的节点 | 只有密文（`inner_ciphertext`），拿不到明文 |

**因此正确的部署要求是：入口中继必须是受信节点**（通常由运营方自己跑）。
它只能看到**经过它的那一份**副本，且不知道提交者是谁 —— 但它确实看得到内容。

**要彻底消除这一点需要嵌套授权（v2 计划，未实现）：**

```
内层 = 公共可验的授权证明（门限签名覆盖"内容承诺"，本身不含正文）
       + 用主题密钥加密的真正正文
中继只解封并校验授权证明 → 永远看不到正文
订阅者解封正文 → 用承诺值校验与授权证明一致
```

代价是验证管线要区分"授权证明"与"内容正文"两条路径，属于结构性改动，
因此在 v1 明确不做，并在此处标注为已知限制而非遗漏。

---

### 5.8 重要权衡（必须知情）

> **公开可验证性与发送方匿名性不可兼得。**
>
> - 要让**任何人**都能验证"这是超管签的"，门限签名必须明文出现在公网消息里，
>   于是"这条消息由超管授权"对所有人可见（但超管 IP 仍可隐藏 —— 即 `signed` 模式）。
> - 要让**外部观察者连'这是超管发的'都判定不了**，验证必然收窄到**持有主题密钥的人**（`sealed` 模式）。
>
> 本设计把选择权交给配置项，不做虚假承诺。三种模式见 §5.1 对比矩阵。

---

### 5.9 ⚠️ 未解决的发现：node 层观察到明文可达（已缓解，路径未定位）

在把 CLI 的 sealed 发布流程下沉到 `internal/node` 层复现时，观察到无主题口令的
观察者**以明文 `ADMIN_BROADCAST` 形式收到了广播正文**。栈追踪确认中继是收到了
一条来自超管节点的明文 `PUSH`，但在超管侧未观测到对应的转发调用。

逐层排查（转发层栈追踪、解封点诊断、提交载荷校验、逐层计数器）后**未能定位该路径**。
这里如实记录，不掩盖、不猜测性地宣布已修复。

**已采取的缓解（每条都有独立测试）：**

| 缓解 | 位置 | 测试 |
|------|------|------|
| CLI 的 sealed 发布不再本地广播明文 | `cli/node.go` → `PublishLocalOnly` | `TestSealedConfidentialityProperties` |
| 转发层"保密性闸门"：sealed/signed 模式拒绝转发明文管理员广播 | `node/handlers.go` → `relayStats` | `TestConfidentialityGateBlocksPlaintextAdminRelay` |
| 中继无主题口令时拒绝重发布，不做静默降级 | `node/sealed_relay.go` | `TestRelayWithoutTopicKeyRefusesToRepublish` |

**在定位并修复前，不要把 sealed 模式用于"连入口中继之外的所有节点都必须读不到内容"的场景。**
`public` / `signed` 模式不受此发现影响。

### 5.10 传播收敛：一次性发布路径的静默丢帧（已修复）

> **编号说明**：本节在加入 §5.6 定向广播之前曾是 §5.9，之后顺延为 §5.10。
> 若你在早先的对话/记录里看到"§5.9 传播不收敛"，指的就是本节。

**症状**：端到端演示（`make demo`）约 1/3 概率失败，表现为某个远端节点在 15 秒内
始终收不到广播，而超管所在节点报告"确认送达 1 个邻居"。

**根因（已定位）**：不是 anti-entropy 失效，而是**一次性发布客户端退出时丢了在途帧**。

```
CLI publish：连上种子 → WriteFrame(PUSH) → 立刻退出 → transport.Close()
                                                              ↓
                              quicStream.close() 调用 conn.CloseWithError()
                                                              ↓
                    quic-go 语义：等价于 CancelWrite，**已写入但未发出的数据不保证送达**
                                                              ↓
                                        PUSH 帧被丢弃，而调用方已报告"已发布"
```

quic-go 的 `SendStream` 文档写得很明确：

> `Close`：关闭流的写方向，已写入的数据**可靠送达**（发 FIN）。
> `CancelWrite`：**已写入但尚未送达对端的数据不保证被可靠投递**。

而 `Connection.CloseWithError()` 对未发出数据的行为等同后者。发布客户端在
`WriteFrame` 返回后立刻走到 `defer n.Stop()` → `conn.Close()`，此时 PUSH 还躺在
发送缓冲里，于是被整帧丢弃。`WriteFrame` 返回 nil 只代表"已交给缓冲"，
不代表对端收到 —— 这正是"报告成功但实际丢失"的来源。

**修复（两处，互相加固）**：

1. **优雅关闭**：`transport.Conn.CloseGraceful(grace)` 先 `SendStream.Close()`
   让已写入数据可靠送出，再关连接；节点的 `Stop()` 改为"先写 Bye 到所有连接 →
   再逐个优雅关闭（150ms 宽限）"。
2. **同步补发**：`PublishAndConfirm` 在返回前于窗口内**同步**重发至少 4 轮
   （间隔 120ms）。之前的后台补发 goroutine 是无效的 —— 进程退出会立刻关连接，
   它根本没机会运行。同步补发的代价极低（对端按 msg_id 去重），
   换来一次性发布路径的确定性送达。

**验证**：

| 项 | 修复前 | 修复后 |
|----|--------|--------|
| `make demo` 连续运行 | 约 3/5 通过 | **10/10 通过** |
| `TestOneShotPublisherAlwaysDelivers`（8 轮"发布即退出"） | **失败**（回退修复后复现） | 通过，`-count=4` 稳定 |
| `go test ./...` | 全绿 | 全绿（129 项） |

回归测试 `TestOneShotPublisherAlwaysDelivers` 已确认**具备抓 bug 能力**：
把两处修复临时回退后它立刻变红 —— 这是它有价值的前提，否则只是一个恒绿的摆设。

**顺带修掉的三个相关缺陷**（它们各自也会造成传播问题，但不是本次的主因）：

- **INV 主题覆盖不全**：`sendInvs` 原先只遍历 `cfg.Topics`，用 `""` 当"全部主题"
  通配是无效的（`store.List` 对非空 topic 精确匹配），导致未列入配置的主题上的
  消息永远不会被 INV 广告出去。现改为遍历 `store.Topics()`（本地实际存在的主题）。
- **重连风暴**：两端互当种子时反复重复建连，3 节点几秒内产生 18 次建连。
  现按连接存活时长做冷却与退避。
- **定向广播转发未去重**：同一条定向消息会被邻居反复推回并放大数百次。
  现于转发前查 `Seen`。

## 6. 节点发现与自适应扩张

### 6.1 身份自证

`NodeID = SHA-256(ed25519_pub)`，256 位。`HELLO` 携带 node_id / 公钥 / `signed_at` / 自签证明，防止中间人占用他人 node_id。路由表按异或距离分 256 桶，每桶 k=8。

### 6.2 只用很少的 IP 就能扩张

```
配置里只写 2~4 个种子（或一个 DNS 名 / 局域网组播发现）
  ├ PING / PONG
  ├ FIND_NODE(random_target)   → 一批邻居
  ├ PEER_EXCHANGE              → 邻居互推（带 TTL 与自签）
  └ 周期性对最远的桶做 FIND_NODE → 补齐路由表
```

- `PEER_EXCHANGE` 中每条 `NodeInfo` 由通告者自签，接收方按 `(node_id, addr, seq)` 防重放，单次上限 64 条防路由投毒。
- 地址 15 分钟未刷新即过期；同 `/24` 或同 AS 的连接数 ≤2（防日蚀）。
- **sealed/signed 模式的超管不进入任何人的地址簿**：它只出站、不监听，因此不可被 PING 应答。

### 6.3 自适应行为

| 事件 | 反应 |
|------|------|
| 连接数 < `min_peers` | 加速 FIND_NODE，缩短心跳 |
| 连接数 ≥ `max_peers` | 保留"最新 + 低延迟 + 高分"的连接，其余软关闭 |
| 邻居静默 > 90s | PING 探活；连败 3 次踢出并补新邻居 |
| 路由桶为空 | 对该桶目标 FIND_NODE |
| 协议版本不一致 | 记录并降级，或按 `min_proto` 拒绝 |

**断网自愈**：重连后重新握手 + `NODE_ANNOUNCE`，anti-entropy 自动补齐 7 天内错过的消息。

---

## 7. 消息传播（Gossip + Anti-entropy）

```
收到/产生新消息：
  1. 校验（§4.2 + §5.2 外层规则）→ 算 msg_id → 查去重表 → 命中即丢
  2. 落盘 MessageStore（可选加密）
  3. PUSH 给随机 6 个出站邻居
  4. 每 3s 每个 topic 向全部邻居发 INV = { topic, msg_id[:8], 时间窗 }
     邻居比对缺失 → GET(id 列表) → 本节点回 MSG
```

- 去重表：LRU + 滑动时间窗（默认 50k 条 / 7 天）。
- `expires_at` + `max_hops`(32)；管理员消息默认 7 天，可设永不回收。
- 大内容（音频/附件）：正文只放 `content_ref`(SHA-256 + 长度)，按 1 MiB 分片走 `GET_CONTENT / CHUNK`，逐片哈希校验，可从任意邻居并行拉取。
- 抖动：普通消息 ≤300ms；封存中继消息 **[200ms, 2500ms]**（默认，`relay.max_jitter_ms` 可配）。
  上限**刻意收敛到一个 INV 周期（3s）之内** —— 这样封存副本最多晚 2.5s 发布，
  但仍能在同一轮 anti-entropy 里被补齐，匿名性与时效性同时保住。

---

## 8. 加密与隐私

| 层级 | 机制 | 默认 |
|------|------|------|
| L1 链路 | QUIC TLS 1.3（备选 TLS-over-TCP / WebSocket），自签证书 + Ed25519 自证 | **开** |
| L2 内容 | 主题级 AES-256-GCM，密钥由管理员封装进 `TopicPolicy.wrapped_keys` | 可选 |
| L3 封存 | 封存信封（§5.2），无密钥节点只看到密文 | sealed 模式下开 |
| L4 传输隐私 | 定长填充（512B / 4KiB） | 可选 |
| L5 封面流量 | 定时 no-op 消息 + dummy 信箱查询（掩护 §5.5） | 可选 |
| L6 节点匿名 | 出站走 SOCKS5 / Tor | 可选 |

L2/L3 与「超管可识别」不冲突：**签名在密文之外还是之内由模式决定** —— public/signed 模式签名在密文外（人人可验），sealed 模式签名在密文内（仅密钥持有者可验）。

---

## 9. 验证级别

| 模式 | 规则 | 适用 |
|------|------|------|
| `strict` | 所有消息必须带管理员 M-of-N 签名 | 应急广播、只读信道 |
| `standard`（默认） | 管理员主题必须门限签名；`info` 主题允许普通节点签名 | 通用 |
| `open` | 任何消息都转发，UI 标注来源 | 测试/完全开放 |

`TopicPolicy` 由管理员签名发布：主题名、`write_policy`(admin_only / node_allowed / keyring)、`read_policy`、`default_ttl`、`encrypted`、`wrapped_keys`。**权限模型本身也是被广播、被签名的。**

**sealed 信封的外层规则**：外层按 `standard` 校验（节点签名即可）；解封失败或内层门限不足 → **只转发不展示**，避免封存消息被用来做拒绝服务打洞。

---

## 10. 威胁模型与对策

| 威胁 | 对策 |
|------|------|
| 伪造管理员广播 | 2-of-3 门限；单钥泄露不足以签发 |
| 内容篡改 | 规范化编码 + SHA-256 内容寻址 + Ed25519 |
| 重放 | `created_at` 时间窗(±300s) + nonce + LRU 去重 + `expires_at` |
| 泛洪 / DoS | 每连接令牌桶、无效签名记负分、指数退避封禁(≤24h)、压力下要求 PoW 票据 |
| 日蚀攻击 | 多种子、子网/AS 多样性、周期重入网、sentinel 探测 |
| 路由表投毒 | 邻居通告须自签、限条数、地址过期、只信任能反向连通的节点 |
| **定位超管机器** | sealed/signed：不监听 + 只出站 + 中继每代轮换 + 每份副本字段独立随机化 |
| **关联"某中继 = 超管入口"** | 统一中继义务让所有节点都在搬运封存消息；抖动打散时间关联 |
| 元数据泄露 | 封存 + 定长填充 + 封面流量 + dummy 信箱查询 |
| 大内容投毒 | 分片哈希校验，任一片不符即整块丢 |
| 私钥泄露 | 轮换 + 宽限期后旧代数失效；3 把分存、冷签发 |
| 封存消息被滥用做匿名广播 | 外层仍是节点签名 + 速率配额；封存容量按主题计量 |

**明确不做的**：不抗拥有全局视野的强对手做流量关联分析；不做强匿名；不做拜占庭一致的全局排序（只承诺最终一致）。

---

## 11. 协议定义（.proto 摘要）

> **本摘要仅供理解设计意图，不是规范。** 字段号、类型、可选性的**唯一真相源**是
> `proto/futurecast/v1/*.proto`；线格式规范见 `docs/PROTOCOL.md`。
> 两者如有出入，一律以 proto 为准。

```proto
syntax = "proto3";
package futurecast.v1;
option go_package = "futurecast/gen/futurecastv1;futurecastv1";

message Hash  { bytes value = 1; }   // SHA-256, 32B
message KeyID { bytes value = 1; }   // SHA-256(ed25519_pub)[:16]
message PubKey{ bytes ed25519 = 1; }

message Signature {
  KeyID key_id = 1;
  bytes signature = 2;               // Ed25519(SignInput), 64B
  int64 signed_at_unix_nanos = 3;
}

enum MessageKind {
  MESSAGE_KIND_UNSPECIFIED      = 0;
  MESSAGE_KIND_ADMIN_BROADCAST  = 1;   // 超管广播（需门限）
  MESSAGE_KIND_ADMIN_SET        = 2;   // 管理员轮换（需旧集合门限）
  MESSAGE_KIND_TOPIC_POLICY     = 3;
  MESSAGE_KIND_NODE_ANNOUNCE    = 10;  // 节点动态
  MESSAGE_KIND_PEER_EXCHANGE    = 11;
  MESSAGE_KIND_LIVENESS         = 12;
  MESSAGE_KIND_CONTENT_MANIFEST = 20;
  MESSAGE_KIND_CHUNK            = 21;
  MESSAGE_KIND_SEALED           = 30;  // 封存信封（内层为完整 SignedBody）
}

message AdminSet {
  uint64 generation = 1;
  repeated AdminKey keys = 2;
  SigningPolicy policy = 3;          // threshold=2 / total=3 / root_key_ids / scheme
  Hash previous_set_hash = 4;
  int64 created_at_unix_nanos = 5;
  RelayPolicy relay_policy = 6;      // 统一中继义务（sealed 模式）
  repeated Inbox inboxes = 7;        // 各 sealed 超管的轮换信箱
  repeated Signature signers = 8;    // 轮换授权签名（不参与 AdminSet 自身摘要）
}
message Inbox {
  Hash rendezvous_id = 1;            // HKDF(admin_seed, "fc/v1/inbox"||epoch)
  fixed64 epoch = 2;
  uint32 replica = 3;                // k = 副本数
  uint32 mailbox_quota_bytes = 4;
}
message RelayPolicy {
  bool mandatory = 1;                // 所有节点都必须当中继
  uint32 per_inbox_quota = 2;
  uint32 max_jitter_ms = 3;
}

message SignedBody {
  uint32 proto_version = 1;
  MessageKind kind = 2;
  string topic = 3;
  Hash msg_id = 4;
  int64 created_at_unix_nanos = 5;
  int64 expires_at_unix_nanos = 6;
  bytes nonce = 7;                   // 16B
  uint64 admin_set_generation = 8;
  Hash signer_set_hash = 9;          // SHA256(AdminSet) 绑定
  SigningPolicy policy = 10;
  NodeID author = 11;
  repeated Signature signers = 12;
  bytes payload = 13;                // oneof text/binary/admin_set/node_announce/sealed/...
}

// 注意：实际消息名是 SealedPayload（不是 SealedEnvelope），且一物两用。
message SealedPayload {
  Hash inbox_rendezvous_id = 1;
  fixed64 epoch = 2;
  bytes ephemeral_x25519 = 3;
  bytes ciphertext = 4;              // AES-256-GCM(SignedBody)；提交通道使用
  fixed64 jitter_hint_ms = 5;
  bytes inner_body = 6;              // 发布通道使用：内层管理员 SignedBody
}

message Envelope {
  Hash msg_id = 1;
  uint32 hops = 2;
  uint32 max_hops = 3;
  int64 first_seen_unix_nanos = 4;
  fixed64 relay_tag = 5;             // HMAC 轮换标签，不泄露拓扑
  ContentCipher cipher = 6;
  SignedBody body = 7;
}

message NodeAnnounce {
  NodeID node_id = 1;
  repeated string addrs = 2;         // sealed/signed 超管此字段恒为空
  bool address_public = 3;           // 对应 admin.broadcast_ip
  Hash rendezvous_hint = 4;          // 仅 sealed 超管携带，且每代轮换
  int64 seq = 5;
  int64 issued_at_unix_nanos = 6;
  bytes self_signature = 7;
}

message Frame {
  oneof body {
    Hello hello = 1; Ping ping = 2; Pong pong = 3;
    FindNode find_node = 10; Nodes nodes = 11; PeerExchange peer_exchange = 12;
    Push push = 20; Inv inv = 21; Get get = 22; Msg msg = 23;
    GetContent get_content = 24; Chunk chunk = 25;
    SealedSubmit sealed_submit = 26; SealedReceipt sealed_receipt = 27;
    MailboxStore mailbox_store = 28; MailboxGet mailbox_get = 29; MailboxData mailbox_data = 30;
    Bye bye = 40; Error error = 41;
  }
}
```

完整 schema 见 `proto/futurecast/v1/futurecast.proto`。

---

## 12. 运行环境（已实测打通）

| 项目 | 结果 |
|------|------|
| Go | `go1.22.2 linux/arm64` ✅ |
| 公网 / proxy.golang.org | ❌ i/o timeout |
| **goproxy.cn** | ✅ `200 / 1.9s` —— `GOPROXY=https://goproxy.cn,direct` |
| goproxy.io | ✅ 备用 |
| **quic-go v0.48.2** | ✅ 通过镜像拉取成功 |
| **google.golang.org/protobuf** | ✅ v1.34.2 |
| **protoc** | ✅ `libprotoc 3.21.12`（apt 安装） |
| **protoc-gen-go** | ✅ v1.34.2，端到端生成 `.pb.go` 验证通过 |
| sum.golang.google.cn | ❌ → 使用 `GOSUMDB=off` |

```bash
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=off
export PATH=$PATH:/root/go/bin
```

Makefile 中固化以上环境变量，CI 与本地一致。

---

## 13. 仓库结构与并行切分

```
futurecast/
├── go.mod / go.sum             # quic-go, x/crypto, google.golang.org/protobuf
├── Makefile                    # env / proto / build / test / demo
├── docs/DESIGN.md              # 本文档
├── docs/PROTOCOL.md            # 线格式 + 黄金测试向量（跨语言互通基准）
├── proto/futurecast/v1/futurecast.proto
├── gen/futurecastv1/           # protoc 生成（勿手改）
├── cmd/futurecast/main.go      # CLI: node / publish / admin / verify / relay
├── scripts/                    # keygen.sh · demo.sh · selftest.sh
└── internal/
    ├── codec/          protobuf 编解码封装 + 规范化（canonical）   [Lead]
    ├── housekitchen/   ID 类型、错误、日志、配置                   [Lead]
    ├── crypto/         签名/验签、SignInput/msg_id、X25519+HKDF    [T1]
    ├── identity/       节点身份、管理员密钥、助记词                 [T1]
    ├── registry/       AdminSet、2-of-3 门限、轮换链、TopicPolicy   [T1]
    ├── sealed/         封存信封、RendezvousHash、信箱、抖动         [T2]
    ├── store/          内容寻址存储、LRU 去重、分片校验             [T2]
    ├── peer/           节点表、地址簿、评分封禁、令牌桶             [T3]
    ├── transport/      QUIC/TCP 抽象、握手、帧、连接池              [Lead]
    └── node/           gossip、anti-entropy、发现、中继义务         [Lead+T3]
```

**接口冻结**：`codec/`、`housekitchen/`、`transport/` 的公开 API 由 Lead 在 P0 一次性定死，之后只以"追加"方式演进；T1/T2/T3 写域互不重叠。

---

## 14. 里程碑

| 阶段 | 内容 | 验收 |
|------|------|------|
| **M0** | proto + 生成 + codec + crypto + registry + store + peer + 单测 | `go test ./...` 全绿；伪造/篡改/门限不足/世代不符全部被拒 |
| **M1** | 可运行 MVP：3+ 节点 QUIC 互连、握手、push+INV、CLI | 三节点：发布 2-of-3 广播 <1s 全达；改 1 字节即全网丢弃 |
| **M2** | 自动发现：Kademlia、FIND_NODE/PEER_EXCHANGE、地址自愈 | 只给 1 个种子启动 8 节点，30s 内全连通；杀种子仍互通 |
| **M3** | **封存模式**：SealedEnvelope、中继轮换、信箱、抖动、统一中继义务 | 抓包证明：观测者无法从公网流量判定哪个节点连接超管 |
| **M3.5** | **定向广播**：两层结构、逐收件人密钥封装、名单盲化 | 只有被点名的节点能解密；非收件人与中继验签通过但读不到内容；名单不出现明文 |
| **M4** | 加固：评分/封禁/PoW、填充、封面流量、轮换演练 | 恶意节点泛洪被隔离；轮换后旧代数签名失效 |
| **M5** | 体验层：本地 HTTP API + Web UI、音频/大文件、多主题 | 浏览器订阅、离线签名收集流程可用 |
| **M6** | 生产：跨平台单文件发行、Docker、部署文档 | 一键建网 + 一键加入 |

---

## 15. 需求 → 效果对照表

| 需求 | 设计落点 | 做完后的实际效果 |
|------|---------|----------------|
| 去中心化广播 | §7 | 无中心服务器；节点掉线消息仍能绕路到达 |
| 广播超管消息 | §4 + §9 strict | 集齐 2/3 签名全网才认；单钥被盗也发不出 |
| 使用 protobuf | §11 + `proto/` + `gen/` | 官方 protoc 生成，线格式规范、跨语言可互通 |
| 不需要知道很多 IP | §6.2 | 配置只写 1~3 个种子，自动发现扩张到几十个邻居 |
| 自动拓展发现节点 | §6.3 | 上下线自动广播动态，邻居表自愈，路由桶自动补齐 |
| 广播节点动态 | `NODE_ANNOUNCE` / `LIVENESS` | 每个节点可见拓扑变化与邻居上下线 |
| 可选加密 | §8 | 默认链路已加密；可再开"中转也读不懂"的封存模式 |
| 所有消息经签名 | §3 + §4.2 | 篡改 1 字节即被丢弃，UI 上不会出现 |
| 超管身份可识别 | §4.4 / §5.8 | `public`/`signed`：UI 显示「已验证·2/3·世代3」；`sealed`：仅密钥持有者可验 |
| **超管 IP 可配置是否广播** | §5.1 | `public` 进地址簿做种子；`signed`/`sealed` 不监听、只出站、地址永不出现在网络里 |
| **不要暴露下级节点与超管的联系** | §5.2–5.5 | 中继每代轮换、每份副本字段独立随机化、统一中继义务、抖动打散时间关联 |
| **所有节点地位均等** | P6 + §5.4 | 同一二进制、同一职责、同一配额；`AdminSet` 只含公钥，无特权角色 |
| **定向广播：只有指定节点能解密** | §5.6 | 超管指定收件人；收件人解出正文，中继与其他节点能验签但读不到；收件人名单对外隐藏 |

---

## 16. 三个真实使用场景

**A. 校园/园区应急广播（public 模式）**
机房 3 台种子，每个楼栋树莓派一条命令加入。管理员用 2 把硬件密钥签名 → 全网 2 秒内弹窗 + 音频播报。任何第三方都能独立验证"这确实是官方签的"。断网节点重连后自动补齐。

**B. 敏感信道（sealed 模式）**
超管机器不监听任何端口，只主动连出 4 个按 epoch 轮换的中继。中继把封存副本随机抖动后按普通消息发出。外部观察者看到的只是"几个普通节点在正常发布消息"；只有持主题密钥的订阅者能解封并验证 2-of-3。超管离线期间消息落在 rendezvous 信箱里，上线后拉取。

**C. 开源组织公告信道（signed 模式）**
管理员 3 人各持一把密钥，公告需 2 人签署，公众可验证；同时超管机器不监听、只出站、中继每代轮换，机器位置不暴露。

---

## 17. 已知取舍与后续增强

- **可验证性 vs 匿名性**：见 §5.8，用配置项交给使用者决定，不做虚假承诺。
- **抗强匿名**：不抗全局流量关联；可加 Tor/混合网（§8 L6）。
- **FROST**：2-of-3 多签约 150B，将来可切 FROST 降至 64B（§4.1）。
- **大文件吞吐**：分片 + 多源并行；后续可加纠删码。
- **浏览器节点**：传输已抽象（QUIC/TCP/WebSocket），不阻塞。
- **量子抵抗**：当前 Ed25519/X25519；后续可加混合 ML-KEM/ML-DSA。
