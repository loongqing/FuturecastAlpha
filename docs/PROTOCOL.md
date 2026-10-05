# FutureCast 线格式规范 v1（PROTOCOL）

> 目标读者：**没有读过 Go 代码的 Rust / Python / C 实现者**。
> 本文是 FutureCast v1 的**互通契约**：只要严格遵守本文的字节级规则，
> 你的实现算出的 `msg_id`、`SIGN_INPUT`、`ADMIN_SET_HASH` 与 Go 参考实现**逐字节相同**，
> 签名可以互相验证，消息可以在同一条链路上互相解析。
>
> **真相源优先级**：`proto/futurecast/v1/*.proto` > 本文 > `docs/DESIGN.md`。
> 若三者冲突，以 proto 与当前代码为准，并视为本文的缺陷。
> `docs/DESIGN.md` §11 的 proto 摘要是早期版本，**字段号已脱节**，不要照抄。

## 0. 成熟度与未决项（务必先读）

| 标记 | 含义 |
|---|---|
| **[已冻结]** | 参考实现已存在，字节级行为由本文固定，跑得过 §11 向量。可以放心互通。 |
| **[未实现]** | 参考实现尚无该代码路径（主要是 `cmd/futurecast` CLI）。线格式可先实现，端到端联调要等 CLI。 |
| **⚠️ [待裁决]** | Lead 已宣布的规则与当前代码**不一致**。本文以**当前代码**为准，并给出两种可能。 |

**撰写时的仓库状态（供判断可信度）**：

- `internal/housekitchen`、`crypto`、`identity`、`registry`、`store`、`peer`、`sealed`、`transport`、`node` 均已存在；
- `cmd/futurecast/` **仍然没有 Go 文件** → CLI 与端到端演示 [未实现]；
- `scripts/` 下的脚本会在 CLI 缺失时**明确报错退出**，不会伪造成功。

**必须知道的三个未决/风险点**（详见对应章节，不要在实现里忽略）：

1. **⚠️ 节点自证类消息的域前缀目前出现两次**（§4.5）。Lead 已宣布改为单次，但**代码尚未改**；
   实测"单前缀验签=false、双前缀验签=true"。**以当前代码（双前缀）为准**，等裁决后可能破坏性变更。
2. **发布通道的 `inner_body` 是明文**（§8.1、§10.4）。当前实现里 `signed` 与 `sealed` 两种模式
   在**线格式上完全相同**；`sealed` 只隐藏"谁提交"，不隐藏"内容是管理员广播"。这与 DESIGN §5.1 的承诺有差距。
3. **sealed 超管的 `NODE_ANNOUNCE.rendezvous_hint` 是一个可被观察者识别的标记**（§10.4-D）。

---

## 1. 术语与命名

| 名称 | 含义 |
|---|---|
| `MUST` / `MUST NOT` | 不遵守即无法互通或产生安全缺陷 |
| `u32/u64/i64` | wire 上按 protobuf varint / fixed64 编码的整数 |
| `u64be(x)` | `x` 的 8 字节**大端**表示 |
| `\|\|` | 字节串拼接 |
| `SHA256(x)` | RFC 6234 SHA-256，输出 32 字节 |
| `HMAC-SHA256(k,m)` | RFC 2104 HMAC |
| `Ed25519(sk,m)` | RFC 8032 **纯** Ed25519（不是 Ed25519ph），`sk` 由 32 字节种子派生 |
| `det_proto(M)` | M 的**确定性 protobuf 序列化**（§3.1） |
| `DOMAIN_*` | 域分隔前缀原始字节（§3.2） |

标识符长度（**必须精确匹配，偏差一律视为非法，不得截断或补零**）：

| 类型 | 长度 | 派生 |
|---|---|---|
| `Hash` | 32 B | 任意 SHA-256 摘要 |
| `KeyID` | 16 B | `SHA256(ed25519_pub)[0:16]` |
| `NodeID` | 32 B | `SHA256(ed25519_pub)` |
| ed25519 公钥 | 32 B | — |
| ed25519 签名 | 64 B | — |
| X25519 公钥 | 32 B | 由 ed25519 公钥确定性派生（§8.4） |
| `nonce`（SignedBody） | 16 B | CSPRNG |
| GCM nonce | 12 B | CSPRNG |

> 参考实现 `GetHash/GetKeyID/GetNodeID` 遇到长度不符返回**全零值**而不是报错。
> 你可以在解析期更严格（直接拒绝），但**不要**把长度不符的值截断后参与哈希。

---

## 2. 传输层 [已冻结]

### 2.1 帧格式

```
+----------------+--------------------------------------+
| u32 长度 N (BE)|  protobuf(Frame)，恰好 N 字节         |
+----------------+--------------------------------------+
```

1. 长度前缀是 **4 字节无符号大端**整数，表示紧随其后的 protobuf 字节数 `N`。
2. `N == 0` → **协议错误**（零长度帧），断开连接（普通错误，无哨兵）。
3. `N > 1 MiB`（`1048576` 字节，`1 << 20`）→ **协议错误**（`ErrFrameTooLarge`），断开连接。
   合法范围 `1 <= N <= 1048576`；校验在**读取正文之前**完成。
4. 写方向参考实现使用确定性序列化（§3.1）；读方向接受任意合法 protobuf 字节序，
   不得假设对端按字段号升序发送。
5. 读满 `N` 字节失败（短读 / 超时）→ 连接错误。参考实现读超时 120s、写超时 30s。
6. 每帧只有一个 `Frame.body`（`oneof`）成员；`Frame` 没有其他字段。

### 2.2 承载方式

| 承载 | 说明 |
|---|---|
| QUIC | 默认。TLS 1.3，ALPN = **`futurecast/1`**；每条连接开 **1 条双向 stream**，帧在 stream 上顺序传输。 |
| TLS-over-TCP | 后备。TCP 之上 TLS 1.3，ALPN 同为 `futurecast/1`，帧直接在 TLS 上顺序传输。 |

两种承载的**帧格式与握手完全相同**，上层不感知差异。

TLS **不承担身份认证**：参考实现生成自签 P-256 证书、客户端 `InsecureSkipVerify`、`ServerName="futurecast"`。
端点身份一律由 §2.3 的 Ed25519 自证保证。实现者**不得**用证书 CN / 指纹做身份，也不得因为跳过证书校验就认为连接可信。

### 2.3 握手序列（两端对称）

连接建立后，双方**各自立即发送一个 `HELLO`**，然后各读一个 `HELLO`：

```
A: WriteFrame(HELLO_A)                     B: WriteFrame(HELLO_B)
A: f = ReadFrame()  → 必须是 HELLO_B        B: f = ReadFrame()  → 必须是 HELLO_A
A/B: 校验对端 HELLO（下述 6 步）
A/B: WriteFrame(PING{nonce=随机})
A/B: ReadFrame()  → 期待 PONG{nonce 相同}   # 用于初始化 RTT/延迟
```

**HELLO 校验 6 步**（任一失败即断开）：

1. 首帧必须是 `Frame.hello`，否则"握手首帧不是 HELLO"；
2. `public_key.ed25519` 长度 == 32；
3. `node_id == SHA256(public_key.ed25519)` → 否则 `ErrPeerIDMismatch`；
4. 自证签名有效（§4.5）→ 否则 `ErrPeerIDMismatch`；
5. `peer.proto_version >= 1` → 否则 `ErrProtocolVersion`；
6. `node_id != 本机 NodeID` → 否则拒绝自连。
   另外：`admin_set_generation != 0` 且本地不认识该代数时**只记日志**（不拒绝），
   因为该对端的消息会在正文校验时各自被拒。

`PING`/`PONG`（`Frame.ping`=2 / `Frame.pong`=3）：
`Ping{nonce:u64=1, issued_at_unix_nanos:i64=2}`，`Pong` 同构；收到 PING 必须回 `nonce` **原样回显**的 PONG。
两者**没有签名**，不携带身份，不得用于信任决策。

### 2.4 `Frame` 的 `oneof` 成员号

见 §9.5。未列出的字段号：按 protobuf 未知字段规则忽略，不得因此断连。

---

## 3. 规范化（canonical）编码 —— 本文最关键的章节

**目标**：同一份逻辑数据，任何语言、任何库、任何字段写入顺序，都产生**同一串字节**。
参考实现用 `proto.MarshalOptions{Deterministic: true}`；本节把它的可观察行为完整写死。

### 3.1 确定性 protobuf 序列化规则（`det_proto`）

以下规则**完全定义** `det_proto`，不需要读 protobuf 库源码：

1. **字段顺序**：按字段号**升序**输出。不得按写入顺序、字典序或哈希序。
2. **非 repeated 字段至多出现一次**；`oneof` 至多一个成员被设置。
3. **proto3 隐式 presence 的标量**（`uint32/uint64/int64/fixed64/bool/enum/string/bytes`）：
   等于默认值（`0`、`false`、枚举 `0`、空 string、空 bytes）时 **MUST 省略该字段的 TLV**；
   不等于默认值时 MUST 输出。本 schema **没有任何 `optional` 关键字**，
   因此不存在"显式 presence 的标量"。
4. **消息类型字段（singular）**：在内存中**不存在 / nil** 时省略；
   **存在但内容为空**时，必须输出 `tag + length=0`。
   → "全零的 32 字节 `Hash`" 与 "不存在的 `Hash`" 是**两种不同编码**：
   前者输出子消息内容 `0a 20` + 32×`00`，后者字段整体消失。
   实现者必须保留"字段是否被设置"这一信息，不能把 proto3 默认值语义套到消息字段上。
5. **repeated 消息字段**：每个元素一条独立 TLV，**顺序即列表顺序**，不得重排。
   （因此 `AdminSet.keys`、`root_key_ids`、`signers`、`inboxes` 的顺序参与哈希。）
6. **repeated 数值标量**：本 schema 中没有；若将来新增，按 proto3 默认 packed 编码。
7. **map 字段**：本 schema 中没有；若将来新增，必须按键的字节序升序输出。
8. **未知字段**：实现方不得把未知字段写入 canonical 字节；解析时可保留，计算哈希/签名前必须丢弃。
9. **int64 负数**：按二进制补码转 `uint64` 后编码为 varint（负数 10 字节）。
   `SignInput` 的 `signed_at` 同此规则。
10. **字符串/bytes**：UTF-8 原样；`string` 不做 Unicode 规范化、不改大小写、不加去 BOM。

### 3.2 域分隔前缀（**原始字节**）

| 常量名 | ASCII | 十六进制 | 用途 |
|---|---|---|---|
| `DOMAIN_SIGNED_BODY` | `futurecast/v1/signedbody\0` | `667574757265636173742f76312f7369676e6564626f647900` | SignedBody canonical |
| `DOMAIN_ADMIN_SET` | `futurecast/v1/adminset\0` | `667574757265636173742f76312f61646d696e73657400` | AdminSet canonical |
| `DOMAIN_MSG_ID` | `futurecast/v1/msgid\0` | `667574757265636173742f76312f6d7367696400` | msg_id 派生 |
| `DOMAIN_SIGN_INPUT` | `futurecast/v1/signinput\0` | `667574757265636173742f76312f7369676e696e70757400` | 单签名输入 |
| `DOMAIN_HELLO` | `futurecast/v1/hello\0` | `667574757265636173742f76312f68656c6c6f00` | Hello canonical + 自证 |
| `DOMAIN_NODE_ANNOUNCE` | `futurecast/v1/nodeannounce\0` | `667574757265636173742f76312f6e6f6465616e6e6f756e636500` | NodeAnnounce canonical + 自证 |
| `DOMAIN_PEER_EXCHANGE` | `futurecast/v1/peerexchange\0` | `667574757265636173742f76312f7065657265786368616e676500` | PeerExchange canonical + 自证 |
| `DOMAIN_SEALED_PAYLOAD` | `futurecast/v1/sealedpayload\0` | `667574757265636173742f76312f7365616c65647061796c6f616400` | SealedPayload canonical + 提交自证 |
| `DOMAIN_RELAY_TAG` | `futurecast/v1/relaytag\0` | `667574757265636173742f76312f72656c617974616700` | relay_tag HMAC |
| `DOMAIN_DAILY_KEY` | `futurecast/v1/dailykey\0` | `667574757265636173742f76312f6461696c796b657900` | 当日标签密钥派生 |
| `DOMAIN_SEALED_DIGEST` | `futurecast/v1/sealeddigest\0` | `667574757265636173742f76312f7365616c656464696765737400` | 封存密文去重摘要 |
| `AD_PREFIX_SEALED` | `futurecast/v1/sealed\0` | `667574757265636173742f76312f7365616c656400` | sealed AEAD 关联数据前缀（**注意与 `DOMAIN_SEALED_PAYLOAD` 不同**） |
| `DOMAIN_INBOX` | `fc/v1/inbox` | `66632f76312f696e626f78` | rendezvous_id 的 HKDF info 前缀（**无 `\0`**） |
| `SEALED_INFO` | `fc/v1/sealed` | `66632f76312f7365616c6564` | 封存密钥的 HKDF info（**无 `\0`**） |
| `DOMAIN_TOPIC_KEY` | `fc/v1/topickey` | `66632f76312f746f7069636b6579` | 主题密钥封装的 HKDF info（**无 `\0`**） |

> **历史说明**：早期实现的 `CanonicalAdminSet` 复用了 `DOMAIN_SIGNED_BODY`（两个不同结构共享同一域，破坏域分隔本意）。
> 已修正为独立的 `DOMAIN_ADMIN_SET`。若你参考了旧版文档，`ADMIN_SET_HASH` 会不同。
> 当前无外部实现，不存在兼容负担。

### 3.3 需要 canonical 的七种对象

| 对象 | 前缀 | 编码前清空的字段 | 用途 |
|---|---|---|---|
| `SignedBody` | `DOMAIN_SIGNED_BODY` | `msg_id`(4), `signers`(12) | 签名、msg_id |
| `AdminSet` | `DOMAIN_ADMIN_SET` | `signers`(8) | signer_set_hash、轮换签名 |
| `Hello` | `DOMAIN_HELLO` | `self_signature`(10) | 握手自证 |
| `NodeAnnounce` | `DOMAIN_NODE_ANNOUNCE` | `self_signature`(7) | 节点动态自证 |
| `PeerExchange` | `DOMAIN_PEER_EXCHANGE` | `self_signature`(2) | 邻居互推自证 |
| `SealedPayload` | `DOMAIN_SEALED_PAYLOAD` | 无 | 封存提交自证 |
| `Envelope` | **无前缀** | 无 | 整包内容校验/去重，**不用于签名** |

"清空字段"= 视为**未设置**（nil），而不是"长度为零的已设置消息"（§3.1 规则 4）。

---

## 4. 派生关系（可实现伪代码）

### 4.1 `SIGNED_BYTES`

```
SIGNED_BYTES(body) =
    DOMAIN_SIGNED_BODY || det_proto( clone(body) with { .msg_id = UNSET, .signers = UNSET } )
```

### 4.2 `MSG_ID`

```
MSG_ID(SIGNED_BYTES) = SHA256( DOMAIN_MSG_ID || SIGNED_BYTES )
MSG_ID(body)         = MSG_ID( SIGNED_BYTES(body) )
```

`msg_id` 不参与自身签名（先清空再编码），因此它是正文的内容地址。
校验时重算并与 `body.msg_id` 比较，不等即 `ErrMsgIDMismatch`。

### 4.3 `SIGN_INPUT`（逐字节精确）

```
SIGN_INPUT(SIGNED_BYTES, key_id, signed_at_unix_nanos) =
    SHA256( DOMAIN_SIGN_INPUT
         || SIGNED_BYTES
         || key_id                                 # 恰好 16 字节原始值
         || u64be( u64(signed_at_unix_nanos) ) )   # int64 按补码 reinterpret 成 u64

signature = Ed25519( signer_seed, SIGN_INPUT(...) )    # 对 32 字节摘要签名，输出 64 B
```

把 `key_id` 与 `signed_at` 绑进签名输入是**防签名搬运**的核心：
一条签名换到另一条消息、或把同一把密钥的签名复制两份冒充两个 signer，都会失效。

**这条路（消息正文 + AdminSet 轮换）不受 §4.5 的双前缀问题影响，是稳定契约。**

### 4.4 `ADMIN_SET_HASH`

```
ADMIN_SET_HASH(set) = SHA256( DOMAIN_ADMIN_SET || det_proto( clone(set) with { .signers = UNSET } ) )
```

- `SignedBody.signer_set_hash` **MUST** == `ADMIN_SET_HASH(admin_set_generation 对应的集合)`。
- 轮换签名也是对 `CanonicalAdminSet` 走 §4.3 的 `SIGN_INPUT`（§7）。

### 4.5 节点自证签名（Hello / NodeAnnounce / PeerExchange / SealedPayload）⚠️ [待裁决]

```
canonical_X = CanonicalX(X)                       # = DOMAIN_X || det_proto(X 去掉 self_signature)
digest_X    = SHA256( DOMAIN_X || canonical_X )   # SignWithDomain 的行为：再前置一次域
sig_X       = Ed25519( self_seed, digest_X )      # 64 B
```

展开：

```
digest_X = SHA256( DOMAIN_X || DOMAIN_X || det_proto(X 去掉 self_signature) )
```

**这是当前代码的真实行为**，因为：

- `CanonicalHello/CanonicalNodeAnnounce/CanonicalPeerExchange/CanonicalSealedPayload`
  的返回值**已经带域前缀**；
- `crypto.SignWithDomain(priv, domain, canonical)` 实现为 `Sign(priv, SHA256(domain || canonical))`，
  **又前置了一次同一个域**。

实测证据（alice 固定种子，见 §11.5）：`HELLO_SINGLE_PREFIX_VERIFIES=false`、`HELLO_DOUBLE_PREFIX_VERIFIES=true`。

> ⚠️ **待裁决**：Lead 已宣布改为"域只出现一次"（`digest_X = SHA256(canonical_X)`），
> 但**当前代码仍是双前缀**，相关注释与行为不符。本文以当前代码（双前缀）为准。
> 若改为单前缀：§11.5 的 `HELLO_DIGEST` 与 `HELLO_SIGNATURE` 会变，属于**破坏性线格式变更**；
> 实现方务必在动手前确认该裁决已落地（检查 `internal/crypto` 是否仍对 canonical 重新前置域）。

### 4.6 `RELAY_TAG`（不参与签名）

```
day         = floor( unix_seconds / 86400 )
daily_key   = SHA256( DOMAIN_DAILY_KEY || node_seed(32B) || u64be(day) )       # 32 B
relay_tag   = BE_u64( HMAC-SHA256( daily_key,
                                   DOMAIN_RELAY_TAG || msg_id(32B) || u64be(previous_tag) )[0:8] )
```

- 每 24h 轮换；接收方**不验证** relay_tag，只用于环路检测与路径去重。
- 首跳 `previous_tag = 0`；中转每跳用上一跳 tag 作为输入重算。
- relay_tag 在 `Envelope` 里，每跳可改写，不参与任何签名。

### 4.7 封存派生（[已冻结]，详见 §8）

```
sealed_key    = HKDF-SHA256( X25519(eph_priv, relay_x25519_pub), salt=nil, info="fc/v1/sealed", len=32 )
AD            = AD_PREFIX_SEALED || rendezvous_id(32B) || u64be(epoch)      # 共 25+32+8 = 65 B
rendezvous_id = HKDF-SHA256( admin_seed, salt=nil, info="fc/v1/inbox" || "/" || 十进制(epoch), len=32 )
```

---

## 5. 三层数据模型

### 5.1 `Frame`（传输层）

`Frame.body` 是 `oneof`，见 §9.5。整帧由发送方构造，接收方不在这一层做签名校验。

### 5.2 `Envelope`（路由外壳，**中转可改写**）

| 字段 | 号 | 中转可否改写 | 说明 |
|---|---|---|---|
| `msg_id` | 1 | **不可** | MUST == `body.msg_id`，不一致即 `ErrMsgIDMismatch` |
| `hops` | 2 | 可 | 每转一跳 +1；达到 `max_hops` 丢弃 |
| `max_hops` | 3 | 可（受限） | 一般由 `body.max_hops` 初始化；**不参与签名** |
| `first_seen_unix_nanos` | 4 | 可 | 首次本地见到的时间 |
| `relay_tag` | 5 | 可 | 每跳重算（§4.6） |
| `cipher` | 6 | 可 | 主题级 `ContentCipher`（可选） |
| `body` | 7 | **不可** | 被签名的全部内容 |

参考实现 `WrapEnvelope`：`hops=0`、`max_hops=body.max_hops`、`first_seen=now`，不设 `relay_tag`/`cipher`。
`SignedBody.max_hops`(14) **参与签名**；`Envelope.max_hops`(3) 只是便于快速丢弃的副本。

### 5.3 `SignedBody`（签名保护的唯一对象）

字段见 §9.2。全部字段参与 `SIGNED_BYTES`，除 `msg_id` 与 `signers`。
`signers` 列表顺序**不参与**签名校验（逐条验证），但参考实现生成时按 `key_id` **升序**排列
（`FinalizeAdminBody`），使不同节点对同一条消息产生相同的 envelope 字节。

`payload` 是 `Payload` 一元 oneof，成员见 §9.3。

---

## 6. 消息校验管线（2-of-3 门限）

### 6.1 完整顺序（`Registry.VerifyMessage`，**顺序即语义**）

**第一个失败即返回对应错误，不做后续检查**：

| 步 | 检查 | 失败错误 |
|---|---|---|
| 1 | `env != nil` 且 `env.body != nil` | 普通错误（无哨兵） |
| 2 | `VerifyMsgID(body)`：重算 `MSG_ID(body)` == `body.msg_id` | `ErrMsgIDMismatch` |
| 3 | `env.msg_id == body.msg_id` | `ErrMsgIDMismatch` |
| 4 | 过期：`expires_at != 0` 且 `now > expires_at` | `ErrExpired` |
| 5 | 超前：`created_at > now + 300s` | `ErrClockSkew` |
| 6 | `body.admin_set_generation` 在本地接受的代数集合内 | `ErrGenerationMismatch` |
| 7 | `body.signer_set_hash == ADMIN_SET_HASH(该代集合)` | `ErrSignerSetMismatch` |
| 8a | 若 `kind ∈ {ADMIN_BROADCAST(1), ADMIN_SET(2), TOPIC_POLICY(3)}`：门限校验（§6.2） | `ErrThresholdNotMet` |
| 8b | 紧接 8a：`author` 必须未设置/全零 | 普通错误（**无哨兵**） |
| 9a | 否则（节点消息）：`author` 必须存在 | `ErrNotAuthorized` |
| 9b | 会话 `AuthorNodeID` 非零时必须 == `author` | `ErrPeerIDMismatch` |
| 9c | 会话必须有 32 B `AuthorPub` | `ErrNotAuthorized` |
| 9d | `NodeIDFromPub(AuthorPub) == author` | `ErrPeerIDMismatch` |
| 9e | 存在 `key_id == KeyIDFromPub(AuthorPub)` 的签名 | `ErrInvalidSignature` |
| 9f | 用 `AuthorPub` 验证该签名对 `SIGN_INPUT(SIGNED_BYTES(body), key_id, signed_at)` | `ErrInvalidSignature` |
| 10 | 节点消息若同时满足管理员门限，额外置 `AdminAuthorized=true`（不影响成败） | — |

**两个易错点**：

- **步骤 2 必须最先**：改 `payload`、`topic`、`created_at`、`nonce` 等任何正文字节，
  都会先破坏 `msg_id`，因此观察到的是 `ErrMsgIDMismatch` 而**不是**语义错误。
  这是设计意图（内容寻址优先）。写负例测试时不要断言语义错误。
- **步骤 8b 没有哨兵错误**。判定条件是"`author` 全零/未设置"。
- 步骤 9 只查 `key_id == KeyIDFromPub(AuthorPub)` 的那一条签名；
  `signers` 里可以**同时**含管理员签名（超管以节点身份发布）。

### 6.2 单签名的采纳条件（`MultisigVerify`）

对 `body.signers` **逐条**判定：

1. `key_id` 已设置且长度 16 → 否则拒绝（`key_id 非法`）；
2. `key_id ∈ policy.root_key_ids` → 否则拒绝；
3. `key_id` **尚未被成功采纳过** → 否则拒绝（`重复 key_id`）；
4. `signed_at != 0` 且 `|now - signed_at| <= skew`（`skew` 默认 300 s；`policy.clock_skew_tolerance_nanos > 0` 时用它）→ 否则拒绝；
5. 能从 `AdminSet.keys` 解析出该 `key_id` 的 32 B ed25519 公钥 → 否则拒绝；
6. 用该公钥验证 `Ed25519(SIGN_INPUT(canonical, key_id, signed_at))` → 否则拒绝；
7. 全部通过才 `seen.add(key_id)` 并计数 +1。

**去重语义的精确含义**：第 3 步查 `seen`，而 `seen` 只在**成功后**写入。因此：

- 同一把密钥提交两条**都有效**的签名 → 只计 1；
- 同一把密钥先提交**无效**签名、再提交有效签名 → **有效的那条仍被计入**（无效的不算"已采纳"）。

**通过条件**：成功采纳的**互异** `key_id` 数 `>= threshold`。

---

## 7. AdminSet 轮换链

### 7.1 创世（generation = 1）

- `generation == 1`；`previous_set_hash` 未设置（全零视为未设置）。
- `policy.scheme == SIGNING_SCHEME_ED25519_MULTISIG(1)`。
- `threshold > 0`、`total > 0`、`threshold <= total`、`total == len(keys)`。
- `policy.root_key_ids` 非空。
- `keys[]` 与 `root_key_ids[]` 一一对应：每个 `k.key_id == SHA256(k.public_key.ed25519)[0:16]`，
  `key_id` 无重复，每个 `root_key_id` 都在 `keys` 中。

### 7.2 轮换（generation = N+1）

1. 新集合通过 §7.1 的形状检查（除创世专属项）；
2. `new.generation == old.generation + 1` → 否则 `ErrGenerationMismatch`；
3. `new.previous_set_hash == ADMIN_SET_HASH(old)` → 否则 `ErrGenerationMismatch`；
4. 用**旧集合**做门限校验：
   - `canonical = CanonicalAdminSet(new)`（**此时 `previous_set_hash` 已写入、`signers` 已清空**）；
   - `root_key_ids`、公钥解析器、`threshold`、`skew` 全部取自**旧集合** `policy`；
   - 对 `new.signers` 跑 §6.2；不足门限 → `ErrThresholdNotMet`。
5. 拒绝回退与跳号；参考实现保留最近 **4** 代，更旧的被裁剪，裁剪后其签名消息一律
   `ErrGenerationMismatch`（`Install` 幂等：已存在的代数直接返回 nil）。

**顺序陷阱**：`previous_set_hash` 会改变 canonical 字节，
所以签发方必须**先写 `previous_set_hash` → 再算 canonical → 再逐把签名**。
参考实现正是"设字段 → 算 canonical → 改字段 → **重算** canonical → 签名"。

---

## 8. 封存（sealed）与信箱 [已冻结]

### 8.1 `SealedPayload` 的两种用途（**同一结构，两套字段语义**）

**提交通道（超管 → 中继，`Frame.sealed_submit` = 26）**：

| 字段 | 号 | 值 |
|---|---|---|
| `inbox_rendezvous_id` | 1 | 本 epoch 的信箱 ID（§8.3） |
| `epoch` | 2 | `EpochFor(now)`（§8.3） |
| `ephemeral_x25519` | 3 | 一次性 X25519 公钥（32 B） |
| `ciphertext` | 4 | `nonce(12) \|\| AES-256-GCM 密文 \|\| tag`（§8.2） |
| `jitter_hint_ms` | 5 | 发送方建议的抖动上限（ms；参考实现填配置 `SealedJitterMax`，默认 2500） |
| `inner_body` | 6 | **未设置** |

密文**明文** = `det_proto(完整的 inner SignedBody)`，即**带 `msg_id` 与 `signers`** 的完整对象。
⚠️ 注意：**不是** §4.1 的 `SIGNED_BYTES`（不带域前缀、且清空了 `msg_id`/`signers`）。
参考实现用 `proto.MarshalOptions{Deterministic:true}.Marshal(body)`。

**发布通道（中继 → 公网，`SignedBody.kind = MESSAGE_KIND_SEALED(30)`）**：

| 字段 | 号 | 值 |
|---|---|---|
| `inner_body` | 6 | `det_proto(完整的 inner SignedBody)` —— **明文** |
| `inbox_rendezvous_id` | 1 | `SHA256(inner_body)`：对内层正文的**承诺值**（复用字段 1） |
| `epoch` | 2 | **MUST 未设置** |
| `ephemeral_x25519` | 3 | **MUST 未设置** |
| `ciphertext` | 4 | **MUST 未设置** |
| `jitter_hint_ms` | 5 | **MUST 未设置** |

> **为什么发布通道不得携带字段 2–5**：`inbox_rendezvous_id`、`epoch`、`ephemeral_x25519`
> 在多个中继副本之间是**共享的明文**。只要填了，观察者就能用它对 N 份副本做关联，
> 直接反推"哪几个节点在当同一个超管的中继"。因此参考实现的 e2e 测试显式断言
> `len(ciphertext)==0 && epoch==0 && len(ephemeral_x25519)==0`。
> 承诺值 `SHA256(inner_body)` 是唯一允许存在的共享值，但它由内层正文唯一决定，
> 不引入可关联的新信息（内层 `msg_id` 本身就是内容地址）。

**外层 `SignedBody` 的其他字段（发布通道）**：

- `kind = 30`；`author = 中继的 NodeID`；`signers = [中继自己的 1 个签名]`，走 §4.3 的 `SIGN_INPUT` 路径；
- `topic = 内层 topic`（**主题名是明文**）；
- `admin_set_generation` / `signer_set_hash` / `policy` 取中继当前认的集合；
- `Envelope.hops ∈ [0,2]`（随机，`randInt(3)`）、`Envelope.relay_tag = 随机 u64`、
  `first_seen = 发布时刻` —— 随机化到普通消息的取值区间，使副本与普通消息在字段上无法区分。

**订阅者解封（`Unseal`）不需要任何密钥**：校验承诺值 → 解析 `inner_body`
→ 拒绝内层再嵌套 `SEALED` → 用完整校验管线验证内层门限签名。
→ **当前实现中，任何观察者都能读走 `inner_body` 并验证它是管理员广播**（诚实说明见 §10.4）。

### 8.2 密码学参数（冻结值）

```
shared        = X25519(eph_priv, relay_x25519_pub)                       # 32 B
sealed_key    = HKDF-SHA256(secret=shared, salt=nil, info="fc/v1/sealed", len=32)
ciphertext    = AES-256-GCM(key=sealed_key, nonce=12B CSPRNG,
                            plaintext=det_proto(full inner SignedBody),
                            AD=AD_PREFIX_SEALED || rendezvous_id(32B) || u64be(epoch))
输出布局       = nonce(12B) || GCM 密文 || GCM tag(16B)
```

- HKDF = RFC 5869，SHA-256；`salt = nil` 表示**空字节串**（不是 32 字节零）。
- AEAD 关联数据长度固定 = 25 + 32 + 8 = **65 字节**。
- 这是端到端加密：只有持有对应 X25519 私钥的中继能解封；超管与中继之间的链路上，
  即使 TLS 被终止，内容也不泄露给第三方。

### 8.3 epoch 与 `rendezvous_id`

```
epochSeconds  = 配置 Relay.EpochDuration（默认 86400）
epoch         = u64( floor( unix_seconds / epochSeconds ) )          # 秒级整除，向下取整
info_inbox    = "fc/v1/inbox" || "/" || 十进制(epoch)                 # 例：fc/v1/inbox/19875
rendezvous_id = HKDF-SHA256(secret=admin_seed(32B), salt=nil, info=info_inbox, len=32)
```

- `epoch` 用**十进制 ASCII**（无前导零、无填充、无 `\0`）是有意选择：epoch 是公开值，
  十进制让跨语言实现不必猜整数编码。
- `admin_seed` 是超管的 32 字节密钥种子（ed25519 种子）。知道种子的实体（超管本人）能算出全部信箱 ID；
  知道 `epoch` 但不知道种子的人算不出。
- `EpochFor` 对负时间（1970 前）语义未定义；实现方按无符号整除处理即可，正常运行不会遇到。

### 8.4 中继选择与 X25519 公钥派生

**X25519 公钥不占协议字段**，由中继已公布的 ed25519 公钥**确定性派生**：

```
relay_x25519_pub = BytesMontgomery( EdwardsPoint::from_bytes( ed25519_pub ) )     # 32 B
```

即 ed25519 公钥（Edwards y 坐标）经双有理映射得到 Montgomery u 坐标。
用私钥侧表述（与 libsodium `crypto_sign_ed25519_sk_to_curve25519` 一致）：

```
scalar = clamp( SHA512(ed25519_seed)[0:32] )
x25519_pub = X25519(scalar, 9)
```

由于 `BytesMontgomery(EdwardsPoint::from_bytes(ed25519_pub)) == X25519(clamp(SHA512(seed)[:32]), 9)`，
加密身份与签名身份天然绑定，且**不需要新增任何 proto 字段**。

**选择算法**：

```
target = rendezvous_id 当作 32 字节 NodeID
按 XOR 距离对候选排序：compare(target, a, b) < 0 表示 a 更近
  距离比较 = 从第 0 字节起逐字节比较 target^a 与 target^b（无符号）
排序使用**稳定排序**，因此距离相同时保持输入顺序（不是按 NodeID 字典序）
取前 k 个，k 默认 4（配置 Relay.Relays）
```

**候选集合**来自本节点当前已建立会话的邻居（可退回地址簿中已知公钥的节点）。
因此"谁在线"决定实际中继；任何知道 `rendezvous_id` 与同一候选集合的节点算出同一批中继。

### 8.5 提交流程与中继行为

1. 超管组装内层 `SignedBody`，收集门限签名，算 `msg_id`（超管**只出站**，从不监听）；
2. `epoch = EpochFor(now)`，`rendezvous = RendezvousFor(admin_seed, epoch)`；
3. 对每个中继 `r`：生成一次性 X25519 → `sealed_key` → 加密完整内层 body → 组装 `SealedPayload`；
4. 通过**出站**连接发送 `SEALED_SUBMIT{sealed, submitter_self_signature}`；
   中继只知道"某个对端提交了密文"，不知道是超管，也不知道其他中继是谁；
5. 中继侧：
   - `RelayDuty.Admit(rendezvous)` 配额检查（每信箱、1 小时滑动窗、默认上限 128）→ 超限回 `Error{code:429}`；
   - `sealed.Open(self_x25519_priv, sp)` 解封 → 失败回 `Error{code:400}`；
   - 用完整校验管线独立验证内层（`AdminAuthorized` 必须为真，否则 `Error{code:403}`）；
     中继**不信任提交者**，只信内层门限签名；
   - 抖动延迟：`d = Jitter(min,max)`（§8.6），若 `jitter_hint_ms > 0` 则 `d = min(d, hint)`；
   - 入 `pending` 队列并落信箱；
   - 回 `SEALED_RECEIPT{inbox_rendezvous_id, accepted_msg_id=内层 msg_id, scheduled_publish_ms, relay_node_id}`；
6. 中继发布循环每 **200 ms** 扫描到期项，用**自己的节点身份**重签外层并按普通消息 gossip（§8.1）。

**中继侧密文去重**：`SHA256(DOMAIN_SEALED_DIGEST || ciphertext)`，同一封存重复投递只发布一次。

### 8.6 抖动

```
Jitter(min, max) = min + rand_int63n( max - min )      # max 为开区间上界
参考资料：RelayConfig.SealedJitterMin = 200ms, SealedJitterMax = 2500ms
```

- 上限必须显著小于 anti-entropy 的 INV 周期（3 s），否则损害时效；因此默认上限收敛到 **2500 ms**。
- `Jitter` 的随机源是普通 PRNG（非密码学随机），抖动值不参与任何签名或安全判定。

### 8.7 信箱帧语义

| 帧 | 语义 |
|---|---|
| `MAILBOX_STORE`(28) | 把若干 `Envelope` 存入某个 `rendezvous_id` 的信箱；重复 `msg_id` 返回 `ErrDuplicate`（调用方可忽略） |
| `MAILBOX_GET`(29) | 按 `since_unix_nanos`（含边界）拉取，`limit<=0` 时默认 64 |
| `MAILBOX_DATA`(30) | 应答 `{rendezvous_id, envelopes, has_more}`；参考实现恒置 `has_more=false` |

本地信箱容量默认 128 条 / TTL 7 天；超容量按 FIFO 淘汰最旧条目。
超管上线后从 DHT 拉取信箱、轮换 `rendezvous_id`、以及 dummy 掩护查询，属于节点策略层，不在线格式内。

### 8.8 封存层的其余未决/风险点

- **⚠️ §4.5 的双前缀同样作用于 `submitter_self_signature`**（`CanonicalSealedPayload` 已含域，`SignWithDomain` 又加一次）。
- **发布通道的机密性缺口**：`inner_body` 是明文，见 §10.4。
- **`SealedReceipt.self_signature`、`MailboxStore.self_signature` 等字段**：参考实现尚未填写
  （`SealedReceipt` 只填前 4 个字段）。实现方不要假设它们有值。

---

## 9. 字段号总表

`签` 列：`✅` 参与签名/规范化摘要；`—` 不在签名对象内；`清` 表示编码前清空。

### 9.1 `common.proto`

| 消息 | 号 | 字段 | 类型 | 签 |
|---|---|---|---|---|
| `Hash` | 1 | `value` | bytes(32) | — |
| `KeyID` | 1 | `value` | bytes(16) | — |
| `NodeID` | 1 | `value` | bytes(32) | — |
| `PubKey` | 1 | `ed25519` | bytes(32) | — |
| `Signature` | 1 | `key_id` | `KeyID` | ✅ |
| | 2 | `signature` | bytes(64) | ✅ |
| | 3 | `signed_at_unix_nanos` | int64 | ✅ |
| `AdminKey` | 1 | `key_id` | `KeyID` | ✅ |
| | 2 | `public_key` | `PubKey` | ✅ |
| | 3 | `label` | string | ✅ |
| | 4 | `role` | `AdminRole` | ✅ |
| `SigningPolicy` | 1 | `threshold` | uint32 | ✅ |
| | 2 | `total` | uint32 | ✅ |
| | 3 | `root_key_ids` | repeated `KeyID` | ✅（顺序参与） |
| | 4 | `scheme` | `SigningScheme` | ✅ |
| | 5 | `clock_skew_tolerance_nanos` | int64 | ✅ |
| `Inbox` | 1 | `rendezvous_id` | `Hash` | ✅ |
| | 2 | `epoch` | fixed64 | ✅ |
| | 3 | `replica` | uint32 | ✅ |
| | 4 | `mailbox_quota_bytes` | uint32 | ✅ |
| `RelayPolicy` | 1 | `mandatory` | bool | ✅ |
| | 2 | `per_inbox_quota` | uint32 | ✅ |
| | 3 | `max_jitter_ms` | uint32 | ✅ |
| | 4 | `min_jitter_ms` | uint32 | ✅ |
| `ContentCipher` | 1 | `nonce` | bytes(12) | — |
| | 2 | `ciphertext` | bytes | — |
| | 3 | `topic_key_id` | `KeyID` | — |
| `TopicPolicy` | 1 | `topic` | string | ✅ |
| | 2 | `write_policy` | `WritePolicy` | ✅ |
| | 3 | `read_policy` | `ReadPolicy` | ✅ |
| | 4 | `default_ttl_nanos` | int64 | ✅ |
| | 5 | `encrypted` | bool | ✅ |
| | 6 | `wrapped_keys` | repeated `WrappedTopicKey` | ✅（顺序参与） |
| `WrappedTopicKey` | 1 | `recipient_key_id` | `KeyID` | ✅ |
| | 2 | `wrapped` | bytes | ✅ |

枚举：`AdminRole{0 UNSPECIFIED,1 ROOT,2 PUBLISHER}`、
`SigningScheme{0 UNSPECIFIED,1 ED25519_MULTISIG,2 FROST_ED25519}`、
`WritePolicy{0 UNSPECIFIED,1 ADMIN_ONLY,2 NODE_ALLOWED,3 KEYRING}`、
`ReadPolicy{0 UNSPECIFIED,1 PUBLIC,2 TOPIC_KEY}`。

### 9.2 `message.proto` — 顶层

| 消息 | 号 | 字段 | 类型 | 签 |
|---|---|---|---|---|
| `AdminSet` | 1 | `generation` | uint64 | ✅ |
| | 2 | `keys` | repeated `AdminKey` | ✅（顺序参与） |
| | 3 | `policy` | `SigningPolicy` | ✅ |
| | 4 | `previous_set_hash` | `Hash` | ✅ |
| | 5 | `created_at_unix_nanos` | int64 | ✅ |
| | 6 | `relay_policy` | `RelayPolicy` | ✅ |
| | 7 | `inboxes` | repeated `Inbox` | ✅（顺序参与） |
| | 8 | `signers` | repeated `Signature` | 清 |
| `SignedBody` | 1 | `proto_version` | uint32 | ✅ |
| | 2 | `kind` | `MessageKind` | ✅ |
| | 3 | `topic` | string | ✅ |
| | 4 | `msg_id` | `Hash` | 清 |
| | 5 | `created_at_unix_nanos` | int64 | ✅ |
| | 6 | `expires_at_unix_nanos` | int64 | ✅ |
| | 7 | `nonce` | bytes(16) | ✅ |
| | 8 | `admin_set_generation` | uint64 | ✅ |
| | 9 | `signer_set_hash` | `Hash` | ✅ |
| | 10 | `policy` | `SigningPolicy` | ✅ |
| | 11 | `author` | `NodeID` | ✅ |
| | 12 | `signers` | repeated `Signature` | 清 |
| | 13 | `payload` | `Payload` | ✅ |
| | 14 | `max_hops` | int64 | ✅ |
| `Envelope` | 1 | `msg_id` | `Hash` | — |
| | 2 | `hops` | uint32 | — |
| | 3 | `max_hops` | uint32 | — |
| | 4 | `first_seen_unix_nanos` | int64 | — |
| | 5 | `relay_tag` | fixed64 | — |
| | 6 | `cipher` | `ContentCipher` | — |
| | 7 | `body` | `SignedBody` | — |
| `NodeAnnounce` | 1 | `node_id` | `NodeID` | ✅ |
| | 2 | `addrs` | repeated string | ✅（顺序参与） |
| | 3 | `address_public` | bool | ✅ |
| | 4 | `rendezvous_hint` | `Hash` | ✅ |
| | 5 | `seq` | int64 | ✅ |
| | 6 | `issued_at_unix_nanos` | int64 | ✅ |
| | 7 | `self_signature` | bytes(64) | 清 |
| `NodeInfo` | 1 | `node_id` | `NodeID` | ✅ |
| | 2 | `addr` | string | ✅ |
| | 3 | `last_seen_unix_nanos` | int64 | ✅ |
| | 4 | `expires_at_unix_nanos` | int64 | ✅ |
| | 5 | `seq` | int64 | ✅ |
| `PeerExchange` | 1 | `nodes` | repeated `NodeInfo` | ✅（顺序参与） |
| | 2 | `self_signature` | bytes(64) | 清 |
| `Liveness` | 1 | `issued_at_unix_nanos` | int64 | ✅ |
| | 2 | `nonce` | uint64 | ✅ |
| `ContentManifest` | 1 | `content_id` | `Hash` | ✅ |
| | 2 | `total_size` | uint64 | ✅ |
| | 3 | `chunk_size` | uint32 | ✅ |
| | 4 | `chunk_count` | uint32 | ✅ |
| | 5 | `merkle_root` | bytes | ✅ |
| `ContentChunk` | 1 | `content_id` | `Hash` | ✅ |
| | 2 | `index` | uint32 | ✅ |
| | 3 | `data` | bytes | ✅ |
| `SealedPayload` | 1 | `inbox_rendezvous_id` | `Hash` | ✅（双用途，§8.1） |
| | 2 | `epoch` | fixed64 | ✅ |
| | 3 | `ephemeral_x25519` | bytes(32) | ✅ |
| | 4 | `ciphertext` | bytes | ✅ |
| | 5 | `jitter_hint_ms` | fixed64 | ✅ |
| | 6 | `inner_body` | bytes | ✅ |

`MessageKind`：`0 UNSPECIFIED`、`1 ADMIN_BROADCAST`、`2 ADMIN_SET`、`3 TOPIC_POLICY`、
`10 NODE_ANNOUNCE`、`11 PEER_EXCHANGE`、`12 LIVENESS`、`20 CONTENT_MANIFEST`、`21 CHUNK`、`30 SEALED`。
**管理员类型集合**（默认必须门限签名）：`{1,2,3}`；其余走节点自签通道。

### 9.3 `Payload` 一元 oneof

| 成员 | 号 | 类型 | 成员 | 号 | 类型 |
|---|---|---|---|---|---|
| `text` | 1 | `TextPayload` | `admin_set` | 6 | `AdminSet` |
| `binary` | 2 | bytes | `topic_policy` | 7 | `TopicPolicy` |
| `node_announce` | 3 | `NodeAnnounce` | `content_manifest` | 8 | `ContentManifest` |
| `peer_exchange` | 4 | `PeerExchange` | `content_chunk` | 9 | `ContentChunk` |
| `liveness` | 5 | `Liveness` | `sealed` | 10 | `SealedPayload` |

`TextPayload`：`1 media_type:string`、`2 body:string`、`3 attachments:repeated Attachment`。
`Attachment`：`1 name`、`2 media_type`、`3 content_id:Hash`、`4 size:uint64`。

### 9.4 `wire.proto` — 帧载荷

| 消息 | 号 | 字段 | 类型 | 签 |
|---|---|---|---|---|
| `Hello` | 1 | `proto_version` | uint32 | ✅ |
| | 2 | `min_proto` | uint32 | ✅ |
| | 3 | `node_id` | `NodeID` | ✅ |
| | 4 | `public_key` | `PubKey` | ✅ |
| | 5 | `listen_addrs` | repeated string | ✅（顺序参与） |
| | 6 | `admin_set_hash` | `Hash` | ✅ |
| | 7 | `admin_set_generation` | uint64 | ✅ |
| | 8 | `issued_at_unix_nanos` | int64 | ✅ |
| | 9 | `nonce` | uint64 | ✅ |
| | 10 | `self_signature` | bytes(64) | 清 |
| `Ping` / `Pong` | 1 | `nonce` | uint64 | — |
| | 2 | `issued_at_unix_nanos` | int64 | — |
| `FindNode` | 1 | `target` | `NodeID` | — |
| | 2 | `want` | uint32 | — |
| `Nodes` | 1 | `target` | `NodeID` | — |
| | 2 | `nodes` | repeated `NodeInfo` | — |
| `Push` | 1 | `envelope` | `Envelope` | — |
| `Inv` | 1 | `topic` | string | — |
| | 2 | `msg_ids` | repeated `Hash`（完整 32 B） | — |
| | 3 | `since_unix_nanos` | int64 | — |
| `Get` | 1 | `msg_ids` | repeated `Hash` | — |
| `Msg` | 1 | `envelopes` | repeated `Envelope` | — |
| `GetContent` | 1 | `content_id` | `Hash` | — |
| | 2 | `from_index` | uint32 | — |
| | 3 | `count` | uint32 | — |
| `SealedSubmit` | 1 | `sealed` | `SealedPayload` | — |
| | 2 | `submitter_self_signature` | bytes(64) | 清（§4.5 双前缀 ⚠️） |
| `SealedReceipt` | 1 | `inbox_rendezvous_id` | `Hash` | — |
| | 2 | `accepted_msg_id` | `Hash` | — |
| | 3 | `scheduled_publish_ms` | fixed64 | — |
| | 4 | `relay_node_id` | `NodeID` | — |
| | 5 | `self_signature` | bytes(64) | —（参考实现未填） |
| `MailboxStore` | 1 | `rendezvous_id` | `Hash` | — |
| | 2 | `envelopes` | repeated `Envelope` | — |
| | 3 | `self_signature` | bytes(64) | —（参考实现未填） |
| `MailboxGet` | 1 | `rendezvous_id` | `Hash` | — |
| | 2 | `since_unix_nanos` | int64 | — |
| | 3 | `limit` | uint32 | — |
| `MailboxData` | 1 | `rendezvous_id` | `Hash` | — |
| | 2 | `envelopes` | repeated `Envelope` | — |
| | 3 | `has_more` | bool | — |
| `Bye` | 1 | `reason` | string | — |
| `Error` | 1 | `code` | uint32 | — |
| | 2 | `message` | string | — |
| | 3 | `retryable` | bool | — |

### 9.5 `Frame` 一元 oneof

| 成员 | 号 | 成员 | 号 | 成员 | 号 |
|---|---|---|---|---|---|
| `hello` | 1 | `peer_exchange` | 12 | `sealed_receipt` | 27 |
| `ping` | 2 | `push` | 20 | `mailbox_store` | 28 |
| `pong` | 3 | `inv` | 21 | `mailbox_get` | 29 |
| `find_node` | 10 | `get` | 22 | `mailbox_data` | 30 |
| `nodes` | 11 | `msg` | 23 | `bye` | 40 |
| | | `get_content` | 24 | `error` | 41 |
| | | `content_chunk` | 25 | | |
| | | `sealed_submit` | 26 | | |

---

## 10. 三种超管模式：线格式事实

### 10.1 规范目标（DESIGN §5.1 + Lead 裁决）

| | `public` | `signed` | `sealed` |
|---|---|---|---|
| 是否监听端口 | ✅ 可做种子 | ❌ 只出站 | ❌ 只出站 |
| `Hello.listen_addrs` | 真实地址 | **空数组** | **空数组** |
| `NODE_ANNOUNCE.addrs` | 非空 | **空数组** | **空数组** |
| `NODE_ANNOUNCE.address_public` | `true` | `false`/省略 | `false`/省略 |
| 进入他人 `PEER_EXCHANGE` | ✅ | ❌ | ❌ |
| 门限签名可见性 | 明文，人人可验 | 明文，人人可验 | **仅主题密钥持有者可验** |
| 公众可见事实 | "超管 IP 发了 X" | "某节点转发了超管签名的 X" | "某节点发了一条消息" |

### 10.2 当前实现的线格式

| 观察点 | `public` | `signed` | `sealed` |
|---|---|---|---|
| 发布路径 | 直接构造 `Envelope`（`kind=ADMIN_BROADCAST`）| `SubmitSealed` → 中继发布 | `SubmitSealed` → 中继发布 |
| 公网消息外层 `kind` | `1` | **`30 (SEALED)`** | **`30 (SEALED)`** |
| 外层 `author` | 未设置（必须） | 中继 NodeID | 中继 NodeID |
| 外层 `signers` | 2-of-3 管理员签名 | 中继自己的 1 个签名 | 中继自己的 1 个签名 |
| `payload.sealed.inner_body` | 不存在 | **明文内层 body** | **明文内层 body** |
| 外层 `topic` | 内层主题 | 内层主题（明文） | 内层主题（明文） |
| `Envelope.hops` | 普通 | 随机 0–2 | 随机 0–2 |
| `rendezvous_hint` | 无 | 无 | **有**（`NODE_ANNOUNCE` 字段 4） |
| 第三方能否验证管理员签名 | 可以（直接读） | **可以（读 `inner_body`）** | **可以（读 `inner_body`）** |

### 10.3 关键事实：当前 `signed` 与 `sealed` 线格式**完全相同**

节点层没有任何按模式分支的发布逻辑：非 `public` 模式统一走 `SubmitSealed` →
中继统一走 `publishAsRelay`。两者唯一的差异是 `sealed` 模式会在自己的
`NODE_ANNOUNCE.rendezvous_hint` 里带一个每代轮换的 `Hash`。
因此**在抓包层面无法区分 signed 与 sealed**——但这不等于 sealed 更安全，见 §10.4。

### 10.4 必须诚实写明的三个缺口（**不要在部署文档里掩盖**）

**A. `inner_body` 是明文 → sealed 不隐藏"这是管理员广播"**
发布通道把完整内层 `SignedBody`（含 2-of-3 明文签名与正文）直接放在明文 `inner_body` 里。
`Unseal` 不需要任何密钥。因此当前实现只隐藏**"是谁提交的"**（发布者被替换为中继），
**不隐藏"内容是超管授权的"**。这与 DESIGN §5.1 "只有主题密钥持有者能验证" 的承诺有实质差距。
设计文档提到的 `payload.cipher` / `TopicPolicy.wrapped_keys` 在节点层**尚未接线**。

**B. `sealed` 超管的 `NODE_ANNOUNCE.rendezvous_hint` 是可识别标记**
字段 4 只在 sealed 模式下填充。观察者无需知道 `admin_seed` 就能看出
"这个节点通告了 rendezvous_hint，所以它是 sealed 超管"。
该字段每代轮换能防长期关联，但**不能隐藏身份类别**。

**C. 公开可验证性与发送方匿名性不可兼得（DESIGN §5.6，长期结论）**
- `public`/`signed`：签名明文在线，任何人可验证；代价是"这条消息由超管授权"对全网可见。
- `sealed`（设计目标）：连"是否超管消息"都隐藏；代价是验证收窄到持有主题密钥的人，
  第三方无法独立验证。
- 即使在 sealed 目标形态下，也**不抗拥有全局视野的流量关联分析**。

---

---

## 11. 黄金测试向量 [已冻结 · 由参考实现在本仓库实跑生成]

全部输入确定性：种子固定、nonce 固定、时间戳固定。跑通 §11.6 自查清单，
说明你的确定性编码、域前缀、字节序、清空规则全部正确。

### 11.1 输入

```
seed_alice = 0x01 重复 32 次   (label "alice", role ADMIN_ROLE_ROOT)
seed_bob   = 0x02 重复 32 次   (label "bob",   role ADMIN_ROLE_ROOT)
seed_carol = 0x03 重复 32 次   (label "carol", role ADMIN_ROLE_ROOT)

AdminSet:
  generation=1  threshold=2  total=3  scheme=1 (ED25519_MULTISIG)
  clock_skew_tolerance_nanos = 300000000000
  created_at_unix_nanos      = 1699999999000000000
  keys / root_key_ids 按 key_id 字节序升序
  previous_set_hash / relay_policy / inboxes / signers 均未设置

SignedBody:
  proto_version=1  kind=1 (ADMIN_BROADCAST)  topic="ops.alert"
  created_at_unix_nanos=1700000000000000000  expires_at_unix_nanos=1700604800000000000
  nonce = 000102030405060708090a0b0c0d0e0f
  admin_set_generation=1  signer_set_hash = ADMIN_SET_HASH(上面的 AdminSet)
  policy = 与 AdminSet.policy 相同
  author / msg_id / signers 均未设置   max_hops=32
  payload.text = { media_type:"text/plain", body:"hello futurecast" }
```

派生密钥：

| label | seed (hex) | ed25519 pub (hex) | key_id (hex) |
|---|---|---|---|
| alice | `0101010101010101010101010101010101010101010101010101010101010101` | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` | `34750f98bd59fcfc946da45aaabe933b` |
| bob   | `0202020202020202020202020202020202020202020202020202020202020202` | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` | `6a3803d5f059902a1c6dafbc9ba47292` |
| carol | `0303030303030303030303030303030303030303030303030303030303030303` | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` | `b62e867fa2f33afe62d5d6b1642e1621` |

### 11.2 `CanonicalAdminSet`（309 字节）

```
667574757265636173742f76312f61646d696e73657400080112410a120a1034
750f98bd59fcfc946da45aaabe933b12220a208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c1a05616c6963652001123f0a12
0a106a3803d5f059902a1c6dafbc9ba4729212220a208139770ea87d175f56a3
5466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3941a03626f62200112410a
120a10b62e867fa2f33afe62d5d6b1642e162112220a20ed4928c628d1c2c6ea
e90338905995612959273a5c63f93636c14614ac8737d11a056361726f6c2001
1a49080210031a120a1034750f98bd59fcfc946da45aaabe933b1a120a106a38
03d5f059902a1c6dafbc9ba472921a120a10b62e867fa2f33afe62d5d6b1642e
162120012880f092cbdd082880ecbcd4df9fe7cb17
```

```
ADMIN_SET_HASH = c06a96ce9ec26d8c9765b364127e889cd46295380d0aa8aa9c9ab452b4635265
```

首 23 字节是 `DOMAIN_ADMIN_SET`（`667574757265636173742f76312f61646d696e73657400`），
随后是 `det_proto(AdminSet 去掉 signers)`：

| 字节 | 含义 |
|---|---|
| `08 01` | f1 `generation=1` |
| `12 41` + 65 B | f2 `keys[0]`（alice） |
| `12 3f` + 63 B | f2 `keys[1]`（bob） |
| `12 41` + 65 B | f2 `keys[2]`（carol） |
| `1a 49` + 73 B | f3 `policy`（threshold=2,total=3,3×root_key_ids,scheme=1,skew=300e9） |
| `28 80ecbcd4df9fe7cb17` | f5 `created_at_unix_nanos` |
| — | f4/f6/f7/f8 未设置 → 省略 |

### 11.3 `SIGNED_BYTES(SignedBody)`（227 字节）

```
667574757265636173742f76312f7369676e6564626f647900080110011a096f
70732e616c657274288080a8b1e39fe7cb17308080ccfae2e1f0cc173a100001
02030405060708090a0b0c0d0e0f40014a220a20c06a96ce9ec26d8c9765b364
127e889cd46295380d0aa8aa9c9ab452b46352655249080210031a120a103475
0f98bd59fcfc946da45aaabe933b1a120a106a3803d5f059902a1c6dafbc9ba4
72921a120a10b62e867fa2f33afe62d5d6b1642e162120012880f092cbdd086a
200a1e0a0a746578742f706c61696e121068656c6c6f20667574757265636173
747020
```

```
MSG_ID = 499fbe1b60288b97831c7b46507412c46dfbc39d60c5ab48e781351d8879a0b1
```

首 25 字节是 `DOMAIN_SIGNED_BODY`，随后：

| TLV | 字段 | 值 |
|---|---|---|
| `08 01` | f1 `proto_version` | 1 |
| `10 01` | f2 `kind` | 1 |
| `1a 09 6f70732e616c657274` | f3 `topic` | `"ops.alert"` |
| ~~f4~~ | `msg_id` | **省略（清空）** |
| `28 8080a8b1e39fe7cb17` | f5 `created_at` | 1700000000000000000 |
| `30 8080ccfae2e1f0cc17` | f6 `expires_at` | 1700604800000000000 |
| `3a 10 000102…0e0f` | f7 `nonce` | 16 B |
| `40 01` | f8 `admin_set_generation` | 1 |
| `4a 22 0a 20 <hash>` | f9 `signer_set_hash` | 11.2 的 hash |
| `52 49 …` | f10 `policy` | 同 11.2 |
| ~~f11~~ | `author` | **省略（未设置）** |
| ~~f12~~ | `signers` | **省略（清空）** |
| `6a 20 0a1e 0a0a "text/plain" 1210 "hello futurecast"` | f13 `payload.text` | — |
| `70 20` | f14 `max_hops` | 32 |

### 11.4 `SIGN_INPUT` 与 ed25519 签名

```
signer_key_id        = 34750f98bd59fcfc946da45aaabe933b
signed_at_unix_nanos = 1700000000000000000
SIGN_INPUT           = 8e67ba6030d70638307542d80ce38381b2d9541b0e2f4de632ae8816aaefd4ed
```

`ED25519_SIGNATURE`（64 B，`Signature.signature` 字段的值）：

```
113f048bf63e3ee4a8564bcb74caf66dfab370c90cee20477afe18901bf9abc7
e4dc994857fbf2eaa65c828894d8c694f604dc133c21c3ef7b3ac5f0f3841b00
```

### 11.5 Hello 自证：双前缀实测证据 ⚠️

`HELLO_CANONICAL`（`CanonicalHello` 的输出，已含 `DOMAIN_HELLO`，162 字节）：

```
667574757265636173742f76312f68656c6c6f00080110011a220a2034750f98
bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e22220a20
8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
2a0e3132372e302e302e313a3737373732220a20c06a96ce9ec26d8c9765b364
127e889cd46295380d0aa8aa9c9ab452b46352653801408080a8b1e39fe7cb17
482a
```

```
HELLO_DIGEST_CURRENT = SHA256(DOMAIN_HELLO || canonical_hello) = c9d5b80272fd1f98a1b62f5632669b83716387a1a6decdf40d24d7bbf266f4fe
HELLO_DIGEST_SINGLE  = SHA256(canonical_hello)                 = 25cf14e53b1440bdbb03623e56aa511c0a64e97d2c1f90f92101ab2019a213d5
```

`HELLO_SIGNATURE`（当前实现签名的是 `HELLO_DIGEST_CURRENT`）：

```
ffd1655ff21335f8f56a12ed60a43deced2952c9e52a7a2b8a1428f550d2e4b0
94e15abb13da1d8c65bfecde08073a321cdef3e65be23eebde5336698a4f2104
```

对上面的签名分别验签（alice 公钥）：

```
Verify(pub, HELLO_DIGEST_SINGLE,  sig) = false
Verify(pub, HELLO_DIGEST_CURRENT, sig) = true
```

→ 当前实现的被签名摘要是 `SHA256(DOMAIN_HELLO || DOMAIN_HELLO || det_proto(Hello 去掉 self_signature))`，
即 §4.5 的"域出现两次"。**若 Lead 改为单前缀，本节两个摘要与签名都会变。**

Hello 的输入：`proto_version=1, min_proto=1, listen_addrs=["127.0.0.1:7777"]`，
`admin_set_hash = 11.2 的 hash`，`admin_set_generation=1`，`issued_at=1700000000000000000`，`nonce=42`，
`node_id = NodeID(alice 公钥)`，`self_signature` 参与编码前清空。

### 11.6 自查清单

1. `CanonicalAdminSet` 十六进制 == 11.2，长度 309；
2. `SHA256(...)` == 11.2 的 `ADMIN_SET_HASH`；
3. `SIGNED_BYTES` 十六进制 == 11.3，长度 227；
4. `SHA256(DOMAIN_MSG_ID || SIGNED_BYTES)` == 11.3 的 `MSG_ID`；
5. `SHA256(DOMAIN_SIGN_INPUT || SIGNED_BYTES || key_id || u64be(signed_at))` == 11.4 的 `SIGN_INPUT`；
6. 用 alice 公钥验证 11.4 的签名 == 通过；
7. `SHA256(DOMAIN_HELLO || CanonicalHello(11.5 输入))` == 11.5 的 `HELLO_DIGEST_CURRENT`。

## 12. 实现者常见错误清单

1. **AdminSet 用了 `DOMAIN_SIGNED_BODY`**：必须用 `DOMAIN_ADMIN_SET`（§3.2 历史说明）。
2. **自证签名域只加一次**：当前实现是**两次**（§4.5）。按单前缀实现会验签失败；
   动手前先确认 `internal/crypto` 是否已改为单前缀。
3. **封存明文用 `SIGNED_BYTES`**：必须用**完整** `det_proto(body)`（含 `msg_id` 与 `signers`，无域前缀）。
4. **给 `msg_id`/`signers` 之外还清了别的字段**，或**忘了清**这两个。
5. **proto3 默认值不省略**（把 `address_public=false` 编进去），
   或**反过来把"已设置的空消息"省略**（§3.1 规则 4）。
6. **`SignInput` 的 `signed_at` 用了变长十进制**而不是 `u64be` 补码整数。
7. **repeated 字段重排**（`keys`/`root_key_ids`/`signers` 生成侧按 `key_id` 升序）。
8. **把 `Envelope.hops`/`relay_tag` 纳入签名**（它们必须可变）。
9. **用 `Envelope.max_hops` 参与签名**（签的是 `SignedBody.max_hops`）。
10. **节点消息信任消息自称的公钥**，而不是握手会话公钥（§6.1 步 9）。
11. **先做语义检查、后校验 msg_id**（会给出错误的错误类型，§6.1）。
12. **重复签名先去重后验签**：只对"成功采纳过"的 key_id 去重（§6.2）。
13. **发布通道携带 `epoch`/`ephemeral_x25519`/`ciphertext`**：会破坏副本不可关联性（§8.1）。
14. **rendezvous info 用二进制 epoch**：必须用 `"fc/v1/inbox" || "/" || 十进制(epoch)`（§8.3）。
15. **AEAD AD 少了 `AD_PREFIX_SEALED`**：AD = `"futurecast/v1/sealed\0"` + rendezvous(32B) + u64be(epoch)。
16. **误以为 sealed 隐藏内容**：当前实现 `inner_body` 是明文（§10.4-A）。

---

## 13. 参考实现文件对照（便于交叉核对）

| 规则 | 参考实现位置 |
|---|---|
| 帧格式 / 长度上限 | `internal/codec/codec.go` |
| 域前缀与常量 | `internal/housekitchen/ids.go` |
| canonical 七种对象 | `internal/housekitchen/canonical.go` |
| SIGN_INPUT / 签名 / 多签 / X25519 派生 | `internal/crypto/crypto.go` |
| 校验管线 / 轮换链 | `internal/registry/registry.go` |
| 签发顺序 / signers 排序 | `internal/registry/sign.go` |
| 握手自证 / 节点身份 | `internal/identity/node.go` |
| 封存参数 / 中继选择 / 抖动 / 信箱 | `internal/sealed/sealed.go` |
| 中继发布通道 / 提交通道 | `internal/node/sealed_relay.go` |
| 节点配置与模式 | `internal/node/config.go` |
| ALPN / TLS | `internal/transport/tlsutil.go` |
| 跨语言一致性向量（另一份） | `internal/conformance/vectors.go`、`scripts/vectors/vectors.json` |

---

## 附录 A：内容分片与 Merkle 约定（实现事实，v1）

`ContentManifest.merkle_root` 的算法在 proto 里没有写死，以下是本实现的约定。
跨语言实现如需互通，必须与本节一致。

```
叶节点   : leaf_i   = SHA-256( chunk_i 的原始字节 )
内部节点 : parent   = SHA-256( left || right )
奇数节点 : 末节点原样进位到上一层（不复制、不哈希自身）
根       : 全部合并后的单一 32 字节摘要
```

- `chunk_size` 默认 1 MiB，`chunk_count = ceil(total_size / chunk_size)`。
- 收到分片时先校验 `SHA-256(data) == 该分片的期望叶摘要`，不符立即丢弃并扣减对端评分。

`CommitManifest` 的错误语义（**调用方必须区分**）：

| 情况 | 错误 | 含义 |
|------|------|------|
| 分片内容与其摘要不符 / 总长不符 / merkle 根不符 | 包装 `ErrInvalidSignature` | **校验失败**，该内容永久不可信，应丢弃并惩罚来源 |
| 分片尚未到齐 | 专用 `errIncompleteContent`（**不**包装 `ErrInvalidSignature`） | **还没到齐**，应继续向其他邻居拉取，不应惩罚来源 |

只判断 `errors.Is(err, ErrInvalidSignature)` 会把"还没到齐"误判为"内容被投毒"，
从而错误地封禁正常邻居。

---

## 附录 B：作者身份的自证模型（v1，重要）

早期设计曾规定"节点消息的作者必须等于连接对端的身份"。**这是错的，已废除。**

原因：Gossip 网络中消息会被中继转发。接收方的直接对端是**转发者**，而不是**作者**。
若坚持"作者 = 对端"，任何转发都会被拒绝，网络退化成只允许直连发布。

v1 的信任模型是**作者自证**，由两件事共同保证：

1. `SignedBody.author_pub`（field 15，**在签名覆盖范围内**）必须哈希出 `SignedBody.author`；
2. `author_pub` 对应的私钥必须对 `SIGNED_BYTES` 签过名（即 `signers` 中包含
   `KeyID = SHA-256(author_pub)[:16]` 的有效签名）。

因此：

- 作者身份**不依赖传输层**，中继无法冒充作者，也无法把别人的消息改成自己的；
- 携带 `author_pub` 不泄露额外信息 —— `author`(NodeID) 本身就是 `SHA-256(author_pub)`；
- 连接对端身份（握手得到的公钥）仅用于**可选交叉校验**：
  当对端自称就是作者时，用它的握手公钥再核一次。

**这条对 sealed 模式尤其关键**：中继用**自己的**节点密钥签名外层，`author` = 中继自身，
所以外层看起来完全是"某个普通节点发布的消息"。内层管理员正文的作者信息被封存，
只有持主题密钥者解封后可见。

---

## 附录 C：sealed 内容的两种形态（v1）

`SealedPayload` 一个结构、两种用途。**务必区分**：

### C.1 提交通道（超管 → 中继，点对点）

| 字段 | 值 |
|------|-----|
| `inbox_rendezvous_id` | 本代 rendezvous 信箱 ID |
| `epoch` | 本代编号 |
| `ephemeral_x25519` | 发送方临时 X25519 公钥 |
| `ciphertext` | `AES-256-GCM(canonical 完整 SignedBody)` |
| `jitter_hint_ms` | 建议抖动上限 |
| `inner_body` / `inner_ciphertext` | **空** |

密钥派生：`HKDF-SHA256(X25519(eph_priv, relay_x25519_pub), salt=nil, info="fc/v1/sealed", 32)`
关联数据：`"futurecast/v1/sealed\x00" || rendezvous_id || u64be(epoch)`
密文布局：`nonce(12B) || ciphertext || tag(16B)`

### C.2 发布通道（中继 → 公网，kind = `MESSAGE_KIND_SEALED`）

**只填 `inner_body` 或 `inner_ciphertext`，绝不填提交通道的字段。**

| 配置 | 填充 | 观察者能知道什么 |
|------|------|-----------------|
| 未配置 `topic_secret` | `inner_body` = 内层正文明文 | 能读到正文、能验证超管签名（**只在隐藏提交者**） |
| 配置了 `topic_secret` | `inner_ciphertext` + `inner_nonce` + `topic_key_id` | **只能看到密文**，连"这是超管广播"都无法判定 |

两种情况下 `inbox_rendezvous_id` 都被复用为**内层正文的 SHA-256 承诺值**
（`SHA-256(inner_bytes)`），并且它位于**外层节点签名的覆盖范围内**，
因此中继无法把内层正文调包成另一条消息。

主题密钥派生：

```
topic_key = HKDF-SHA256( secret = SHA-256(passphrase),
                         salt   = SHA-256(topic),
                         info   = "fc/v1/topickey",
                         len    = 32 )
inner_ad  = "futurecast/v1/innerbody\x00" || topic
```

**为什么发布通道不携带 `epoch` / `ephemeral_x25519` 等字段**：这些值在同一次发布的
多个中继副本之间是**共享的**。一旦携带，观察者就能用它们把 N 份副本关联起来，
反推出"哪几个节点在替同一个人转发"，直接摧毁 sealed 模式的核心保证。
同理，中继发布时会把 `hops` 与 `relay_tag` 随机化到普通消息的取值区间。

---

## 附录 D：跨语言实现检查清单（易错点）

| # | 易错点 | 正确做法 |
|---|--------|---------|
| 1 | 域前缀加两次 | 每个 `CanonicalXxx` 的返回值**已含域前缀**，直接对它签名；不要再叠加 |
| 2 | 把 AdminSet 摘要当成 SignedBody 摘要 | 两者域前缀不同：`adminset\0` vs `signedbody\0` |
| 3 | 忘记清空签名字段 | `SignedBody` 清 `msg_id`+`signers`；`AdminSet` 清 `signers`；`NodeAnnounce`/`PeerExchange`/`Hello` 清 `self_signature` |
| 4 | 用哈希表序输出 `signers` | 规范化前必须清空；写回后按 `key_id` 字典序排列 |
| 5 | `AdminSet.keys` / `root_key_ids` 顺序不定 | 必须按 `key_id` 字典序排序，否则摘要因实现而异 |
| 6 | 把 proto3 默认值也编码进去 | 默认值（0/""/空数组）一律**不编码** |
| 7 | HKDF salt 为空当成空字节串 | 空 salt = RFC 5869 的 **32 个 0x00** |
| 8 | 域前缀的 NUL 结尾搞错 | `DomainInbox` 与 `DomainTopicKey` **无** NUL 结尾；`DomainRelayTag` 等**有** |
| 9 | `expires_at = 0` 当作永不过期 | v1 要求 `expires_at > created_at > 0`，无"永不过期"语义 |
| 10 | 门限取自消息里的 `policy` | 门限、`root_key_ids`、方案**一律取自本地 AdminSet**；消息声明的 policy 只允许"一致或被拒" |

---

## 附录 E：定向广播（v1）

### E.1 线格式

`Envelope.directed_body`（字段 8）与 `Envelope.body`（字段 7）**二选一**。
定向广播填 `directed_body`，其被签名对象是 `DirectedBody` 而不是 `SignedBody`。

`DirectedBody` 字段（号 / 类型 / 是否参与签名）：

| 号 | 字段 | 类型 | 参与签名 |
|----|------|------|---------|
| 1 | proto_version | uint32 | 是 |
| 2 | kind | MessageKind (=4) | 是 |
| 3 | msg_id | Hash | 否（派生值） |
| 4 | created_at_unix_nanos | int64 | 是 |
| 5 | expires_at_unix_nanos | int64 | 是 |
| 6 | nonce | bytes(16) | 是 |
| 7 | admin_set_generation | uint64 | 是 |
| 8 | signer_set_hash | Hash | 是 |
| 9 | policy | SigningPolicy | 是 |
| 10 | max_hops | int32 | 是 |
| 11 | signers | repeated Signature | 否（签名本体） |
| 12 | recipients | repeated DirectRecipient | 是 |
| 13 | ciphertext | bytes | 是 |
| 14 | content_nonce | bytes(12) | 是 |
| 15 | recipient_count | uint32 | 是 |
| 16 | blind_salt | bytes(16) | 是 |

`DirectRecipient`：`eph_pub`(1, bytes32)、`wrapped_key`(2, bytes)、`recipient_tag`(3, bytes16)。

`DirectedKernel`（内层，加密后承载）：`topic`(1)、`media_type`(2)、`body`(3)、
`created_at_unix_nanos`(4)、`expires_at_unix_nanos`(5)、`nonce`(6)。
**字段 7 已废弃并保留号**（早期设计过一个 `outer_msg_id`，实际绑定由 AAD 里的
`blind_salt` 完成，该字段从未被填充，故删除且不得再编码）。

### E.2 规范化与派生

```
DIRECTED_BYTES  = "futurecast/v1/directedbody\x00" || deterministic_proto(DirectedBody 去 msg_id 去 signers)
DIRECTED_MSG_ID = SHA-256("futurecast/v1/msgid\x00" || DIRECTED_BYTES)
KERNEL_BYTES    = "futurecast/v1/directedkernel\x00" || deterministic_proto(DirectedKernel)
content_key     = 32 字节随机（一次性）
blind_key       = HKDF-SHA256(secret=content_key, salt=blind_salt, info="fc/v1/directedblind", len=32)
recipient_tag   = HMAC-SHA256(blind_key, "futurecast/v1/dirtag\x00" || node_id)[:16]
recipient_x25519= Ed25519ToX25519(收件人 ed25519 公钥)
wrap_key_i      = HKDF-SHA256(secret=X25519(eph_priv_i, recipient_x25519),
                              salt=nil, info="fc/v1/directedwrap", len=32)
wrapped_key_i   = AES-256-GCM(wrap_key_i, content_key)
                  AD = "futurecast/v1/dirwrap\x00" || blind_salt || u64be(i)
ciphertext      = AES-256-GCM(content_key, KERNEL_BYTES)
                  AD = "futurecast/v1/directedkernel\x00" || blind_salt
```

**AD 里用的是 `blind_salt` 而不是外层摘要**，这是刻意的：外层摘要覆盖
`ciphertext`，而 `ciphertext` 又需要 AD，用摘要会形成循环依赖。
`blind_salt` 是每消息随机值、且在门限签名覆盖范围内，作为绑定同样安全且实现无误。

### E.3 校验顺序

外层（任何节点可做，**无需解密**）：

```
1. kind == MESSAGE_KIND_DIRECTED_BROADCAST
2. proto_version 落在 [MinProtoVersion, ProtoVersion]
3. DIRECTED_MSG_ID 与 msg_id 一致                        -> ErrMsgIDMismatch
4. created_at > 0、expires_at > created_at、且未过期       -> ErrClockSkew / ErrExpired
5. admin_set_generation 与本地集合一致                     -> ErrGenerationMismatch
6. signer_set_hash == SHA-256(CanonicalAdminSet)          -> ErrSignerSetMismatch
7. recipients 非空、recipient_count 相符、content_nonce 长 12、
   ciphertext 非空、blind_salt 长 16                       -> ErrDirectedInvalid
8. 门限签名（门限与 root_key_ids 取自本地 AdminSet）        -> ErrThresholdNotMet
```

内层（仅收件人可做）：

```
9.  逐槽位 unwrap_key_i，失败则试下一槽
10. 成功者用 blind_key 算出自己的 recipient_tag，与槽位值常数时间比较；不等则跳过
11. 用 content_key 解 ciphertext（AD 用 blind_salt）
12. 剥掉 "futurecast/v1/directedkernel\x00" 前缀后解析 DirectedKernel
13. kernel.topic 必须非空
```

第 10 步不可省：否则构造错误槽位的攻击者可以让人误以为消息是发给别人的。

**一条容易误判的排序事实**：`recipient_count` 与 `blind_salt` 都参与签名，
因此**直接篡改**它们会先被第 3 步的内容寻址拦成 `ErrMsgIDMismatch`；
只有"改完再重新签名"的消息才会走到第 7 步的结构检查并得到 `ErrDirectedInvalid`。
两者都是正确拒绝，但错误码不同，实现与测试都应对齐这一点。

`blind_salt` 的长度检查**必须放在外层**（第 7 步），不能只在收件人解密时做：
否则一条重新签名的短盐消息能通过所有中继的外层校验并被全网转发，
而只有收件人在解密时才发现打不开 —— 攻击者可借此制造大量无法解密的流量。

### E.4 与其它模式的互操作

- 定向广播**可与 sealed 模式叠加**：超管用封存投递把定向消息交给中继，
  中继转发外层；此时内容对中继与全网都是密文。
- 定向广播**不需要**主题密钥，也不需要 `topic_secret`。
- 收到定向广播但非收件人的节点：**正常转发**，并记录一条不含任何内容的回执。
- 收件人解开后**可以再转发**（技术上无法阻止）。约定上建议标注来源为"定向广播"。
