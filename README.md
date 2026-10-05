# FutureCast

**无中心服务器的广播网络**：任意数量节点互相发现、互为中继；
持有「超级管理员」门限密钥（默认 **2-of-3**）的一组人签发广播，
该广播在丢包、断连、部分节点作恶的条件下**最终到达每个在线节点**，
且节点能独立验证「这条消息确实由超管门限授权、内容未被改动」。

- 线格式与互通规范：[docs/PROTOCOL.md](docs/PROTOCOL.md)
- 设计说明书：[docs/DESIGN.md](docs/DESIGN.md)
- 冻结接口契约：[docs/CONTRACTS.md](docs/CONTRACTS.md)

> **先读这一句**：本项目当前处于 **M0/M1 之间的集成期**，但 **CLI 已经可用**。
> `internal/` 下的密码学、注册表、存储、封存、传输、节点包已落地并有测试；
> `cmd/futurecast` 与 `internal/cli` 已实现全部子命令：`init` / `node` / `status` /
> `peers` / `publish` / `verify`，以及 `admin keygen|set|rotate|compose|sign|finalize`。
> 先 `make build` 即可构建。本文档中的所有命令形态都由 `scripts/demo.sh`
> （三节点端到端演示）与 `scripts/selftest.sh` 实跑覆盖；脚本在依赖缺失时会明确报错
> 退出，不会伪造成功输出。以代码为准，不以本文的宣传口径为准。

---

## 1. 三种超管模式

超管可以选择是否公开自己的 IP。这个选择决定了两件事：**谁能验证消息**、**谁看得到超管的位置**。

| | `public` | `signed` | `sealed` |
|---|---|---|---|
| 监听端口 | ✅ 可做种子 | ❌ 只出站 | ❌ 只出站 |
| 地址进入网络地址簿 | ✅ | ❌ | ❌ |
| 谁能验证「超管授权」 | 任何人 | 任何人 | **仅持主题密钥者**（设计目标） |
| 外部可见的事实 | 「超管 IP 发了 X」 | 「某节点转发了超管签名的 X」 | 「某节点发了一条消息」 |
| 抗流量关联 | 低 | 中 | 高（有限，见 §3） |

**线格式上到底差在哪**：`public` 直接发一条 `kind=ADMIN_BROADCAST` 的普通消息；
`signed`/`sealed` 由超管**主动出站**把封存副本交给若干中继，中继再用**自己的节点身份**
重签一条 `kind=SEALED` 的外层消息发布出去。逐字段差异见
[PROTOCOL §10](docs/PROTOCOL.md)。

⚠️ **当前实现的诚实说明（不要跳过）**：

1. `signed` 与 `sealed` 目前走**同一条发布路径**，公网线格式**完全相同**；
2. 发布通道的 `inner_body`（内层管理员正文）**是明文**，`Unseal` 不需要密钥。
   也就是说：当前 `sealed` 只隐藏「**是谁提交的**」（发布者被替换为中继），
   **没有隐藏「内容是管理员广播」**。设计文档承诺的"仅主题密钥持有者可验证"尚未接线；
3. `sealed` 超管的 `NODE_ANNOUNCE.rendezvous_hint` 是一个**可被观察者识别的标记**，
   能看出"这个节点是 sealed 超管"（每代轮换只能防长期关联，防不了身份类别）。

这三条都是**已知缺口**，不是本文的修辞。实现/部署前请以
[PROTOCOL §10.4](docs/PROTOCOL.md) 为准做安全评审。

---

## 2. 环境准备

Go `1.22.2`（linux/arm64 已验证）。**本机公网 `proxy.golang.org` 不可达**，
必须使用镜像，否则依赖拉不下来：

```bash
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=off
export PATH="$PATH:/root/go/bin"      # protoc-gen-go
```

`scripts/` 下所有脚本都会在顶部自动 export 这三个变量，直接用即可。

生成 protobuf 绑定（需要 `protoc` + `protoc-gen-go`，模块已生成过，一般无需重跑）：

```bash
protoc --proto_path=proto \
  --go_out=. --go_opt=module=github.com/loongqing/FuturecastAlpha \
  proto/futurecast/v1/*.proto
```

---

## 3. 安全模型与能力边界（**诚实清单**）

**信任根**：`AdminSet` 里只有公钥与门限 M/N；没有"特权节点"这种角色。
节点只需知道当前 `AdminSet`，用 2-of-3 门限签名验证消息。
`msg_id = SHA-256(规范化正文)` 提供去重与内容寻址；篡改任意 1 字节都会先破坏 `msg_id` 被丢弃。

**能做到的**：

- 无中心服务器；节点掉线后消息仍能绕路到达（最终一致，**不是**同时到达）；
- 单把管理员密钥泄露不足以签发广播（需 2/3）；
- 内容篡改、重放（时间窗 + nonce + 去重）、超跳数、超配额在协议层被拒；
- 传输层 TLS 提供链路机密性，但**不承担身份认证**——身份一律靠 Ed25519 自证。

**做不到 / 明确不承诺的**：

> **公开可验证性与发送方匿名性不可兼得**（[DESIGN §5.7](docs/DESIGN.md)）。

- 要让**任何人**都能验证「这是超管签的」，门限签名必须明文出现在公网消息里，
  于是「这条消息由超管授权」对所有人可见（`public`/`signed`）；
- 要让外部观察者连「这是超管发的」都判定不了，验证必然收窄到**持有主题密钥的人**（`sealed` 目标形态），
  第三方无法独立验证；
- **不抗拥有全局视野的强对手做流量关联分析**；不做强匿名（Tor/混合网只是叠加项，不是保证）；
- 不做拜占庭一致的全局排序（只承诺最终一致）；
- 当前实现还存在 §1 列出的三个缺口（`sealed` 内容明文、signed≡sealed、`rendezvous_hint` 标记）。

**当前实现的密码学参数**（细节见 [PROTOCOL](docs/PROTOCOL.md)）：

| 用途 | 算法 |
|---|---|
| 消息与节点身份签名 | Ed25519（纯 Ed25519，非 Ed25519ph） |
| 内容寻址 / 域分隔摘要 | SHA-256，域前缀含结尾 `\0` |
| 密钥派生 | HKDF-SHA256 |
| 封存 / 主题密钥封装 | X25519 + HKDF-SHA256 + AES-256-GCM（12B nonce，`nonce‖ct‖tag`） |
| 中继 X25519 公钥 | 由节点 ed25519 公钥确定性映射（不占协议字段） |
| 链路 | QUIC TLS 1.3（ALPN `futurecast/1`），TLS-over-TCP 后备 |

---

## 4. 快速开始

> 以下命令遵循 [CONTRACTS](docs/CONTRACTS.md) 与本仓库约定的 CLI 形态，**均已实现**。
> 先构建：`make build`（等价于 `go build -o bin/futurecast ./cmd/futurecast`）。

### 4.1 一键建网：生成 2-of-3 管理员密钥环

```bash
scripts/keygen.sh --out ./admin-keys --threshold 2 --total 3
```

产出 3 份私钥文件（权限 `0600`，请分放 3 台离线机）+ 一份创世 `AdminSet` JSON，
并打印公钥指纹供人工核对备份。**私钥不要放进版本库、不要联网传输。**

### 4.2 启动节点

```bash
# 种子节点（public 模式，公布地址，可被拨入）
futurecast node --config ./node1.yaml

# 加入者：配置里 seeds 指向任意一个已知节点即可，网络会自动扩张
futurecast node --config ./node2.yaml
```

### 4.3 发布广播

```bash
# 公开模式：任何人可验证
futurecast publish --config ./node1.yaml --topic ops.alert --text "进入静默模式"

# signed：签名明文可验，但超管机器不在地址簿里
futurecast publish --config ./admin.yaml --topic ops.alert --text "..." --mode signed

# sealed：中继转发，超管机器不可被扫描
futurecast publish --config ./admin.yaml --topic ops.alert --text "..." --mode sealed
```

### 4.4 查看状态与离线校验

```bash
futurecast status --config ./node2.yaml      # 邻居、代数、当前 AdminSet 摘要
futurecast verify --envelope ./env.json      # 不联网校验一条广播
```

### 4.5 门限签发（离线收集流程）

```bash
futurecast admin set    --keyring ./admin-keys --generation 1 --out admin-set.json
futurecast admin sign   --keyring ./admin-keys --in body.json --key <id> --out sig1.json
futurecast admin sign   --keyring ./admin-keys --in body.json --key <id> --out sig2.json
futurecast admin finalize --in body.json --sigs sig1.json,sig2.json --out envelope.json
futurecast admin rotate --keyring ./admin-keys --generation 2 --out admin-set.json \
                        --sign-with <id1>,<id2>
```

### 4.6 一键自检与演示

```bash
scripts/selftest.sh     # go build + go test + go test -race，逐项输出结果
scripts/demo.sh         # 三节点本机演示（CLI 未就绪时会明确报错）
make -f scripts/Makefile.frag help   # 可加入根 Makefile 的目标清单
```

---

## 5. 常见问题（FAQ）

**Q：节点起不来，提示端口占用 / `address already in use`。**
默认 QUIC 走 **UDP**。检查 `listen` 端口是否被占用（同机跑多节点必须用不同端口），
以及防火墙是否放行 UDP。`signed`/`sealed` 模式**故意不监听端口**，这是设计行为，不是故障。

**Q：在 NAT / 云主机后面能被连上吗？**
`public` 模式需要**可被拨入**的地址（端口映射 / 公网 IP + 放行 UDP）。
`signed`/`sealed` 超管**只出站**，不需要任何入站映射——这也是它不可被扫描的原因。
只有在 NAT 后的普通节点建议配置至少一个可拨入的种子。

**Q：日志出现 `signature timestamp outside tolerance` / 消息莫名被丢。**
先对时。签名时间戳默认容差 **±300 s**；`created_at` 超前 300 s 会被判 `ErrClockSkew`。
用 NTP 同步各节点时钟。注意校验顺序：正文被改动时先报的是
`msg_id does not match body`，而不是语义错误——这是设计意图。

**Q：密钥怎么备份？**
3 份管理员私钥**分开放**（3 台离线机 / 3 张硬件密钥），任何一份单独泄露都签不出广播。
备份后核对脚本打印的公钥指纹，并记下创世 `AdminSet` 的 SHA-256；
轮换后旧代数在宽限期（最近 4 代）之后彻底失效。
节点身份密钥默认在 `~/.futurecast/`（`0600`）——丢了只是换身份，不影响网络，但会换 `NodeID`。

**Q：`sealed` 消息为什么我能看懂？**
当前实现的 `inner_body` 是明文（§1 缺口 2），`Unseal` 不需要密钥。
在缺口修复前，**不要把 sealed 当作内容保密手段**。

**Q：`scripts/selftest.sh` 里 `go test -race` 报 `ThreadSanitizer: unsupported VMA range`。**
这是**运行环境限制**（本沙箱/部分内核不允许 TSan 预留所需地址区间），不是代码缺陷。
`selftest.sh` 会把这种失败单独记为 `ENV`，不掩盖真正的测试失败。
要跑 race，请在正常内核的 Linux 主机（或 CI）上执行 `go test -race ./...`。

**Q：`go build` 报依赖下载失败。**
你的 `GOPROXY` 没设镜像。执行 §2 的三行 export。`sum.golang.google.cn` 在本机不可达，
所以必须同时 `export GOSUMDB=off`。

---

## 6. 仓库结构

```
futurecast/
├── docs/PROTOCOL.md      线格式规范 + 黄金测试向量（跨语言互通契约）
├── docs/DESIGN.md        设计说明书（§11 proto 摘要为早期版本，字段号以 proto/ 为准）
├── docs/CONTRACTS.md     冻结接口契约
├── proto/futurecast/v1/  唯一真相源：common.proto · message.proto · wire.proto
├── gen/futurecastv1/     protoc 生成（勿手改）
├── cmd/futurecast/       CLI（node/publish/status/admin/verify）—— 入口 main.go → internal/cli
├── internal/             codec · housekitchen · crypto · identity · registry
│                         store · peer · sealed · transport · node · cli
│                         · directed · conformance
└── scripts/              keygen.sh · demo.sh · selftest.sh · Makefile.frag
```

## 7. 许可与状态

本项目以 **MIT 许可**发布，全文见 [LICENSE](LICENSE)。

当前为内部开发阶段（M0→M1），接口仍可能破坏性变更——
每一次线格式变更都会同步更新 [PROTOCOL](docs/PROTOCOL.md) 的版本说明。

---

## 定向广播：只有被点名的节点能解密

```bash
# 1) 先查已知节点的完整 node_id
futurecast peers --config seed.json

# 2) 指定收件人发布（只有他们能解密；中继与其他节点能验签但读不到内容）
futurecast publish --config seed.json --topic alerts --text "只给你们三个" \
    --direct-to <node_id_1>,<node_id_2>,<node_id_3> \
    --admin-keys admin-keys/admin-1.key,admin-keys/admin-2.key
```

效果：

| 角色 | 能做/能看到什么 |
|------|----------------|
| 被点名的收件人 | 解出正文，并确认"这确实来自超管（2/3 签名）" |
| 中继 / 其他节点 | 能验签、能转发，**读不到正文** |
| 外部观察者 | 只知道"存在一条定向广播、有几个槽位"，**不知道收件人是谁** |

按设计不做的事（不做过度承诺）：槽位数量可见（即"发给了几个人"可见）；
宏观上"存在一条定向广播"也可见 —— 当前实现按普通消息全网 gossip。
要让存在性都不可见，需要按收件人身份做定向路由，属于独立的一层，v1 未实现。

## ⚠️ 已知限制（v1，务必阅读）

### sealed 模式的入口中继能看到明文

封存投递时，入口中继必须**解封**才能独立校验内层 2-of-3 门限签名 ——
它不能盲信提交者。因此：

| 角色 | 能看到什么 |
|------|-----------|
| **入口中继**（仅限经过它的那一份副本） | 完整明文 + 门限签名 |
| 公网其他节点 / 被动观察者 | 只有密文；能看到"存在一条封存消息"，无法判定来源 |
| 持主题口令的订阅者 | 明文 + 可验证的 2-of-3 签名 |
| 订阅同主题但无口令的节点 | 只有密文 |

**部署要求：入口中继必须是受信节点**（通常由你自己运营）。
它不知道提交者是谁，但看得到内容。

彻底消除这一点需要"嵌套授权"结构（授权证明公开可验、正文单独用主题密钥加密），
属于 v2 的结构性改动，v1 明确不做。详见 `docs/DESIGN.md` §5.6。

### 已修复：传播偶发不收敛

早先版本有约 1/3 概率出现"某节点收不到广播"。根因是**一次性发布客户端退出时
丢弃了在途帧** —— `quic-go` 的 `Connection.CloseWithError()` 不保证已写入但
尚未发出的数据送达。已修复为"优雅关流 + 同步补发"，`make demo` 现可连续通过。

### 其它

- **不抗全局流量关联分析**：拥有全网视野的对手可以做统计关联。
- **公开可验证性与发送方匿名性不可兼得**（见 §5.7）：`public`/`signed` 模式公众可验证，
  `sealed` 模式的验证范围收窄到持主题口令者。
- **`go test -race` 在本机不可用**：内核 39 位 VA，ThreadSanitizer 需要 48 位
  （`unsupported VMA range`）。这是环境限制，不是代码问题。
