// 对抗性负例：以下每一条都必须被拒绝，或（对重放）证明必须由 store 层补齐。
// 断言严格遵循 docs/CONTRACTS.md §5.1 的判定顺序：
//
//	1 VerifyMsgID → 2 信封 msg_id → 3 时间窗 → 4 代数 → 5 signer_set_hash
//	6 管理员门限 + 不得带 author → 7 节点自签
//
// 因此"篡改正文"必须先撞 ErrMsgIDMismatch（设计意图），而"签名自洽但语义非法"
// 的用例必须先改字段再签名，才能抵达对应的语义检查。
package conformance_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
	"github.com/loongqing/FuturecastAlpha/internal/conformance"
	fccrypto "github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
	"github.com/loongqing/FuturecastAlpha/internal/registry"
	"github.com/loongqing/FuturecastAlpha/internal/store"
)

var negNow = conformance.VectorTime

// verifyErr 只取错误，便于在断言辅助函数里使用。
func verifyErr(r *registry.Registry, env *pb.Envelope, sess registry.Session) error {
	_, err := r.VerifyMessage(env, sess)
	return err
}

// ---------- N1 伪造世代 ----------

func TestNegative_N1_UnknownGeneration(t *testing.T) {
	keys := testAdminKeys(t, "neg")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	fake := proto.Clone(set).(*pb.AdminSet)
	fake.Generation = 7
	env, _, _ := broadcast(t, fake, keys, 2, negNow, nil)

	_, err := r.VerifyMessage(env, registry.Session{Now: negNow})
	expectErrIs(t, err, housekitchen.ErrGenerationMismatch, "N1 声明未知代数 gen=7")
}

// ---------- N2 signer_set_hash 指向另一个 AdminSet ----------

func TestNegative_N2_SignerSetMismatch(t *testing.T) {
	keysA := testAdminKeys(t, "neg-a")
	setA := testSet(t, keysA, 1, nil)
	r := newRegistry(t, setA)

	keysB := testAdminKeys(t, "neg-b")
	setB := testSet(t, keysB, 1, nil)
	env, _, _ := broadcast(t, setB, keysB, 2, negNow, nil)

	hashA, _ := housekitchen.AdminSetHash(setA)
	hashB, _ := housekitchen.AdminSetHash(setB)
	if hashA == hashB {
		t.Fatal("测试前提失败：两个集合摘要不应相同")
	}
	_, err := r.VerifyMessage(env, registry.Session{Now: negNow})
	expectErrIs(t, err, housekitchen.ErrSignerSetMismatch, "N2 signer_set_hash 指向 setB 而本地是 setA")
}

// ---------- N3 同一把密钥的签名复制多份凑门限 ----------

func TestNegative_N3_DuplicatedSignerDoesNotMeetThreshold(t *testing.T) {
	keys := testAdminKeys(t, "neg")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	env, body, canonical := broadcast(t, set, keys, 1, negNow, nil)
	one := body.Signers[0]
	body.Signers = []*pb.Signature{one, one, one}

	// 直接用冻结的 crypto.MultisigVerify：有效且互异签名数必须为 1。
	res, ok, err := fccrypto.MultisigVerify(canonical, body.Signers, identity.RootKeyIDs(set),
		identity.PubKeyResolver(set), 2, negNow, time.Duration(housekitchen.DefaultClockSkewNanos))
	if err != nil {
		t.Fatalf("MultisigVerify 返回错误: %v", err)
	}
	if ok || res.Valid != 1 {
		t.Fatalf("同一 key_id 复制 3 份后 Valid=%d ok=%v，期望 Valid=1 ok=false", res.Valid, ok)
	}
	expectErrIs(t, verifyErr(r, env, registry.Session{Now: negNow}), housekitchen.ErrThresholdNotMet,
		"N3 单密钥签名复制 3 份")

	// 更强变体：同一 key_id 的两次"不同"签名（signed_at 不同，签名字节不同）仍只计 1。
	alt := fccrypto.SignBody(keys[0].Priv, canonical, keys[0].KeyID, negNow.Add(time.Second))
	body.Signers = []*pb.Signature{one, alt}
	res2, ok2, err := fccrypto.MultisigVerify(canonical, body.Signers, identity.RootKeyIDs(set),
		identity.PubKeyResolver(set), 2, negNow, time.Duration(housekitchen.DefaultClockSkewNanos))
	if err != nil {
		t.Fatalf("MultisigVerify 返回错误: %v", err)
	}
	if ok2 || res2.Valid != 1 {
		t.Fatalf("同一 key_id 的两份不同签名 Valid=%d ok=%v，期望 1/false", res2.Valid, ok2)
	}
	expectErrIs(t, verifyErr(r, env, registry.Session{Now: negNow}), housekitchen.ErrThresholdNotMet,
		"N3 同 key_id 两份不同签名")
}

// ---------- N4 篡改正文任意 1 字节 ----------

func TestNegative_N4_TamperedBodyByte(t *testing.T) {
	keys := testAdminKeys(t, "neg")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	cases := []struct {
		name   string
		mutate func(*pb.Envelope)
	}{
		{"payload 内部 1 字节", func(e *pb.Envelope) { e.Body.Payload.GetText().Body += "x" }},
		{"topic", func(e *pb.Envelope) { e.Body.Topic = "alerts-x" }},
		{"created_at", func(e *pb.Envelope) { e.Body.CreatedAtUnixNanos++ }},
		{"nonce", func(e *pb.Envelope) { e.Body.Nonce[0] ^= 0x01 }},
		{"max_hops", func(e *pb.Envelope) { e.Body.MaxHops++ }},
	}
	for _, tc := range cases {
		env, _, _ := broadcast(t, set, keys, 2, negNow, nil)
		tc.mutate(env)
		_, err := r.VerifyMessage(env, registry.Session{Now: negNow})
		expectErrIs(t, err, housekitchen.ErrMsgIDMismatch, "N4 篡改 "+tc.name)
	}
}

// ---------- N5 msg_id 与正文不符 ----------

func TestNegative_N5_MsgIDMismatch(t *testing.T) {
	keys := testAdminKeys(t, "neg")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	// 正文 msg_id 被改写
	env, _, _ := broadcast(t, set, keys, 2, negNow, nil)
	env.Body.MsgId = housekitchen.PBHash(housekitchen.Sum256([]byte("forged-body")))
	expectErrIs(t, verifyErr(r, env, registry.Session{Now: negNow}), housekitchen.ErrMsgIDMismatch,
		"N5 正文 msg_id 被改写")

	// 仅信封 msg_id 被改写（正文仍自洽）
	env2, _, _ := broadcast(t, set, keys, 2, negNow, nil)
	env2.MsgId = housekitchen.PBHash(housekitchen.Sum256([]byte("forged-envelope")))
	expectErrIs(t, verifyErr(r, env2, registry.Session{Now: negNow}), housekitchen.ErrMsgIDMismatch,
		"N5 信封 msg_id 被改写")
}

// ---------- N6 过期 / created_at 超前（签名自洽） ----------

func TestNegative_N6_ExpiredAndFutureCreatedAt(t *testing.T) {
	keys := testAdminKeys(t, "neg")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	// 过期：先改 expires_at 再签名，使 msg_id 与签名都有效。
	env, _, _ := broadcast(t, set, keys, 2, negNow, func(b *pb.SignedBody) {
		b.ExpiresAtUnixNanos = negNow.Add(-time.Second).UnixNano()
	})
	expectErrIs(t, verifyErr(r, env, registry.Session{Now: negNow}), housekitchen.ErrExpired,
		"N6 expires_at 已过期")

	// created_at 超前：同样先改再签名。
	env2, _, _ := broadcast(t, set, keys, 2, negNow, func(b *pb.SignedBody) {
		b.CreatedAtUnixNanos = negNow.Add(time.Hour).UnixNano()
		b.ExpiresAtUnixNanos = negNow.Add(2 * time.Hour).UnixNano()
	})
	expectErrIs(t, verifyErr(r, env2, registry.Session{Now: negNow}), housekitchen.ErrClockSkew,
		"N6 created_at 超前 1 小时")

	// 边界：超出容差 1ms 即拒（DefaultClockSkewNanos = 300s）。
	env3, _, _ := broadcast(t, set, keys, 2, negNow, func(b *pb.SignedBody) {
		b.CreatedAtUnixNanos = negNow.Add(time.Duration(housekitchen.DefaultClockSkewNanos) + time.Millisecond).UnixNano()
		b.ExpiresAtUnixNanos = negNow.Add(time.Hour).UnixNano()
	})
	expectErrIs(t, verifyErr(r, env3, registry.Session{Now: negNow}), housekitchen.ErrClockSkew,
		"N6 created_at 超出容差 1ms")
}

// ---------- N7 管理员消息携带 author ----------

func TestNegative_N7_AdminMessageWithAuthor(t *testing.T) {
	keys := testAdminKeys(t, "neg")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	node, err := identity.NodeIdentityFromSeed(seed32("neg/node"))
	if err != nil {
		t.Fatalf("构造节点身份失败: %v", err)
	}
	// 先写 author 再签名，使 msg_id 与门限签名都自洽，才能抵达 author 检查。
	env, _, _ := broadcast(t, set, keys, 2, negNow, func(b *pb.SignedBody) {
		b.Author = housekitchen.PBNodeID(node.ID)
	})
	_, err = r.VerifyMessage(env, registry.Session{Now: negNow})
	expectRejected(t, err, "N7 管理员消息携带 author")
	if !strings.Contains(err.Error(), "不得携带 author") {
		t.Fatalf("N7 期望 author 拒绝路径，实为: %v", err)
	}
	// F7 已修复：该路径现在包装 ErrNotAuthorized，errors.Is 可分类。
	if !errors.Is(err, housekitchen.ErrNotAuthorized) {
		t.Fatalf("F7 回退：author 拒绝路径未包装 ErrNotAuthorized，实为: %v", err)
	}

	// 顺序验证：门限不足时先报 ErrThresholdNotMet，author 检查在其后（§5.1 第 6 步）。
	env2, _, _ := broadcast(t, set, keys, 1, negNow, func(b *pb.SignedBody) {
		b.Author = housekitchen.PBNodeID(node.ID)
	})
	expectErrIs(t, verifyErr(r, env2, registry.Session{Now: negNow}), housekitchen.ErrThresholdNotMet,
		"N7 仅有 1 签 + 带 author（门限先于 author 检查）")
}

// ---------- N8 节点消息由非 author 的密钥自签 ----------

func TestNegative_N8_NodeMessageNonAuthorSignature(t *testing.T) {
	keys := testAdminKeys(t, "neg")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	author, err := identity.NodeIdentityFromSeed(seed32("neg/node-author"))
	if err != nil {
		t.Fatalf("构造作者身份失败: %v", err)
	}
	impostor, err := identity.NodeIdentityFromSeed(seed32("neg/node-impostor"))
	if err != nil {
		t.Fatalf("构造冒充者身份失败: %v", err)
	}

	// 默认构造：author=A、body.author_pub=A.Pub，但自签用的是 B 的密钥。
	env, _ := nodeMsg(t, author, set, impostor, negNow)

	// (a) 会话对端就是 A → 找不到与 A 的 key_id 匹配的签名
	expectErrIs(t, verifyErr(r, env, registry.Session{AuthorNodeID: author.ID, AuthorPub: author.Pub, Now: negNow}),
		housekitchen.ErrInvalidSignature, "N8 自签来自 B，会话对端是 A")

	// (b) 会话对端是 B（中继转发场景）→ author_pub 优先，仍找不到 A 的自签
	expectErrIs(t, verifyErr(r, env, registry.Session{AuthorNodeID: impostor.ID, AuthorPub: impostor.Pub, Now: negNow}),
		housekitchen.ErrInvalidSignature, "N8 自签来自 B，会话对端是 B（author_pub 优先）")

	// (c) 对端自称就是作者 A，却给出 B 的公钥 → 交叉校验失败
	expectErrIs(t, verifyErr(r, env, registry.Session{AuthorNodeID: author.ID, AuthorPub: impostor.Pub, Now: negNow}),
		housekitchen.ErrPeerIDMismatch, "N8 对端自称 A 却给 B 的公钥")

	// (d) 不带 author_pub 的旧式消息 + 会话对端是 B → 兼容路径要求会话公钥必须等于作者
	envNoPub, _ := nodeMsgWith(t, author, set, impostor, negNow, func(b *pb.SignedBody) {
		b.AuthorPub = nil
	})
	expectErrIs(t, verifyErr(r, envNoPub, registry.Session{AuthorNodeID: impostor.ID, AuthorPub: impostor.Pub, Now: negNow}),
		housekitchen.ErrPeerIDMismatch, "N8 无 author_pub 且对端身份≠author")

	// (e) 无 author_pub 且没有对端公钥 → 无法校验
	expectErrIs(t, verifyErr(r, envNoPub, registry.Session{AuthorNodeID: author.ID, Now: negNow}),
		housekitchen.ErrNotAuthorized, "N8 无 author_pub 也无会话公钥")

	// (f) author_pub 与 author 不一致（签名前篡改）→ ErrPeerIDMismatch
	envBadPub, _ := nodeMsgWith(t, author, set, author, negNow, func(b *pb.SignedBody) {
		b.AuthorPub = impostor.Pub
	})
	expectErrIs(t, verifyErr(r, envBadPub, registry.Session{AuthorNodeID: author.ID, AuthorPub: author.Pub, Now: negNow}),
		housekitchen.ErrPeerIDMismatch, "N8 author_pub 与 author 不匹配")

	// (g) 对照组：author 用自己的密钥自签且 author_pub 正确 → 必须通过
	okEnv, _ := nodeMsg(t, author, set, author, negNow)
	if _, err := r.VerifyMessage(okEnv, registry.Session{AuthorNodeID: author.ID, AuthorPub: author.Pub, Now: negNow}); err != nil {
		t.Fatalf("对照组：author 自签的节点消息应被接受，却被拒: %v", err)
	}
	// (h) 对照组 2：中继转发（会话对端≠author，但 author_pub 与自签都正确）→ 必须通过
	if _, err := r.VerifyMessage(okEnv, registry.Session{AuthorNodeID: impostor.ID, AuthorPub: impostor.Pub, Now: negNow}); err != nil {
		t.Fatalf("对照组：中继转发合法节点消息应被接受，却被拒: %v", err)
	}
	t.Log("N8 OK：非 author 自签在 5 种会话上下文中均被拒；作者自签与中继转发均被接受")
}

// ---------- N9 轮换链 ----------

func TestNegative_N9_RotationChain(t *testing.T) {
	oldKeys := testAdminKeys(t, "neg-old")
	set1 := testSet(t, oldKeys, 1, nil)
	newKeys := testAdminKeys(t, "neg-new")

	// (a) 代数跳号：直接用 gen=3
	skip := testSet(t, newKeys, 3, set1)
	if err := registry.ValidateAdminSet(skip, set1, negNow); err == nil {
		t.Fatal("N9a 代数跳号必须被拒")
	} else {
		expectErrIs(t, err, housekitchen.ErrGenerationMismatch, "N9a 代数跳号 1→3")
	}
	r := newRegistry(t, set1)
	_ = registry.SignAdminSet(skip, set1, oldKeys[:2], 2, negNow)
	expectErrIs(t, r.Install(skip), housekitchen.ErrGenerationMismatch, "N9a Install 代数跳号")

	// (b) previous_set_hash 不匹配
	otherKeys := testAdminKeys(t, "neg-other")
	other := testSet(t, otherKeys, 1, nil)
	otherHash, _ := housekitchen.AdminSetHash(other)
	next := testSet(t, newKeys, 2, set1)
	if err := registry.SignAdminSet(next, set1, oldKeys[:2], 2, negNow); err != nil {
		t.Fatalf("N9b 签名轮换失败: %v", err)
	}
	next.PreviousSetHash = housekitchen.PBHash(otherHash)
	r2 := newRegistry(t, set1)
	expectErrIs(t, r2.Install(next), housekitchen.ErrGenerationMismatch, "N9b previous_set_hash 指向别的集合")

	// (c) 旧集合仅 1 把签名
	nextC := testSet(t, newKeys, 2, set1)
	if err := registry.SignAdminSet(nextC, set1, oldKeys[:1], 2, negNow); err != nil {
		t.Fatalf("N9c 签名失败: %v", err)
	}
	r3 := newRegistry(t, set1)
	expectErrIs(t, r3.Install(nextC), housekitchen.ErrThresholdNotMet, "N9c 旧集合仅 1 把签名")

	// (d) 自授权轮换：用新集合自己的密钥签名，而不是旧集合
	nextD := testSet(t, newKeys, 2, set1)
	if err := registry.SignAdminSet(nextD, set1, newKeys[:2], 2, negNow); err != nil {
		t.Fatalf("N9d 签名失败: %v", err)
	}
	r4 := newRegistry(t, set1)
	expectErrIs(t, r4.Install(nextD), housekitchen.ErrThresholdNotMet, "N9d 新集合自签授权自己")

	// 对照组：旧集合 2/3 正确签名 → 轮换成功
	nextOK := testSet(t, newKeys, 2, set1)
	if err := registry.SignAdminSet(nextOK, set1, oldKeys[:2], 2, negNow); err != nil {
		t.Fatalf("对照组签名失败: %v", err)
	}
	r5 := newRegistry(t, set1)
	if err := r5.Install(nextOK); err != nil {
		t.Fatalf("对照组：旧集合 2/3 签名的轮换应成功: %v", err)
	}
	if gen, _ := r5.Current(); gen != 2 {
		t.Fatalf("对照组当前代数应为 2，实为 %d", gen)
	}
	t.Log("N9 对照组 OK：旧集合 2/3 签名可完成轮换")
}

// ---------- N10 重放 ----------

func TestNegative_N10_Replay(t *testing.T) {
	keys := testAdminKeys(t, "neg")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	env, body, _ := broadcast(t, set, keys, 2, negNow, nil)
	sess := registry.Session{Now: negNow}

	// 注册表层无重放状态：同一信封两次都通过（Finding F9）。
	if _, err := r.VerifyMessage(env, sess); err != nil {
		t.Fatalf("第一次校验应通过: %v", err)
	}
	if _, err := r.VerifyMessage(env, sess); err != nil {
		t.Fatalf("第二次校验意外被拒（F9 状态可能已变化）: %v", err)
	}
	knownIssue(t, "F9", "info", "Registry.VerifyMessage 对重放无状态，同一信封可无限次通过；去重必须由 store.Seen 承担")

	// 集成层去重：Seen → Verify 顺序才构成有效防线。
	st := store.New(1024, time.Hour)
	msgID := housekitchen.GetHash(body.GetMsgId())
	if !st.Seen(msgID, negNow) {
		t.Fatal("首次 Seen 应为 true")
	}
	if st.Seen(msgID, negNow) {
		t.Fatal("二次 Seen 应为 false（去重失效）")
	}
	if err := st.Put(env, negNow); err != nil {
		t.Fatalf("首次 Put 应成功: %v", err)
	}
	if err := st.Put(env, negNow); !errors.Is(err, housekitchen.ErrDuplicate) {
		t.Fatalf("重复 Put 期望 ErrDuplicate，实为: %v", err)
	}
	t.Log("N10 OK：registry 无状态，store.Seen/Put 正确去重")
}

// ---------- 附加攻击面 ----------

// 签名列表不被 msg_id 覆盖（三层模型的设计意图）：篡改 signers 只会撞门限检查，
// 不会撞 ErrMsgIDMismatch。这里固化该顺序，防止未来有人把 signers 纳入 msg_id。
func TestNegative_SignatureTamperIsThresholdNotContentAddress(t *testing.T) {
	keys := testAdminKeys(t, "neg")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	env, body, _ := broadcast(t, set, keys, 2, negNow, nil)
	// 把第一个签名换成第三个密钥的签名（仍然合法，但不是凑数的两份）。
	third := fccrypto.SignBody(keys[2].Priv, mustCanonical(t, body), keys[2].KeyID, negNow)
	body.Signers[0] = third
	_, err := r.VerifyMessage(env, registry.Session{Now: negNow})
	// 仍然是 2 个有效互异签名 → 应被接受
	if err != nil {
		t.Fatalf("替换为另一把合法密钥的签名后应仍有 2 个有效签名: %v", err)
	}

	// 把两个签名都换成同一个第三把密钥的两个副本 → 门限不足
	body.Signers = []*pb.Signature{third, third}
	env2 := registry.WrapEnvelope(body, negNow)
	expectErrIs(t, verifyErr(r, env2, registry.Session{Now: negNow}), housekitchen.ErrThresholdNotMet,
		"附加：签名列表被替换为同一 key_id 的两份")

	// 加入一个不在 root_key_ids 的伪造签名：应被忽略，不破坏原有 2 个有效签名。
	env3, body3, _ := broadcast(t, set, keys, 2, negNow, nil)
	bogus := testAdminKeys(t, "neg-bogus")[0]
	body3.Signers = append(body3.Signers, fccrypto.SignBody(bogus.Priv, mustCanonical(t, body3), bogus.KeyID, negNow))
	env3 = registry.WrapEnvelope(body3, negNow)
	if _, err := r.VerifyMessage(env3, registry.Session{Now: negNow}); err != nil {
		t.Fatalf("额外的非 root 签名应被忽略而不是拒绝整条消息: %v", err)
	}
	t.Log("附加 OK：signers 不受 msg_id 保护；非 root 签名被忽略")
}

// signed_at 被清空/篡改时走 ErrThresholdNotMet，而不是 ErrMsgIDMismatch。
func TestNegative_SignedAtZeroRejected(t *testing.T) {
	keys := testAdminKeys(t, "neg")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	env, body, canonical := broadcast(t, set, keys, 2, negNow, nil)
	body.Signers[0].SignedAtUnixNanos = 0
	res, ok, err := fccrypto.MultisigVerify(canonical, body.Signers, identity.RootKeyIDs(set),
		identity.PubKeyResolver(set), 2, negNow, time.Duration(housekitchen.DefaultClockSkewNanos))
	if err != nil {
		t.Fatalf("MultisigVerify 错误: %v", err)
	}
	if ok || res.Valid != 1 {
		t.Fatalf("signed_at=0 应被拒且 Valid=1，实为 Valid=%d ok=%v", res.Valid, ok)
	}
	if len(res.Rejected) == 0 || !strings.Contains(res.Rejected[0].Reason, "signed_at") {
		t.Fatalf("期望拒绝原因为缺少 signed_at，实为 %+v", res.Rejected)
	}
	expectErrIs(t, verifyErr(r, env, registry.Session{Now: negNow}), housekitchen.ErrThresholdNotMet,
		"附加 signed_at=0")
}

// 节点消息缺少 author 字段 → ErrNotAuthorized。
func TestNegative_NodeMessageWithoutAuthor(t *testing.T) {
	keys := testAdminKeys(t, "neg")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	author, _ := identity.NodeIdentityFromSeed(seed32("neg/node-author"))
	env, _ := nodeMsg(t, author, set, author, negNow)
	env.Body.Author = nil
	// author 字段在 msg_id 覆盖范围内，清空后先撞 ErrMsgIDMismatch。
	expectErrIs(t, verifyErr(r, env, registry.Session{AuthorNodeID: author.ID, AuthorPub: author.Pub, Now: negNow}),
		housekitchen.ErrMsgIDMismatch, "附加 清空 author 会先撞 msg_id")

	// 要抵达节点分支的 "缺少 author" 检查，必须在签名前就不设 author。
	body, err := registry.NewNodeMessage(author, pb.MessageKind_MESSAGE_KIND_NODE_ANNOUNCE, vectorTopic,
		&pb.Payload{Payload: &pb.Payload_Liveness{Liveness: &pb.Liveness{IssuedAtUnixNanos: negNow.UnixNano()}}},
		set, time.Hour, negNow)
	if err != nil {
		t.Fatalf("NewNodeMessage 失败: %v", err)
	}
	// 必须在计算 canonical 之前清空 author，否则会先撞 ErrMsgIDMismatch。
	body.Author = nil
	canonical, err := registry.CanonicalForSigning(body)
	if err != nil {
		t.Fatalf("CanonicalForSigning 失败: %v", err)
	}
	if err := registry.FinalizeNodeBody(body, canonical, author, negNow); err != nil {
		t.Fatalf("FinalizeNodeBody 失败: %v", err)
	}
	envNoAuthor := registry.WrapEnvelope(body, negNow)
	expectErrIs(t, verifyErr(r, envNoAuthor, registry.Session{AuthorNodeID: author.ID, AuthorPub: author.Pub, Now: negNow}),
		housekitchen.ErrNotAuthorized, "附加 签名自洽但缺少 author")
}

func mustCanonical(t *testing.T, body *pb.SignedBody) []byte {
	t.Helper()
	c, err := housekitchen.CanonicalSignedBody(body)
	if err != nil {
		t.Fatalf("CanonicalSignedBody 失败: %v", err)
	}
	return c
}
