package registry_test

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
	"github.com/loongqing/FuturecastAlpha/internal/registry"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

const topic = "alerts"

// newTestKeyring 生成 3 把管理员密钥与创世 AdminSet。
func newTestKeyring(t *testing.T) (*identity.Keyring, *pb.AdminSet) {
	t.Helper()
	kr := identity.NewKeyring()
	for _, lbl := range []string{"alice", "bob", "carol"} {
		k, err := identity.NewAdminKey(lbl, pb.AdminRole_ADMIN_ROLE_ROOT)
		if err != nil {
			t.Fatalf("生成管理员密钥失败: %v", err)
		}
		kr.Add(k)
	}
	set, err := kr.BuildAdminSet(1, 2, 3, "genesis")
	if err != nil {
		t.Fatalf("构建创世 AdminSet 失败: %v", err)
	}
	return kr, set
}

func newTestRegistry(t *testing.T, set *pb.AdminSet) *registry.Registry {
	t.Helper()
	r, err := registry.New(set, registry.Options{
		Now: func() time.Time { return time.Unix(1700000000, 0) },
	})
	if err != nil {
		t.Fatalf("创建 Registry 失败: %v", err)
	}
	return r
}

// signBroadcast 走完整的签发流程，返回可校验的信封。
func signBroadcast(t *testing.T, r *registry.Registry, kr *identity.Keyring, set *pb.AdminSet, n int) *pb.Envelope {
	t.Helper()
	now := time.Unix(1700000000, 0)
	body, err := registry.NewAdminBroadcast(set, topic, "系统进入静默模式", "text/plain", time.Hour, now)
	if err != nil {
		t.Fatalf("组装广播失败: %v", err)
	}
	canonical, err := registry.CanonicalForSigning(body)
	if err != nil {
		t.Fatalf("规范化失败: %v", err)
	}
	keys := make([]*identity.AdminKey, 0, n)
	for _, id := range set.GetPolicy().GetRootKeyIds() {
		if len(keys) == n {
			break
		}
		if k, ok := kr.Get(housekitchen.GetKeyID(id)); ok {
			keys = append(keys, k)
		}
	}
	if err := registry.FinalizeAdminBody(body, canonical, keys, n, now); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	return registry.WrapEnvelope(body, now)
}

func TestValidBroadcastAcceptedWithFullThreshold(t *testing.T) {
	kr, set := newTestKeyring(t)
	r := newTestRegistry(t, set)
	env := signBroadcast(t, r, kr, set, 2)

	v, err := r.VerifyMessage(env, registry.Session{Now: time.Unix(1700000000, 0)})
	if err != nil {
		t.Fatalf("2/3 门限广播应被接受，却被拒: %v", err)
	}
	if !v.AdminAuthorized {
		t.Fatal("应标记为管理员授权")
	}
	if len(v.Signers) != 2 {
		t.Fatalf("应有 2 个有效签名者，实为 %d", len(v.Signers))
	}
}

// 负例 1：只有 1 个签名 → 门限不足，必须拒
func TestRejectBelowThreshold(t *testing.T) {
	kr, set := newTestKeyring(t)
	r := newTestRegistry(t, set)
	env := signBroadcast(t, r, kr, set, 1)

	_, err := r.VerifyMessage(env, registry.Session{Now: time.Unix(1700000000, 0)})
	if err == nil {
		t.Fatal("1/3 签名必须被拒")
	}
	if !isErr(err, housekitchen.ErrThresholdNotMet) {
		t.Fatalf("期望 ErrThresholdNotMet，实为: %v", err)
	}
}

// 负例 2：正文被改 1 字节 → msg_id 不符，必须拒
func TestRejectTamperedBody(t *testing.T) {
	kr, set := newTestKeyring(t)
	r := newTestRegistry(t, set)
	env := signBroadcast(t, r, kr, set, 2)

	env.Body.Payload.GetText().Body = "系统进入静默模式 " // 多一个空格
	_, err := r.VerifyMessage(env, registry.Session{Now: time.Unix(1700000000, 0)})
	if err == nil {
		t.Fatal("篡改正文必须被拒")
	}
	if !isErr(err, housekitchen.ErrMsgIDMismatch) {
		t.Fatalf("期望 ErrMsgIDMismatch，实为: %v", err)
	}
}

// 负例 3：msg_id 被改成别的值 → 必须拒
func TestRejectForgedMsgID(t *testing.T) {
	kr, set := newTestKeyring(t)
	r := newTestRegistry(t, set)
	env := signBroadcast(t, r, kr, set, 2)

	env.MsgId = housekitchen.PBHash(housekitchen.Sum256([]byte("forged")))
	_, err := r.VerifyMessage(env, registry.Session{Now: time.Unix(1700000000, 0)})
	if err == nil {
		t.Fatal("伪造 msg_id 必须被拒")
	}
}

// 负例 4：同一把密钥的签名复制两份凑门限 → 只计 1 个，必须拒
func TestRejectDuplicatedSigner(t *testing.T) {
	kr, set := newTestKeyring(t)
	r := newTestRegistry(t, set)
	env := signBroadcast(t, r, kr, set, 1)

	one := env.Body.Signers[0]
	env.Body.Signers = []*pb.Signature{one, one}
	_, err := r.VerifyMessage(env, registry.Session{Now: time.Unix(1700000000, 0)})
	if err == nil {
		t.Fatal("重复 key_id 凑门限必须被拒")
	}
	if !isErr(err, housekitchen.ErrThresholdNotMet) {
		t.Fatalf("期望 ErrThresholdNotMet，实为: %v", err)
	}
}

// 负例 5：声明一个本地不认识的代数 → 必须拒
//
// 注意：这里不能简单地"签完再改 AdminSetGeneration"，因为世代字段在签名与
// msg_id 的覆盖范围内，改动会先触发 ErrMsgIDMismatch。这正是设计意图：
// 篡改检测先于语义检查。因此要构造一个签名有效但代数不可接受的合法消息。
func TestRejectUnknownGeneration(t *testing.T) {
	kr, set := newTestKeyring(t)
	r := newTestRegistry(t, set)

	now := time.Unix(1700000000, 0)
	// 用第 1 代的密钥，却声明第 7 代（本地未知），签名本身是有效的。
	fake := proto.Clone(set).(*pb.AdminSet)
	fake.Generation = 7

	body, err := registry.NewAdminBroadcast(fake, topic, "伪造世代", "text/plain", time.Hour, now)
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	canonical, err := registry.CanonicalForSigning(body)
	if err != nil {
		t.Fatalf("规范化失败: %v", err)
	}
	if err := registry.FinalizeAdminBody(body, canonical, keysInOrder(t, kr, set)[:2], 2, now); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	env := registry.WrapEnvelope(body, now)

	_, err = r.VerifyMessage(env, registry.Session{Now: now})
	if err == nil {
		t.Fatal("未知代数必须被拒")
	}
	if !isErr(err, housekitchen.ErrGenerationMismatch) {
		t.Fatalf("期望 ErrGenerationMismatch，实为: %v", err)
	}
}

// 负例 6：消息绑定的 AdminSet 摘要与本地该代集合不符 → 必须拒
//
// 构造方式：注册表里第 1 代是 setA，但消息由 setB（不同密钥集）以第 1 代签名。
// 消息自身的 msg_id 与签名都合法，唯独 signer_set_hash 指向了另一个集合。
func TestRejectSignerSetMismatch(t *testing.T) {
	_, setA := newTestKeyring(t)
	r := newTestRegistry(t, setA)

	krB, setB := newTestKeyring(t)
	now := time.Unix(1700000000, 0)
	body, err := registry.NewAdminBroadcast(setB, topic, "来自另一个集合的广播", "text/plain", time.Hour, now)
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	canonical, err := registry.CanonicalForSigning(body)
	if err != nil {
		t.Fatalf("规范化失败: %v", err)
	}
	if err := registry.FinalizeAdminBody(body, canonical, keysInOrder(t, krB, setB)[:2], 2, now); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	env := registry.WrapEnvelope(body, now)

	hashA, _ := housekitchen.AdminSetHash(setA)
	hashB, _ := housekitchen.AdminSetHash(setB)
	if hashA == hashB {
		t.Fatal("测试前提失败：两个集合摘要不应相同")
	}

	_, err = r.VerifyMessage(env, registry.Session{Now: now})
	if err == nil {
		t.Fatal("signer_set_hash 与本地集合不符必须被拒")
	}
	if !isErr(err, housekitchen.ErrSignerSetMismatch) {
		t.Fatalf("期望 ErrSignerSetMismatch，实为: %v", err)
	}
}

// 负例 7：过期消息 → 必须拒
func TestRejectExpired(t *testing.T) {
	kr, set := newTestKeyring(t)
	r := newTestRegistry(t, set)
	env := signBroadcast(t, r, kr, set, 2)

	_, err := r.VerifyMessage(env, registry.Session{Now: time.Unix(1700000000, 0).Add(2 * time.Hour)})
	if err == nil {
		t.Fatal("过期消息必须被拒")
	}
	if !isErr(err, housekitchen.ErrExpired) {
		t.Fatalf("期望 ErrExpired，实为: %v", err)
	}
}

// 轮换：由旧集合 2/3 签名的新集合可被安装；仅 1 把签名则不行
func TestAdminSetRotation(t *testing.T) {
	kr, set := newTestKeyring(t)
	r := newTestRegistry(t, set)

	oldKeys := keysInOrder(t, kr, set)
	next, err := kr.BuildAdminSet(2, 2, 3, "rotated")
	if err != nil {
		t.Fatalf("构建第 2 代失败: %v", err)
	}
	if err := registry.SignAdminSet(next, set, oldKeys[:1], 2, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("签名轮换失败: %v", err)
	}
	if err := r.Install(next); err == nil {
		t.Fatal("只有 1 把旧密钥签名的轮换必须失败")
	}

	if err := registry.SignAdminSet(next, set, oldKeys[:2], 2, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("签名轮换失败: %v", err)
	}
	if err := r.Install(next); err != nil {
		t.Fatalf("2/3 旧密钥签名的轮换应成功: %v", err)
	}
	gen, cur := r.Current()
	if gen != 2 || cur.GetGeneration() != 2 {
		t.Fatalf("当前代数应为 2，实为 %d", gen)
	}
}

// 节点消息必须由作者自签
func TestNodeMessageRequiresAuthorSignature(t *testing.T) {
	_, set := newTestKeyring(t)
	r := newTestRegistry(t, set)
	now := time.Unix(1700000000, 0)

	node, err := identity.NewNodeIdentity()
	if err != nil {
		t.Fatalf("生成节点身份失败: %v", err)
	}
	body, err := registry.NewNodeMessage(node, pb.MessageKind_MESSAGE_KIND_NODE_ANNOUNCE, topic,
		&pb.Payload{Payload: &pb.Payload_Liveness{Liveness: &pb.Liveness{IssuedAtUnixNanos: now.UnixNano()}}},
		set, time.Hour, now)
	if err != nil {
		t.Fatalf("组装节点消息失败: %v", err)
	}
	canonical, err := registry.CanonicalForSigning(body)
	if err != nil {
		t.Fatalf("规范化失败: %v", err)
	}
	if err := registry.FinalizeNodeBody(body, canonical, node, now); err != nil {
		t.Fatalf("节点自签失败: %v", err)
	}
	env := registry.WrapEnvelope(body, now)

	if _, err := r.VerifyMessage(env, registry.Session{
		AuthorNodeID: node.ID, AuthorPub: node.Pub, Now: now,
	}); err != nil {
		t.Fatalf("合法节点消息应被接受: %v", err)
	}

	// 冒充手段一：把 author_pub 换成别人 —— 但 author 字段仍指向原节点，
	// 哈希对不上，必须被拒。
	other, _ := identity.NewNodeIdentity()
	forged := proto.Clone(env).(*pb.Envelope)
	forged.Body.AuthorPub = other.Pub
	if _, err := r.VerifyMessage(forged, registry.Session{Now: now}); err == nil {
		t.Fatal("author_pub 与 author 不符必须被拒")
	}

	// 冒充手段二：连 author 一起换成别人，但签名是原作者的私钥签的 —— 必须被拒。
	forged2 := proto.Clone(env).(*pb.Envelope)
	forged2.Body.Author = housekitchen.PBNodeID(other.ID)
	forged2.Body.AuthorPub = other.Pub
	if _, err := r.VerifyMessage(forged2, registry.Session{Now: now}); err == nil {
		t.Fatal("用他人身份声明的节点消息必须被拒")
	}

	// 没有自签
	env.Body.Signers = nil
	if _, err := r.VerifyMessage(env, registry.Session{
		AuthorNodeID: node.ID, AuthorPub: node.Pub, Now: now,
	}); err == nil {
		t.Fatal("缺少作者自签的节点消息必须被拒")
	}
}

func keysInOrder(t *testing.T, kr *identity.Keyring, set *pb.AdminSet) []*identity.AdminKey {
	t.Helper()
	out := make([]*identity.AdminKey, 0, len(set.GetKeys()))
	for _, id := range set.GetPolicy().GetRootKeyIds() {
		k, ok := kr.Get(housekitchen.GetKeyID(id))
		if !ok {
			t.Fatalf("密钥环缺少 %s", housekitchen.GetKeyID(id).Short())
		}
		out = append(out, k)
	}
	return out
}

func isErr(err, target error) bool { return errors.Is(err, target) }
