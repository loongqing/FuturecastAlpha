// 本文件把"外部实现者/攻击者"发现的每一条问题固化成可执行断言。
//
// 默认模式：断言**当前实际行为**并打印 `已知问题` 日志，保证 `go test` 全绿，
// 同时让问题在输出里显式可见。
// 严格模式：`FUTURECAST_STRICT=1 go test ./internal/conformance/` 会把每一条
// 仍可复现的问题变成测试失败，便于 Lead 一键确认待修清单。
package conformance_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
	"github.com/loongqing/FuturecastAlpha/internal/conformance"
	fccrypto "github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/registry"
)

// designSignInput 是 docs/DESIGN.md:121（§4.1）字面写出的 SIGN_INPUT 公式，
// 故意**不**包含 DomainSignInput 前缀。
func designSignInput(canonical []byte, keyID housekitchen.KeyID, at int64) [32]byte {
	h := sha256.New()
	h.Write(canonical)
	h.Write(keyID.Bytes())
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(at))
	h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// F3：DESIGN.md §4.1 的公式与实现不一致，按文档实现的外部签名者会不兼容。
func TestKnownIssue_F3_DesignFormulaOmitsDomainPrefix(t *testing.T) {
	v := build()
	canonical := mustHex(t, v.SignedBody.SignedBytesHex)
	s := v.SignedBody.Signers[0]
	keyID := mustKeyID(t, s.KeyIDHex)

	impl := housekitchen.SignInput(canonical, keyID, s.SignedAtUnixNanos)
	design := designSignInput(canonical, keyID, s.SignedAtUnixNanos)
	if impl.Bytes() == nil || design == impl {
		t.Fatal("测试前提失败：两种公式应产生不同摘要")
	}
	if string(design[:]) == string(impl.Bytes()) {
		t.Fatal("两种公式相同")
	}
	t.Logf("实现公式 SIGN_INPUT = %x", impl.Bytes())
	t.Logf("DESIGN:121 公式   = %x", design[:])

	// 按 DESIGN:121 签名，会被冻结实现拒绝。
	var seedHex string
	for _, k := range v.AdminSet.Keys {
		if k.KeyIDHex == s.KeyIDHex {
			seedHex = k.SeedHex
		}
	}
	if seedHex == "" {
		t.Fatal("向量缺少签名者种子")
	}
	priv := ed25519.NewKeyFromSeed(mustHex(t, seedHex))
	pub := priv.Public().(ed25519.PublicKey)
	badSig := ed25519.Sign(priv, design[:])
	err := fccrypto.VerifySignature(pub, canonical, &pb.Signature{
		KeyId:             housekitchen.PBKeyID(keyID),
		Signature:         badSig,
		SignedAtUnixNanos: s.SignedAtUnixNanos,
	})
	if err == nil {
		t.Fatal("按 DESIGN:121 公式签名竟被接受——F3 可能已被修复")
	}
	// 正确公式的签名必须通过。
	if err := fccrypto.VerifySignature(pub, canonical, &pb.Signature{
		KeyId:             housekitchen.PBKeyID(keyID),
		Signature:         mustHex(t, s.SignatureHex),
		SignedAtUnixNanos: s.SignedAtUnixNanos,
	}); err != nil {
		t.Fatalf("向量签名应通过: %v", err)
	}
	knownIssue(t, "F3", "high",
		"docs/DESIGN.md:121（§4.1）的 SIGN_INPUT 公式缺少 \"futurecast/v1/signinput\\x00\" 前缀，与 DESIGN.md:91 及实现冲突；按 §4.1 实现的签名被拒绝: "+err.Error())
}

// F4 已由 Lead 修复：门限一律取自**本地** AdminSet，签名者自填的 policy 只能
// "与本地一致或被拒"。这里做回归守卫：自降门限必须被拒。
func TestResolvedFinding_F4_SelfDeclaredThresholdDowngrade(t *testing.T) {
	keys := testAdminKeys(t, "find")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	env, _, _ := broadcast(t, set, keys, 1, negNow, func(b *pb.SignedBody) {
		p := proto.Clone(set.GetPolicy()).(*pb.SigningPolicy)
		p.Threshold = 1 // 单把密钥自降门限
		b.Policy = p
	})
	_, err := r.VerifyMessage(env, registry.Session{Now: negNow})
	if err == nil {
		t.Fatal("F4 回退：1 把密钥自降 threshold=1 的广播被接受了")
	}
	if !errors.Is(err, housekitchen.ErrThresholdNotMet) {
		t.Fatalf("期望 ErrThresholdNotMet，实为: %v", err)
	}
}

// F6 已修复：协议版本必须在 [MinProtoVersion, ProtoVersion] 内。
func TestResolvedFinding_F6_ProtocolVersionEnforced(t *testing.T) {
	keys := testAdminKeys(t, "find")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	env, _, _ := broadcast(t, set, keys, 2, negNow, func(b *pb.SignedBody) {
		b.ProtoVersion = 999
	})
	_, err := r.VerifyMessage(env, registry.Session{Now: negNow})
	if err == nil {
		t.Fatal("F6 回退：proto_version=999 被接受了")
	}
	if !errors.Is(err, housekitchen.ErrProtocolVersion) {
		t.Fatalf("期望 ErrProtocolVersion，实为: %v", err)
	}
}

// F8 已修复：同代不同内容必须报错（之前是静默 no-op，会把 equivocation 吞掉）。
func TestResolvedFinding_F8_SameGenerationEquivocation(t *testing.T) {
	oldKeys := testAdminKeys(t, "find-old")
	set1 := testSet(t, oldKeys, 1, nil)
	r := newRegistry(t, set1)

	keysA := testAdminKeys(t, "find-a")
	nextA := testSet(t, keysA, 2, set1)
	if err := registry.SignAdminSet(nextA, set1, oldKeys[:2], 2, negNow); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if err := r.Install(nextA); err != nil {
		t.Fatalf("第一个第 2 代集合应安装成功: %v", err)
	}

	keysB := testAdminKeys(t, "find-b")
	nextB := testSet(t, keysB, 2, set1)
	if err := registry.SignAdminSet(nextB, set1, oldKeys[:2], 2, negNow); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	hashA, _ := housekitchen.AdminSetHash(nextA)
	hashB, _ := housekitchen.AdminSetHash(nextB)
	if hashA == hashB {
		t.Fatal("测试前提失败：两个第 2 代集合应不同")
	}
	err := r.Install(nextB)
	if err == nil {
		t.Fatal("F8 回退：同代但内容不同的 AdminSet 被静默接受")
	}
	if !errors.Is(err, housekitchen.ErrGenerationMismatch) {
		t.Fatalf("期望 ErrGenerationMismatch，实为: %v", err)
	}
	// 幂等性仍然保留：同代同内容重复安装必须是 no-op。
	if err := r.Install(nextA); err != nil {
		t.Fatalf("同代同内容重复安装应为幂等 no-op，实为: %v", err)
	}
	_, cur := r.Current()
	curHash, _ := housekitchen.AdminSetHash(cur)
	if curHash != hashA {
		t.Fatal("当前集合不应被冲突集合替换")
	}
}

// F10 已修复：时间戳必须有界，不再把 expires_at==0 当作"永不过期"。
func TestResolvedFinding_F10_ZeroExpiryRejected(t *testing.T) {
	keys := testAdminKeys(t, "find")
	set := testSet(t, keys, 1, nil)
	r := newRegistry(t, set)

	later := negNow.Add(10 * 365 * 24 * time.Hour)
	env, _, _ := broadcast(t, set, keys, 2, later, func(b *pb.SignedBody) {
		b.CreatedAtUnixNanos = 0
		b.ExpiresAtUnixNanos = 0
	})
	_, err := r.VerifyMessage(env, registry.Session{Now: later})
	if err == nil {
		t.Fatal("F10 回退：created_at=0/expires_at=0 的消息被接受了")
	}

	// 另一个方向：expires_at 必须严格晚于 created_at。
	env2, _, _ := broadcast(t, set, keys, 2, negNow, func(b *pb.SignedBody) {
		b.ExpiresAtUnixNanos = b.CreatedAtUnixNanos
	})
	if _, err := r.VerifyMessage(env2, registry.Session{Now: negNow}); err == nil {
		t.Fatal("F10 回退：expires_at == created_at 被接受了")
	}
}

// F11 已由 Lead 修复：签名的 domain 参数被彻底移除，
// 域前缀只由 housekitchen.CanonicalXxx 施加一次，调用方无法重复施加。
// 这里做正向守卫，防止"忽略 domain 参数"这类陷阱 API 回退。
func TestResolvedFinding_F11_NoDomainParameter(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(seed32("find/domain-probe"))
	pub := priv.Public().(ed25519.PublicKey)
	msg := []byte("futurecast/conformance/domain-probe")

	sig := fccrypto.SignCanonical(priv, msg)
	if string(sig) != string(ed25519.Sign(priv, msg)) {
		t.Fatal("SignCanonical 应对传入字节直接签名")
	}
	if !fccrypto.VerifyCanonical(pub, msg, sig) {
		t.Fatal("VerifyCanonical 应接受自己签出的签名")
	}
	if fccrypto.VerifyCanonical(pub, []byte("other"), sig) {
		t.Fatal("VerifyCanonical 不应接受内容不同的输入")
	}
}

// F1/F2/F5 已在本轮被 Lead 修复，这里做正向守卫，防止回退。
func TestResolvedFindingsGuard(t *testing.T) {
	// F1：DomainSealedPayload 必须存在且被 CanonicalSealedPayload 使用。
	if housekitchen.DomainSealedPayload != "futurecast/v1/sealedpayload\x00" {
		t.Fatalf("F1 回退：DomainSealedPayload=%q", housekitchen.DomainSealedPayload)
	}
	sp := &pb.SealedPayload{Epoch: 1}
	canonical, err := housekitchen.CanonicalSealedPayload(sp)
	if err != nil {
		t.Fatalf("CanonicalSealedPayload 失败: %v", err)
	}
	if string(canonical[:len(housekitchen.DomainSealedPayload)]) != housekitchen.DomainSealedPayload {
		t.Fatal("F1 回退：封存规范化未使用 DomainSealedPayload")
	}
	// F5：AdminSet 与 SignedBody 必须使用不同域。
	if housekitchen.DomainAdminSet == housekitchen.DomainSignedBody {
		t.Fatal("F5 回退：AdminSet 与 SignedBody 共用域前缀")
	}
	// F2：节点自证必须是单前缀（签名输入 == canonical）。
	v := build()
	if v.NodeAnnounce.SignDigestInputHex != v.NodeAnnounce.SignedBytesHex {
		t.Fatal("F2 回退：节点自证出现额外域前缀")
	}
	t.Log("F1/F2/F5 正向守卫 OK")
}

// TestFindingsWellFormed 保证 findings 元数据自洽，并打印摘要。
func TestFindingsWellFormed(t *testing.T) {
	v := build()
	if len(v.Findings) == 0 {
		t.Fatal("findings 为空")
	}
	seen := map[string]bool{}
	open := 0
	for _, f := range v.Findings {
		if f.ID == "" || f.Severity == "" || f.Summary == "" || f.Contract == "" || f.Evidence == "" || f.Status == "" {
			t.Fatalf("finding %s 字段不完整: %+v", f.ID, f)
		}
		if seen[f.ID] {
			t.Fatalf("finding %s 重复", f.ID)
		}
		seen[f.ID] = true
		if len(f.Status) >= 4 && f.Status[:4] == "open" {
			open++
		}
		t.Logf("%-4s [%-8s] %s", f.ID, f.Severity, f.Summary)
	}
	t.Logf("共 %d 条 finding，其中 open %d 条；严格模式：FUTURECAST_STRICT=1 go test ./internal/conformance/", len(v.Findings), open)
	_ = conformance.Findings
}
