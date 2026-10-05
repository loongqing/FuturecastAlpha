package conformance_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
	"github.com/loongqing/FuturecastAlpha/internal/conformance"
	fccrypto "github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
	"github.com/loongqing/FuturecastAlpha/internal/registry"
	"github.com/loongqing/FuturecastAlpha/internal/sealed"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("十六进制解析失败 %q: %v", s, err)
	}
	return b
}

func mustHash(t *testing.T, s string) housekitchen.Hash {
	t.Helper()
	h, err := housekitchen.HashFromHex(s)
	if err != nil {
		t.Fatalf("Hash 解析失败 %q: %v", s, err)
	}
	return h
}

func build() *conformance.Vectors {
	v, err := conformance.Build()
	if err != nil {
		panic(err)
	}
	return v
}

// TestVectorsDeterministic 保证两次 Build 逐字节一致（跨语言基准的前提）。
func TestVectorsDeterministic(t *testing.T) {
	var a, b bytes.Buffer
	if err := conformance.WriteJSON(&a, build()); err != nil {
		t.Fatalf("WriteJSON #1 失败: %v", err)
	}
	if err := conformance.WriteJSON(&b, build()); err != nil {
		t.Fatalf("WriteJSON #2 失败: %v", err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("两次 Build/WriteJSON 输出不一致，向量不确定")
	}
	t.Logf("向量 JSON 确定性 OK：%d 字节", a.Len())

	var round conformance.Vectors
	if err := json.Unmarshal(a.Bytes(), &round); err != nil {
		t.Fatalf("vectors.json 无法回读: %v", err)
	}
	if round.SignedBody.MsgIDHex != build().SignedBody.MsgIDHex {
		t.Fatal("回读后 msg_id 不一致")
	}
	t.Logf("msg_id=%s", round.SignedBody.MsgIDHex)
}

// TestFrozenDomainGuard 锁定域前缀的字节值。冻结接口若再次演进，本测试会立刻失败，
// 提醒复核向量与 PROTOCOL.md。
func TestFrozenDomainGuard(t *testing.T) {
	want := map[string]string{
		housekitchen.DomainSignedBody:    "667574757265636173742f76312f7369676e6564626f647900",
		housekitchen.DomainAdminSet:      "667574757265636173742f76312f61646d696e73657400",
		housekitchen.DomainSealedPayload: "667574757265636173742f76312f7365616c65647061796c6f616400",
		housekitchen.DomainMsgID:         "667574757265636173742f76312f6d7367696400",
		housekitchen.DomainSignInput:     "667574757265636173742f76312f7369676e696e70757400",
		housekitchen.DomainNodeAnnounce:  "667574757265636173742f76312f6e6f6465616e6e6f756e636500",
		housekitchen.DomainRelayTag:      "667574757265636173742f76312f72656c617974616700",
		housekitchen.DomainInbox:         "66632f76312f696e626f78",
		housekitchen.DomainTopicKey:      "66632f76312f746f7069636b6579",
	}
	for domain, wantHex := range want {
		got := hex.EncodeToString([]byte(domain))
		if got != wantHex {
			t.Fatalf("域前缀字节变了：%q -> %s（期望 %s）。冻结接口演进后必须复核 vectors 与 PROTOCOL.md。", domain, got, wantHex)
		}
	}
	t.Log("冻结域前缀字节守卫 OK")
}

// TestInterop_AdminSetEncodedWithoutGoProtobuf 用手写 proto3 编码器复算 AdminSet，
// 证明规范化字节不依赖 Go protobuf 运行时。
func TestInterop_AdminSetEncodedWithoutGoProtobuf(t *testing.T) {
	v := build()
	pv := v.AdminSet.Policy

	policy := &pb.SigningPolicy{
		Threshold:               pv.Threshold,
		Total:                   pv.Total,
		Scheme:                  pb.SigningScheme(pv.Scheme),
		ClockSkewToleranceNanos: pv.ClockSkewToleranceNanos,
	}
	set := &pb.AdminSet{
		Generation:         v.AdminSet.Generation,
		Policy:             policy,
		CreatedAtUnixNanos: v.AdminSet.CreatedAtUnixNanos,
	}
	if len(v.AdminSet.Keys) != len(v.AdminSet.Policy.RootKeyIDsHex) {
		t.Fatal("keys 与 root_key_ids 数量不一致")
	}
	for i, k := range v.AdminSet.Keys {
		pub := mustHex(t, k.PubHex)
		derived := housekitchen.KeyIDFromPub(pub)
		if hex.EncodeToString(derived.Bytes()) != k.KeyIDHex {
			t.Fatalf("KEY_ID 派生不符：pub=%s 派生 %s，向量声明 %s", k.PubHex, derived, k.KeyIDHex)
		}
		set.Keys = append(set.Keys, &pb.AdminKey{
			KeyId:     housekitchen.PBKeyID(derived),
			PublicKey: &pb.PubKey{Ed25519: pub},
			Label:     k.Label,
			Role:      pb.AdminRole(k.Role),
		})
		policy.RootKeyIds = append(policy.RootKeyIds, housekitchen.PBKeyID(derived))
		if hex.EncodeToString(derived.Bytes()) != v.AdminSet.Policy.RootKeyIDsHex[i] {
			t.Fatalf("root_key_ids[%d] 顺序不符", i)
		}
	}

	manual := encAdminSet(set)
	requireEqualString(t, "手写编码 AdminSet vs 向量 proto_hex", v.AdminSet.ProtoHex, hex.EncodeToString(manual))

	canonical, err := housekitchen.CanonicalAdminSet(set)
	if err != nil {
		t.Fatalf("CanonicalAdminSet 失败: %v", err)
	}
	requireEqualString(t, "CanonicalAdminSet vs 向量 signed_bytes", v.AdminSet.SignedBytesHex, hex.EncodeToString(canonical))
	if !bytes.HasPrefix(canonical, []byte(v.AdminSet.DomainUsedASCII)) {
		t.Fatal("AdminSet 规范化字节未以 DomainAdminSet 开头")
	}
	hash, err := housekitchen.AdminSetHash(set)
	if err != nil {
		t.Fatalf("AdminSetHash 失败: %v", err)
	}
	requireEqualString(t, "AdminSetHash", v.AdminSet.AdminSetHashHex, hex.EncodeToString(hash.Bytes()))
	t.Logf("AdminSet 规范化互通 OK：domain=%q hash=%s", v.AdminSet.DomainUsedASCII, hash)
}

// TestInterop_SignedBodyMsgIDAndSignInput 用手写编码器 + 独立 SHA-256 复算
// SIGNED_BYTES、MSG_ID、SIGN_INPUT，并用 stdlib ed25519 直接验签。
func TestInterop_SignedBodyMsgIDAndSignInput(t *testing.T) {
	v := build()
	sb := v.SignedBody
	body := reconstructSignedBody(t, v, false)

	manual := encSignedBody(body)
	requireEqualString(t, "手写编码 SignedBody vs 向量 proto_hex", sb.ProtoHex, hex.EncodeToString(manual))

	canonical, err := housekitchen.CanonicalSignedBody(body)
	if err != nil {
		t.Fatalf("CanonicalSignedBody 失败: %v", err)
	}
	requireEqualString(t, "CanonicalSignedBody vs 向量 signed_bytes", sb.SignedBytesHex, hex.EncodeToString(canonical))

	msgInput := append(append([]byte{}, []byte(housekitchen.DomainMsgID)...), canonical...)
	msgID := sha256.Sum256(msgInput)
	requireEqualString(t, "独立 MSG_ID vs 向量", sb.MsgIDHex, hex.EncodeToString(msgID[:]))
	goMsgID, err := housekitchen.MsgID(body)
	if err != nil {
		t.Fatalf("MsgID 失败: %v", err)
	}
	requireEqualString(t, "housekitchen.MsgID vs 向量", sb.MsgIDHex, hex.EncodeToString(goMsgID.Bytes()))

	pubOf := map[string][]byte{}
	for _, k := range v.AdminSet.Keys {
		pubOf[k.KeyIDHex] = mustHex(t, k.PubHex)
	}
	if len(sb.Signers) != 2 {
		t.Fatalf("向量应有 2 个签名者，实为 %d", len(sb.Signers))
	}
	for i, s := range sb.Signers {
		keyID := mustKeyID(t, s.KeyIDHex)
		input := independentSignInput(canonical, keyID, s.SignedAtUnixNanos)
		requireEqualString(t, "独立 SIGN_INPUT vs 向量", s.SignInputHex, hex.EncodeToString(input[:]))
		goInput := housekitchen.SignInput(canonical, keyID, s.SignedAtUnixNanos)
		requireEqual(t, "housekitchen.SignInput vs 独立实现", input[:], goInput.Bytes())

		sig := mustHex(t, s.SignatureHex)
		pub := ed25519.PublicKey(pubOf[s.KeyIDHex])
		if len(pub) != ed25519.PublicKeySize {
			t.Fatalf("signers[%d] 找不到对应公钥", i)
		}
		if !ed25519.Verify(pub, input[:], sig) {
			t.Fatalf("signers[%d] stdlib ed25519.Verify 失败（SIGN_INPUT 公式不符）", i)
		}
		if err := fccrypto.VerifySignature(pub, canonical, &pb.Signature{
			KeyId:             housekitchen.PBKeyID(keyID),
			Signature:         sig,
			SignedAtUnixNanos: s.SignedAtUnixNanos,
		}); err != nil {
			t.Fatalf("signers[%d] crypto.VerifySignature 失败: %v", i, err)
		}
		t.Logf("signers[%d] key_id=%s sign_input=%s OK", i, s.KeyIDHex, s.SignInputHex)
	}

	full := reconstructSignedBody(t, v, true)
	env := registry.WrapEnvelope(full, conformance.VectorTime)
	requireEqualString(t, "Envelope msg_id", sb.EnvelopeMsgIDHex, hex.EncodeToString(housekitchen.GetHash(env.GetMsgId()).Bytes()))

	reg, err := registry.New(setFromVector(t, v), registry.Options{Now: func() time.Time { return conformance.VectorTime }})
	if err != nil {
		t.Fatalf("registry.New 失败: %v", err)
	}
	res, err := reg.VerifyMessage(env, registry.Session{Now: conformance.VectorTime})
	if err != nil {
		t.Fatalf("golden 消息应被接受，却被拒: %v", err)
	}
	if !res.AdminAuthorized || len(res.Signers) != 2 {
		t.Fatalf("golden 消息门限状态异常: %+v", res)
	}
	t.Logf("端到端 OK：仅用 JSON 输入重建的信封通过 2-of-3 校验（signers=%d）", len(res.Signers))
}

func setFromVector(t *testing.T, v *conformance.Vectors) *pb.AdminSet {
	t.Helper()
	pv := v.AdminSet.Policy
	policy := &pb.SigningPolicy{
		Threshold:               pv.Threshold,
		Total:                   pv.Total,
		Scheme:                  pb.SigningScheme(pv.Scheme),
		ClockSkewToleranceNanos: pv.ClockSkewToleranceNanos,
	}
	for _, idHex := range pv.RootKeyIDsHex {
		policy.RootKeyIds = append(policy.RootKeyIds, housekitchen.PBKeyID(mustKeyID(t, idHex)))
	}
	set := &pb.AdminSet{
		Generation:         v.AdminSet.Generation,
		Policy:             policy,
		CreatedAtUnixNanos: v.AdminSet.CreatedAtUnixNanos,
	}
	for _, k := range v.AdminSet.Keys {
		set.Keys = append(set.Keys, &pb.AdminKey{
			KeyId:     housekitchen.PBKeyID(mustKeyID(t, k.KeyIDHex)),
			PublicKey: &pb.PubKey{Ed25519: mustHex(t, k.PubHex)},
			Label:     k.Label,
			Role:      pb.AdminRole(k.Role),
		})
	}
	return set
}

// TestInterop_NodeAnnounceSingleDomain 证明节点自证当前是"单域前缀"，
// 并反证历史上出现过的双前缀写法会被拒绝。
func TestInterop_NodeAnnounceSingleDomain(t *testing.T) {
	v := build()
	na := v.NodeAnnounce

	announce := &pb.NodeAnnounce{
		NodeId:            housekitchen.PBNodeID(mustNodeID(t, na.NodeIDHex)),
		Addrs:             na.Addrs,
		AddressPublic:     na.AddressPublic,
		RendezvousHint:    housekitchen.PBHash(mustHash(t, na.RendezvousHintHex)),
		Seq:               na.Seq,
		IssuedAtUnixNanos: na.IssuedAtUnixNanos,
	}
	manual := encNodeAnnounce(announce)
	requireEqualString(t, "手写编码 NodeAnnounce vs 向量 proto_hex", na.ProtoHex, hex.EncodeToString(manual))

	canonical, err := housekitchen.CanonicalNodeAnnounce(announce)
	if err != nil {
		t.Fatalf("CanonicalNodeAnnounce 失败: %v", err)
	}
	requireEqualString(t, "CanonicalNodeAnnounce vs 向量 signed_bytes", na.SignedBytesHex, hex.EncodeToString(canonical))
	requireEqualString(t, "签名输入即 canonical（单前缀）", na.SignedBytesHex, na.SignDigestInputHex)
	if na.DomainPrefixCount != 1 {
		t.Fatalf("向量声明域前缀次数应为 1，实为 %d", na.DomainPrefixCount)
	}

	digest := sha256.Sum256(canonical)
	requireEqualString(t, "摘要 vs 向量", na.SignDigestHex, hex.EncodeToString(digest[:]))

	nodePub := ed25519.PublicKey(mustHex(t, na.NodePubHex))
	if hex.EncodeToString(housekitchen.NodeIDFromPub(nodePub).Bytes()) != na.NodeIDHex {
		t.Fatal("NODE_ID 派生不符")
	}
	if !ed25519.Verify(nodePub, canonical, mustHex(t, na.SelfSignatureHex)) {
		t.Fatal("stdlib ed25519 验签失败（单前缀结论不成立）")
	}
	announce.SelfSignature = mustHex(t, na.SelfSignatureHex)
	if err := identity.VerifyNodeAnnounceWithPub(nodePub, announce); err != nil {
		t.Fatalf("identity.VerifyNodeAnnounceWithPub 失败: %v", err)
	}

	// 反证：双前缀（历史写法）必须被拒绝。
	domain := []byte(housekitchen.DomainNodeAnnounce)
	double := sha256.Sum256(append(append([]byte{}, domain...), canonical...))
	priv := ed25519.NewKeyFromSeed(mustHex(t, na.NodeSeedHex))
	announce.SelfSignature = ed25519.Sign(priv, double[:])
	if err := identity.VerifyNodeAnnounceWithPub(nodePub, announce); err == nil {
		t.Fatal("双前缀签名竟被接受——单前缀结论有误")
	} else {
		t.Logf("反证 OK：双前缀签名被拒（%v）", err)
	}
	t.Logf("NodeAnnounce 单前缀互通 OK：digest=%s", na.SignDigestHex)
}

// TestInterop_SealedHKDFAndAEAD 用独立 HKDF 与 stdlib AES-GCM 复算两条封存路径。
func TestInterop_SealedHKDFAndAEAD(t *testing.T) {
	v := build()
	sv := v.Sealed

	recipientPriv := mustHex(t, sv.RecipientX25519PrivHex)
	recipientPub, err := curve25519.X25519(recipientPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("派生 recipient 公钥失败: %v", err)
	}
	requireEqualString(t, "recipient 公钥", sv.RecipientX25519PubHex, hex.EncodeToString(recipientPub))

	// ---- 路径 A：主题密钥封装 ----
	tk := sv.TopicKeyWrap
	ephPriv := mustHex(t, tk.EphemeralX25519PrivHex)
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("派生 ephemeral 公钥失败: %v", err)
	}
	requireEqualString(t, "ephemeral 公钥", tk.EphemeralX25519PubHex, hex.EncodeToString(ephPub))
	shared, err := curve25519.X25519(ephPriv, recipientPub)
	if err != nil {
		t.Fatalf("X25519 协商失败: %v", err)
	}
	requireEqualString(t, "共享密钥", tk.SharedSecretHex, hex.EncodeToString(shared))
	key := independentHKDF(shared, nil, []byte(tk.HKDFInfoASCII), 32)
	requireEqualString(t, "独立 HKDF 派生密钥", tk.DerivedKeyHex, hex.EncodeToString(key))
	goKey, err := fccrypto.HKDF(shared, nil, tk.HKDFInfoASCII, 32)
	if err != nil {
		t.Fatalf("crypto.HKDF 失败: %v", err)
	}
	requireEqual(t, "crypto.HKDF vs 独立 HKDF", key, goKey)
	topicAD := mustHex(t, tk.AssociatedDataHex)
	topicSealed := mustHex(t, tk.SealedHex)
	topicNonce := mustHex(t, tk.NonceHex)
	plain := stdlibGCMOpen(t, key, topicNonce, topicSealed[len(topicNonce):], topicAD)
	requireEqualString(t, "主题密钥明文", tk.PlaintextTopicKeyHex, hex.EncodeToString(plain))
	goPlain, err := fccrypto.OpenFromSender(recipientPriv, ephPub, topicSealed, topicAD, tk.HKDFInfoASCII)
	if err != nil {
		t.Fatalf("crypto.OpenFromSender 失败: %v", err)
	}
	requireEqualString(t, "OpenFromSender 明文", tk.PlaintextTopicKeyHex, hex.EncodeToString(goPlain))

	// ---- 路径 B：封存整条 SignedBody ----
	sb := sv.SealedBody
	bEphPriv := mustHex(t, sb.EphemeralX25519PrivHex)
	bEphPub, err := curve25519.X25519(bEphPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("派生封存临时公钥失败: %v", err)
	}
	requireEqualString(t, "封存临时公钥", sb.EphemeralX25519PubHex, hex.EncodeToString(bEphPub))
	bShared, err := curve25519.X25519(bEphPriv, recipientPub)
	if err != nil {
		t.Fatalf("封存 X25519 协商失败: %v", err)
	}
	requireEqualString(t, "封存共享密钥", sb.SharedSecretHex, hex.EncodeToString(bShared))
	bKey := independentHKDF(bShared, nil, []byte(sb.InfoASCII), 32)
	requireEqualString(t, "封存派生密钥", sb.DerivedKeyHex, hex.EncodeToString(bKey))

	// AD 独立拼接校验。
	wantAD := append(append([]byte{}, []byte(sb.AssociatedDataPrefix)...), mustHex(t, sv.RendezvousHex)...)
	wantAD = append(wantAD, housekitchen.Uint64BE(sv.Epoch)...)
	requireEqual(t, "封存 AD", wantAD, mustHex(t, sb.AssociatedDataHex))

	bNonce := mustHex(t, sb.NonceHex)
	bSealed := mustHex(t, sb.SealedHex)
	bPlain := stdlibGCMOpen(t, bKey, bNonce, bSealed[len(bNonce):], wantAD)
	requireEqualString(t, "封存正文明文 == 完整正文", sb.PlaintextFullBodyProtoHex, hex.EncodeToString(bPlain))

	// 明文必须等于"完整 SignedBody（含 msg_id 与 signers）"的确定性序列化。
	full := reconstructSignedBody(t, v, true)
	wantFull, err := proto.MarshalOptions{Deterministic: true}.Marshal(full)
	if err != nil {
		t.Fatalf("序列化完整正文失败: %v", err)
	}
	requireEqualString(t, "完整正文确定性序列化", sb.PlaintextFullBodyProtoHex, hex.EncodeToString(wantFull))

	// 冻结 crypto 也必须能解开同一密文。
	goBody, err := fccrypto.OpenFromSender(recipientPriv, bEphPub, bSealed, wantAD, sb.InfoASCII)
	if err != nil {
		t.Fatalf("crypto.OpenFromSender（封存正文）失败: %v", err)
	}
	requireEqualString(t, "OpenFromSender 封存明文", sb.PlaintextFullBodyProtoHex, hex.EncodeToString(goBody))

	// 形状 1：sealed.Seal / sealed.Open 形状，field 1 = rendezvous。
	spSealed := &pb.SealedPayload{
		InboxRendezvousId: housekitchen.PBHash(mustHash(t, sv.RendezvousHex)),
		Epoch:             sv.Epoch,
		EphemeralX25519:   bEphPub,
		Ciphertext:        bSealed,
		JitterHintMs:      sv.JitterHintMS,
	}
	requireEqualString(t, "手写编码 SealedPayload（形状1）", sb.SealedPayloadProtoHex, hex.EncodeToString(encSealedPayload(spSealed)))
	canonicalSealed, err := housekitchen.CanonicalSealedPayload(spSealed)
	if err != nil {
		t.Fatalf("CanonicalSealedPayload 失败: %v", err)
	}
	requireEqualString(t, "CanonicalSealedPayload（形状1）", sb.SealedPayloadSignedHex, hex.EncodeToString(canonicalSealed))
	if !bytes.HasPrefix(canonicalSealed, []byte(housekitchen.DomainSealedPayload)) {
		t.Fatal("封存规范化前缀不是 DomainSealedPayload")
	}
	opened, err := sealed.Open(recipientPriv, spSealed)
	if err != nil {
		t.Fatalf("sealed.Open 无法解开本向量（info/AD 与实际实现不符）: %v", err)
	}
	requireEqualString(t, "sealed.Open 内层 msg_id", v.SignedBody.MsgIDHex, hex.EncodeToString(housekitchen.GetHash(opened.GetMsgId()).Bytes()))

	// 形状 2：node.publishAsRelay / node.Unseal 形状，field 1 = SHA-256(inner_body) 承诺值。
	nr := sv.NodeRelay
	requireEqualString(t, "形状2 inner_body", nr.InnerBodyProtoHex, hex.EncodeToString(wantFull))
	commit := sha256.Sum256(wantFull)
	requireEqualString(t, "形状2 承诺值", nr.CommitmentHex, hex.EncodeToString(commit[:]))
	spNode := &pb.SealedPayload{
		InboxRendezvousId: housekitchen.PBHash(commit),
		InnerBody:         wantFull,
	}
	requireEqualString(t, "手写编码 SealedPayload（形状2）", nr.SealedPayloadProtoHex, hex.EncodeToString(encSealedPayload(spNode)))
	canonicalNode, err := housekitchen.CanonicalSealedPayload(spNode)
	if err != nil {
		t.Fatalf("CanonicalSealedPayload（形状2）失败: %v", err)
	}
	requireEqualString(t, "CanonicalSealedPayload（形状2）", nr.SealedPayloadSignedHex, hex.EncodeToString(canonicalNode))

	// Finding F12 的实证：两种形状互不兼容。
	if len(spNode.GetCiphertext()) != 0 || len(spNode.GetInnerBody()) == 0 {
		t.Fatal("形状2 应为 inner_body 非空、ciphertext 空的载荷")
	}
	if _, err := sealed.Open(recipientPriv, spNode); err == nil {
		t.Fatal("sealed.Open 竟接受了 node 形状的载荷——F12 可能已被修复")
	} else {
		knownIssue(t, "F12", "high",
			"sealed.Seal/Open 形状（ciphertext+rendezvous）与 node.publishAsRelay/Unseal 形状（inner_body+commitment）互不兼容；sealed.Open 拒绝 node 形状的载荷: "+err.Error())
	}
	t.Logf("封存互通 OK：topic_key=%s sealed_key=%s", tk.DerivedKeyHex, sb.DerivedKeyHex)
}

func stdlibGCMOpen(t *testing.T, key, nonce, ct, ad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("AES 初始化失败: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("GCM 初始化失败: %v", err)
	}
	pt, err := gcm.Open(nil, nonce, ct, ad)
	if err != nil {
		t.Fatalf("stdlib GCM 解密失败: %v", err)
	}
	return pt
}

// TestInterop_RelayTag 独立复算 relay_tag。
func TestInterop_RelayTag(t *testing.T) {
	v := build()
	rt := v.RelayTag
	dailyKey := mustHex(t, rt.DailyKeyHex)
	msgID := mustHash(t, rt.MsgIDHex)
	if len(rt.PreviousTags) != len(rt.Tags) {
		t.Fatal("previous_tags 与 tags 长度不一致")
	}
	for i, prev := range rt.PreviousTags {
		got := independentRelayTag(dailyKey, msgID, prev)
		if got != rt.Tags[i] {
			t.Fatalf("relay_tag[%d] 独立实现=%016x，向量=%016x", i, got, rt.Tags[i])
		}
		if goTag := fccrypto.RelayTag(dailyKey, msgID, prev); goTag != got {
			t.Fatalf("relay_tag[%d] crypto.RelayTag=%016x，独立实现=%016x", i, goTag, got)
		}
	}
	t.Logf("relay_tag 确定性 OK：%v", rt.Tags)
}

// TestDomainsWellFormed 校验域向量自洽。
func TestDomainsWellFormed(t *testing.T) {
	v := build()
	seen := map[string]bool{}
	for _, d := range v.Domains {
		if seen[d.Name] {
			t.Fatalf("域 %s 重复", d.Name)
		}
		seen[d.Name] = true
		requireEqualString(t, "域 "+d.Name+" 的 hex", hex.EncodeToString([]byte(d.ASCII)), d.Hex)
	}
	if !seen["DomainAdminSet"] || !seen["DomainSealedPayload"] {
		t.Fatal("向量缺少 DomainAdminSet / DomainSealedPayload")
	}
	t.Logf("共 %d 个域前缀（其中 %d 个是 sealed 包的未导出常量镜像）", len(v.Domains), 2)
}
