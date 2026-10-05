// 本文件是定向广播（docs/PROTOCOL.md 附录 E）的互操作与对抗性验证。
//
// 核心思路：**只用 vectors.json 里的字段级输入**（固定管理员种子、收件人种子、
// blind_salt、eph 私钥、各 nonce、时间戳），用
//   - 手写的最小 proto3 编码器（不经过 google.golang.org/protobuf），
//   - 独立实现的 HKDF-SHA256 / HMAC-SHA256（不经过 golang.org/x/crypto/hkdf），
//   - 标准库 crypto/aes + cipher.GCM，
//   - 标准库 ed25519（签名输入按 SIGN_INPUT 公式独立拼装），
//
// 重新拼出一条完整的 DirectedBody，再交给**冻结实现**验收：
// directed.VerifyBody 必须接受、directed.Open 必须让每个收件人解出内层、
// 非收件人必须得到 ErrNotAuthorized。
//
// 最后 10 个测试是附录 E 的对抗性负例，每条都断言具体错误哨兵。
package conformance_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
	"github.com/loongqing/FuturecastAlpha/internal/conformance"
	fccrypto "github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/directed"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
)

// ---------- 测试侧独立 proto3 编码器 ----------
//
// 只使用 helpers_test.go 里的字节原语（encVarintField / encBytesField / ...），
// 与 internal/conformance 包内的编码器是两份独立代码。

func encDirectRecipientT(r *pb.DirectRecipient) []byte {
	var out []byte
	out = append(out, encBytesField(1, r.GetEphPub())...)
	out = append(out, encBytesField(2, r.GetWrappedKey())...)
	out = append(out, encBytesField(3, r.GetRecipientTag())...)
	return out
}

func encDirectedKernelT(k *pb.DirectedKernel) []byte {
	var out []byte
	out = append(out, encStringField(1, k.GetTopic())...)
	out = append(out, encStringField(2, k.GetMediaType())...)
	out = append(out, encStringField(3, k.GetBody())...)
	out = append(out, encVarintField(4, uint64(k.GetCreatedAtUnixNanos()))...)
	out = append(out, encVarintField(5, uint64(k.GetExpiresAtUnixNanos()))...)
	out = append(out, encBytesField(6, k.GetNonce())...)
	// field 7 (outer_msg_id) 已废弃保留号：编码时一律不出现。
	return out
}

func encDirectedBodyT(b *pb.DirectedBody) []byte {
	var out []byte
	out = append(out, encVarintField(1, uint64(b.GetProtoVersion()))...)
	out = append(out, encVarintField(2, uint64(b.GetKind()))...)
	// field 3 = msg_id：派生值，编码前清空
	out = append(out, encVarintField(4, uint64(b.GetCreatedAtUnixNanos()))...)
	out = append(out, encVarintField(5, uint64(b.GetExpiresAtUnixNanos()))...)
	out = append(out, encBytesField(6, b.GetNonce())...)
	out = append(out, encVarintField(7, b.GetAdminSetGeneration())...)
	if h := housekitchen.GetHash(b.GetSignerSetHash()); !h.IsZero() {
		out = append(out, encMsgField(8, encHashLike(h.Bytes()))...)
	}
	if p := b.GetPolicy(); p != nil {
		out = append(out, encMsgField(9, encPolicy(p))...)
	}
	out = append(out, encVarintField(10, uint64(b.GetMaxHops()))...)
	// field 11 = signers：签名本体，编码前清空
	for _, r := range b.GetRecipients() {
		out = append(out, encMsgField(12, encDirectRecipientT(r))...)
	}
	out = append(out, encBytesField(13, b.GetCiphertext())...)
	out = append(out, encBytesField(14, b.GetContentNonce())...)
	out = append(out, encVarintField(15, uint64(b.GetRecipientCount()))...)
	out = append(out, encBytesField(16, b.GetBlindSalt())...)
	return out
}

// ---------- 测试侧独立密码学小工具 ----------

// x25519ScalarFromEd25519Seed 独立实现 libsodium crypto_sign_ed25519_sk_to_curve25519：
// SHA-512(seed)[:32] 后 clamp。
func x25519ScalarFromEd25519Seed(seed []byte) []byte {
	h := sha512.Sum512(seed)
	s := make([]byte, 32)
	copy(s, h[:32])
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return s
}

func testGCMSeal(t *testing.T, key, nonce, plaintext, ad []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("AES 初始化失败: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("GCM 初始化失败: %v", err)
	}
	if len(nonce) != gcm.NonceSize() {
		t.Fatalf("nonce 长度应为 %d，实为 %d", gcm.NonceSize(), len(nonce))
	}
	return gcm.Seal(nil, nonce, plaintext, ad)
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func testHMACSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// ---------- 从 vectors.json 字段级输入重建整条消息 ----------

type sealedSlot struct {
	ephPub, xPub, shared, wrapKey, wrapAD, wrapped, tag []byte
	signInput                                           [32]byte
	signature                                           []byte
}

type sealedDirected struct {
	body          *pb.DirectedBody
	canonical     []byte
	directedProto []byte
	msgID         housekitchen.Hash
	blindKey      []byte
	kernelProto   []byte
	kernelBytes   []byte
	slots         []sealedSlot
}

type directedSpec struct {
	set          *pb.AdminSet
	keys         []*identity.AdminKey
	recips       []*identity.NodeIdentity
	nowNanos     int64
	ttlNanos     int64
	topic        string
	mediaType    string
	text         string
	bodyNonce    []byte
	kernelNonce  []byte
	blindSalt    []byte
	contentKey   []byte
	contentNonce []byte
	ephPrivs     [][]byte
	wrapNonces   [][]byte
}

// sealDirected 按附录 E.2 的公式独立封装一条定向广播，并用标准库 ed25519 独立签名。
// 全过程不使用 internal/directed 的任何封装代码，也不使用 Go protobuf 运行时。
func sealDirected(t *testing.T, sp directedSpec) *sealedDirected {
	t.Helper()
	setHash, err := housekitchen.AdminSetHash(sp.set)
	if err != nil {
		t.Fatalf("AdminSetHash 失败: %v", err)
	}

	kernel := &pb.DirectedKernel{
		Topic:              sp.topic,
		MediaType:          sp.mediaType,
		Body:               sp.text,
		CreatedAtUnixNanos: sp.nowNanos,
		ExpiresAtUnixNanos: sp.nowNanos + sp.ttlNanos,
		Nonce:              sp.kernelNonce,
	}
	kernelProto := encDirectedKernelT(kernel)
	kernelBytes := append([]byte(housekitchen.DomainDirectedKernel), kernelProto...)

	blindKey := independentHKDF(sp.contentKey, sp.blindSalt, []byte(housekitchen.DomainDirectedBlind), 32)
	innerAD := append([]byte(housekitchen.DomainDirectedKernel), sp.blindSalt...)
	ciphertext := testGCMSeal(t, sp.contentKey, sp.contentNonce, kernelBytes, innerAD)

	body := &pb.DirectedBody{
		ProtoVersion:       housekitchen.ProtoVersion,
		Kind:               pb.MessageKind_MESSAGE_KIND_DIRECTED_BROADCAST,
		CreatedAtUnixNanos: sp.nowNanos,
		ExpiresAtUnixNanos: sp.nowNanos + sp.ttlNanos,
		Nonce:              sp.bodyNonce,
		AdminSetGeneration: sp.set.GetGeneration(),
		SignerSetHash:      housekitchen.PBHash(setHash),
		Policy:             sp.set.GetPolicy(),
		MaxHops:            housekitchen.DefaultMaxHops,
		BlindSalt:          sp.blindSalt,
		RecipientCount:     uint32(len(sp.recips)),
		ContentNonce:       sp.contentNonce,
		Ciphertext:         ciphertext,
	}

	slots := make([]sealedSlot, 0, len(sp.recips))
	for i, id := range sp.recips {
		scalar := x25519ScalarFromEd25519Seed(id.KeySeed)
		xPub, err := curve25519.X25519(scalar, curve25519.Basepoint)
		if err != nil {
			t.Fatalf("槽位 %d 派生 X25519 公钥失败: %v", i, err)
		}
		// 交叉验证：ed25519 公钥的 birational map 必须等于 scalar*base。
		mapped, err := fccrypto.Ed25519ToX25519(id.Pub)
		if err != nil {
			t.Fatalf("Ed25519ToX25519 失败: %v", err)
		}
		requireEqual(t, "recipient x25519 公钥（scalar*base vs Ed25519ToX25519）", mapped, xPub)

		ephPub, err := curve25519.X25519(sp.ephPrivs[i], curve25519.Basepoint)
		if err != nil {
			t.Fatalf("槽位 %d 派生 eph_pub 失败: %v", i, err)
		}
		shared, err := curve25519.X25519(sp.ephPrivs[i], xPub)
		if err != nil {
			t.Fatalf("槽位 %d X25519 协商失败: %v", i, err)
		}
		wrapKey := independentHKDF(shared, nil, []byte(housekitchen.DomainDirectedWrap), 32)
		wrapAD := append([]byte(conformance.DirectedWrapADPrefix), sp.blindSalt...)
		wrapAD = append(wrapAD, housekitchen.Uint64BE(uint64(i))...)
		wrapped := append(append([]byte(nil), sp.wrapNonces[i]...),
			testGCMSeal(t, wrapKey, sp.wrapNonces[i], sp.contentKey, wrapAD)...)

		tagMsg := append([]byte(housekitchen.DomainDirectedTag), id.ID.Bytes()...)
		tag := testHMACSHA256(blindKey, tagMsg)[:16]

		body.Recipients = append(body.Recipients, &pb.DirectRecipient{
			EphPub:       ephPub,
			WrappedKey:   wrapped,
			RecipientTag: tag,
		})
		slots = append(slots, sealedSlot{
			ephPub: ephPub, xPub: xPub, shared: shared, wrapKey: wrapKey,
			wrapAD: wrapAD, wrapped: wrapped, tag: tag,
		})
	}

	directedProto := encDirectedBodyT(body)
	canonical := append([]byte(housekitchen.DomainDirectedBody), directedProto...)
	msgID := housekitchen.MsgIDFromCanonical(canonical)

	// 标准库 ed25519 独立签名（SIGN_INPUT = SHA-256(DomainSignInput || canonical || key_id || u64be(at))）。
	for i := 0; i < 2 && i < len(sp.keys); i++ {
		k := sp.keys[i]
		input := independentSignInput(canonical, k.KeyID, sp.nowNanos)
		sig := ed25519.Sign(k.Priv, input[:])
		body.Signers = append(body.Signers, &pb.Signature{
			KeyId:             housekitchen.PBKeyID(k.KeyID),
			Signature:         sig,
			SignedAtUnixNanos: sp.nowNanos,
		})
		slots[i].signInput = input
		slots[i].signature = sig
	}
	body.MsgId = housekitchen.PBHash(msgID)

	return &sealedDirected{
		body: body, canonical: canonical, directedProto: directedProto,
		msgID: msgID, blindKey: blindKey, kernelProto: kernelProto, kernelBytes: kernelBytes,
		slots: slots,
	}
}

// directedFixture 是"完全从 vectors.json 重建"出来的一条消息及其上下文。
type directedFixture struct {
	v        *conformance.Vectors
	dv       *conformance.DirectedVector
	set      *pb.AdminSet
	keys     []*identity.AdminKey
	recips   []*identity.NodeIdentity
	outsider *identity.NodeIdentity
	now      time.Time
	sealed   *sealedDirected
}

func directedSpecFromVector(t *testing.T, v *conformance.Vectors) (directedSpec, *directedFixture) {
	t.Helper()
	dv := v.Directed
	fx := &directedFixture{v: v, dv: &dv, now: time.Unix(0, dv.NowUnixNanos)}

	fx.set = setFromVector(t, v)

	// 管理员密钥：仅用 admin_set 段里的种子重建。
	for _, k := range v.AdminSet.Keys {
		key, err := identity.AdminKeyFromSeed(mustHex(t, k.SeedHex), k.Label, pb.AdminRole(k.Role))
		if err != nil {
			t.Fatalf("重建管理员密钥 %s 失败: %v", k.Label, err)
		}
		requireEqualString(t, "管理员 key_id", k.KeyIDHex, hexOf(key.KeyID.Bytes()))
		fx.keys = append(fx.keys, key)
	}

	// 收件人：仅用 directed.recipients[].ed25519_seed_hex 重建。
	for _, r := range dv.Recipients {
		id, err := identity.NodeIdentityFromSeed(mustHex(t, r.Ed25519SeedHex))
		if err != nil {
			t.Fatalf("重建收件人 %s 失败: %v", r.Label, err)
		}
		requireEqualString(t, "收件人 node_id", r.NodeIDHex, hexOf(id.ID.Bytes()))
		requireEqualString(t, "收件人 ed25519 公钥", r.Ed25519PubHex, hexOf(id.Pub))
		fx.recips = append(fx.recips, id)
	}
	outsider, err := identity.NodeIdentityFromSeed(seed32("futurecast/vector/directed-outsider"))
	if err != nil {
		t.Fatalf("重建非收件人失败: %v", err)
	}
	fx.outsider = outsider

	ephPrivs := make([][]byte, 0, len(dv.Recipients))
	wrapNonces := make([][]byte, 0, len(dv.Recipients))
	for _, r := range dv.Recipients {
		ephPrivs = append(ephPrivs, mustHex(t, r.EphPrivHex))
		wrapNonces = append(wrapNonces, mustHex(t, r.WrapNonceHex))
	}

	sp := directedSpec{
		set: fx.set, keys: fx.keys, recips: fx.recips,
		nowNanos: dv.NowUnixNanos, ttlNanos: dv.TTLNanos,
		topic: dv.Kernel.Topic, mediaType: dv.MediaType, text: dv.Kernel.Body,
		bodyNonce: mustHex(t, dv.NonceHex), kernelNonce: mustHex(t, dv.Kernel.NonceHex),
		blindSalt: mustHex(t, dv.BlindSaltHex), contentKey: mustHex(t, dv.ContentKeyHex),
		contentNonce: mustHex(t, dv.ContentNonceHex),
		ephPrivs:     ephPrivs, wrapNonces: wrapNonces,
	}
	return sp, fx
}

// rebuildDirectedFromVectors 重建并逐字段对照 vectors.json 中的所有输出。
func rebuildDirectedFromVectors(t *testing.T) *directedFixture {
	t.Helper()
	v := build()
	sp, fx := directedSpecFromVector(t, v)
	dv := v.Directed
	sd := sealDirected(t, sp)
	fx.sealed = sd

	// ---- 规范化字节 ----
	requireEqualString(t, "KERNEL_BYTES", dv.Kernel.KernelBytesHex, hexOf(sd.kernelBytes))
	requireEqualString(t, "kernel proto（手写编码器）", dv.Kernel.ProtoHex, hexOf(sd.kernelProto))
	requireEqualString(t, "DIRECTED_BYTES", dv.DirectedBytesHex, hexOf(sd.canonical))
	requireEqualString(t, "directed proto（手写编码器）", dv.DirectedProtoHex, hexOf(sd.directedProto))
	if !bytes.HasPrefix(sd.canonical, []byte(housekitchen.DomainDirectedBody)) {
		t.Fatalf("DIRECTED_BYTES 未以 DomainDirectedBody 开头")
	}
	requireEqualString(t, "DIRECTED_MSG_ID", dv.DirectedMsgIDHex, hexOf(sd.msgID.Bytes()))

	// 冻结实现的 canonical 必须一致。
	goCanonical, err := housekitchen.CanonicalDirectedBody(sd.body)
	if err != nil {
		t.Fatalf("CanonicalDirectedBody 失败: %v", err)
	}
	requireEqual(t, "CanonicalDirectedBody vs 独立实现", sd.canonical, goCanonical)

	// ---- 密钥派生 ----
	requireEqualString(t, "content_key", dv.ContentKeyHex, hexOf(sp.contentKey))
	requireEqualString(t, "blind_key（独立 HKDF）", dv.BlindKeyHex, hexOf(sd.blindKey))
	goBlind, err := fccrypto.HKDF(sp.contentKey, sp.blindSalt, housekitchen.DomainDirectedBlind, 32)
	if err != nil {
		t.Fatalf("crypto.HKDF 失败: %v", err)
	}
	requireEqual(t, "blind_key（冻结 HKDF）", sd.blindKey, goBlind)

	// ---- 内层密文：标准库直接解出，确认得到 KERNEL_BYTES ----
	plain := stdlibGCMOpen(t, sp.contentKey, sp.contentNonce, mustHex(t, dv.CiphertextHex),
		append([]byte(housekitchen.DomainDirectedKernel), sp.blindSalt...))
	requireEqualString(t, "ciphertext 解出 KERNEL_BYTES", dv.Kernel.KernelBytesHex, hexOf(plain))
	// 再用固定 nonce 重新加密，必须逐字节复现 ciphertext。
	requireEqualString(t, "ciphertext 独立重算", dv.CiphertextHex,
		hexOf(testGCMSeal(t, sp.contentKey, sp.contentNonce, sd.kernelBytes,
			append([]byte(housekitchen.DomainDirectedKernel), sp.blindSalt...))))

	// ---- 每个槽位 ----
	for i, r := range dv.Recipients {
		s := sd.slots[i]
		requireEqualString(t, "slot eph_pub", r.EphPubHex, hexOf(s.ephPub))
		requireEqualString(t, "slot x25519_pub", r.X25519PubHex, hexOf(s.xPub))
		requireEqualString(t, "slot shared_secret", r.SharedSecretHex, hexOf(s.shared))
		requireEqualString(t, "slot wrap_key", r.WrapKeyHex, hexOf(s.wrapKey))
		requireEqualString(t, "slot wrap_ad", r.WrapADHex, hexOf(s.wrapAD))
		requireEqualString(t, "slot wrapped_key", r.WrappedKeyHex, hexOf(s.wrapped))
		requireEqualString(t, "slot recipient_tag（独立 HMAC）", r.RecipientTagHex, hexOf(s.tag))

		// wrapped_key 用标准库解开 -> content_key
		recovered := stdlibGCMOpen(t, s.wrapKey, sp.wrapNonces[i],
			mustHex(t, r.WrappedKeyHex)[12:], s.wrapAD)
		requireEqual(t, "槽位 unwrap 得到 content_key", sp.contentKey, recovered)
	}
	for i, s := range dv.Signers {
		if i >= len(sd.slots) {
			break
		}
		requireEqualString(t, "SIGN_INPUT", s.SignInputHex, hexOf(sd.slots[i].signInput[:]))
		requireEqualString(t, "signature", s.SignatureHex, hexOf(sd.slots[i].signature))
	}
	return fx
}

// ---------- 互操作：冻结实现必须接受纯外部实现重建的消息 ----------

func TestDirectedInterop_RebuildFromVectorInputsOnly(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)

	res, err := directed.VerifyBody(fx.sealed.body, fx.set, fx.now)
	if err != nil {
		t.Fatalf("纯外部重建的定向广播未被冻结 directed.VerifyBody 接受: %v", err)
	}
	if len(res.Signers) != 2 {
		t.Fatalf("应看到 2 个有效签名者，实为 %d", len(res.Signers))
	}
	for i, id := range fx.recips {
		got, err := directed.Open(id.KeySeed, id.ID, fx.sealed.body)
		if err != nil {
			t.Fatalf("收件人 %d 无法解开冻结实现的消息: %v", i, err)
		}
		if got.Slot != i {
			t.Fatalf("收件人 %d 解出的槽位为 %d", i, got.Slot)
		}
		if got.Kernel.GetBody() != fx.dv.Kernel.Body {
			t.Fatalf("收件人 %d 解出的正文 %q 不符", i, got.Kernel.GetBody())
		}
	}
	if _, err := directed.Open(fx.outsider.KeySeed, fx.outsider.ID, fx.sealed.body); !errors.Is(err, housekitchen.ErrNotAuthorized) {
		t.Fatalf("非收件人应得到 ErrNotAuthorized，实为: %v", err)
	}
	t.Logf("定向广播互操作 OK：directed_msg_id=%s 槽位=%d 内核=%d 字节",
		fx.dv.DirectedMsgIDHex, fx.dv.RecipientCount, len(fx.sealed.kernelBytes))
}

// TestDirectedGoldenFrozenPins 是冻结守卫：锁定 golden 向量的锚点字节。
// 任何一侧（实现或向量）悄悄漂移都会立刻失败，提醒复核 PROTOCOL 附录 E。
func TestDirectedGoldenFrozenPins(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)
	dv := fx.dv
	pins := []struct{ name, want, got string }{
		{"directed_msg_id", "7f954eb07ce78c232af62587d1cc3881d013a7544e231042e30ccd8de2d5301c", dv.DirectedMsgIDHex},
		{"blind_salt", "d7e63dfccba1ca781bb75171683f9c11", dv.BlindSaltHex},
		{"content_key", "b94cb973b299640cb52911e16160dee1f5028c74b54ae8df89afde551059d5d2", dv.ContentKeyHex},
		{"blind_key", "f3effb8041c26c150adc75e52fb7e93c3f9eb9db75260abc8a462020fd413c21", dv.BlindKeyHex},
		{"content_nonce", "9c082e91358fae071d7b2d0c", dv.ContentNonceHex},
		{"recipient_tag[0]", "17d2b279a930db65dfedd184cedf0b6e", dv.Recipients[0].RecipientTagHex},
		{"recipient_tag[1]", "ad0087886087af009812c915911dd0fa", dv.Recipients[1].RecipientTagHex},
		{"recipient_tag[2]", "2440ebffe340c445979c9308119ab420", dv.Recipients[2].RecipientTagHex},
		{"wrap_key[0]", "38a7ba52362eff800ec5b19b9e0f3d990bf99a4777b5ef8eb9298abfb2aa673d", dv.Recipients[0].WrapKeyHex},
		{"sha256(directed_bytes)", "9ed2979755bb8b9482aa9891d4cd9952fb5d84a71975c395f3e3db5dd01dab56", hexOf(sha256Sum(mustHex(t, dv.DirectedBytesHex)))},
		{"sha256(kernel_bytes)", "778fdd6f9c508d750984da4dc015a5905ec432b4c8f041614309aba70910722d", hexOf(sha256Sum(mustHex(t, dv.Kernel.KernelBytesHex)))},
		{"sha256(ciphertext)", "c3b4f532da7bc12c929e6f63dd431d6ee91021fe2aae02d5a68c8448c8404b5d", hexOf(sha256Sum(mustHex(t, dv.CiphertextHex)))},
	}
	for _, p := range pins {
		if p.want != p.got {
			t.Fatalf("golden 锚点 %s 变了\n want=%s\n got =%s", p.name, p.want, p.got)
		}
	}
	t.Logf("定向广播 golden 锚点守卫 OK（%d 项）", len(pins))
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// ---------- 对抗性负例 ----------

func cloneDirected(t *testing.T, b *pb.DirectedBody) *pb.DirectedBody {
	t.Helper()
	c, ok := proto.Clone(b).(*pb.DirectedBody)
	if !ok {
		t.Fatal("DirectedBody 克隆失败")
	}
	return c
}

// resignDirected 模拟"签名自洽但语义非法"的攻击者：改完字段后重算 canonical、
// 重签并回填 msg_id，使内容寻址与门限签名都通过，从而逼出后面的语义检查。
func resignDirected(t *testing.T, fx *directedFixture, body *pb.DirectedBody) {
	t.Helper()
	body.MsgId = nil
	body.Signers = nil
	canonical, err := housekitchen.CanonicalDirectedBody(body)
	if err != nil {
		t.Fatalf("CanonicalDirectedBody 失败: %v", err)
	}
	for i := 0; i < 2; i++ {
		body.Signers = append(body.Signers, fx.keys[i].Sign(canonical, fx.now))
	}
	body.MsgId = housekitchen.PBHash(housekitchen.MsgIDFromCanonical(canonical))
}

// D1 — 门限不足：2-of-3 只剩 1 个签名者。
func TestDirectedNegative_D1_ThresholdNotMet(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)
	body := cloneDirected(t, fx.sealed.body)
	body.Signers = body.Signers[:1]
	_, err := directed.VerifyBody(body, fx.set, fx.now)
	expectErrIs(t, err, housekitchen.ErrThresholdNotMet, "D1 1/3 签名")
}

// D2 — 篡改 created_at：内容寻址先于时间窗检查。
func TestDirectedNegative_D2_CreatedAtTampered(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)
	body := cloneDirected(t, fx.sealed.body)
	body.CreatedAtUnixNanos++
	_, err := directed.VerifyBody(body, fx.set, fx.now)
	expectErrIs(t, err, housekitchen.ErrMsgIDMismatch, "D2 篡改 created_at")
}

// D3 — recipient_count 与槽位数不符。
//
// 两种构造给出不同哨兵，必须分别固定下来：
//
//	(a) 直接改字段：签名覆盖了 recipient_count，msg_id 先不符 -> ErrMsgIDMismatch；
//	(b) 改字段后重签（签名自洽）：msg_id 通过，第 4 步结构检查 -> ErrDirectedInvalid。
func TestDirectedNegative_D3_RecipientCountMismatch(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)

	naive := cloneDirected(t, fx.sealed.body)
	naive.RecipientCount = 1
	_, err := directed.VerifyBody(naive, fx.set, fx.now)
	expectErrIs(t, err, housekitchen.ErrMsgIDMismatch, "D3(a) 直接篡改 recipient_count")

	consistent := cloneDirected(t, fx.sealed.body)
	consistent.RecipientCount = 1
	resignDirected(t, fx, consistent)
	_, err = directed.VerifyBody(consistent, fx.set, fx.now)
	expectErrIs(t, err, housekitchen.ErrDirectedInvalid, "D3(b) 重签自洽的 recipient_count=1 对 3 槽")
}

// D4 — blind_salt 长度错误（F15 已修复，这里是回归守卫）。
//
// F15 的真实风险：VerifyBody 原先不检查 blind_salt 长度，于是一条"重签自洽的
// 8 字节盐"消息能通过所有中继的外层校验并被全网转发，只有收件人在解密时才发现
// 打不开 —— 攻击者可以用它制造大量无法解密的流量。
// 现在外层与 Open 都必须拒绝。
func TestDirectedNegative_D4_BlindSaltLength(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)
	body := cloneDirected(t, fx.sealed.body)
	body.BlindSalt = body.BlindSalt[:8]
	resignDirected(t, fx, body)

	_, err := directed.VerifyBody(body, fx.set, fx.now)
	expectErrIs(t, err, housekitchen.ErrDirectedInvalid, "D4 外层必须拒绝 8 字节 blind_salt")

	_, err = directed.Open(fx.recips[0].KeySeed, fx.recips[0].ID, body)
	expectErrIs(t, err, housekitchen.ErrDirectedInvalid, "D4 directed.Open 也必须拒绝")
}

// D5 — 用另一个 AdminSet 验签（同代数）。
func TestDirectedNegative_D5_WrongAdminSet(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)
	otherKeys := testAdminKeys(t, "directed-other")
	otherSet := testSet(t, otherKeys, 1, nil)

	_, err := directed.VerifyBody(fx.sealed.body, otherSet, fx.now)
	expectErrIs(t, err, housekitchen.ErrSignerSetMismatch, "D5 另一个 AdminSet")
}

// D6 — 过期消息（签名自洽）。
func TestDirectedNegative_D6_Expired(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)
	_, err := directed.VerifyBody(fx.sealed.body, fx.set, fx.now.Add(2*time.Hour))
	expectErrIs(t, err, housekitchen.ErrExpired, "D6 过期")
}

// D7 — 非收件人解密。
//
// 这是**正常结果**而不是故障：网络上绝大多数节点都会得到 ErrNotAuthorized，
// 它们仍然正常转发外层可验签的消息。断言必须写清这一点。
func TestDirectedNegative_D7_NonRecipientIsNormalOutcome(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)
	res, err := directed.Open(fx.outsider.KeySeed, fx.outsider.ID, fx.sealed.body)
	if res != nil {
		t.Fatalf("非收件人不应得到结果: %+v", res)
	}
	expectErrIs(t, err, housekitchen.ErrNotAuthorized, "D7 非收件人（正常结果，非故障）")
	t.Log("D7 说明：非收件人得到 ErrNotAuthorized 是协议预期；节点仍应转发该消息（附录 E.4）。")
}

// D8 — 把 A 槽位的 wrapped_key 搬到 B 槽位：wrap AD 里的槽位序号失配，谁也解不开。
func TestDirectedNegative_D8_SlotSwapBreaksAD(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)
	// 前提：原始消息两个收件人都能解开。
	for i := 0; i < 2; i++ {
		if _, err := directed.Open(fx.recips[i].KeySeed, fx.recips[i].ID, fx.sealed.body); err != nil {
			t.Fatalf("前提失败：原始消息收件人 %d 解不开: %v", i, err)
		}
	}
	body := cloneDirected(t, fx.sealed.body)
	body.Recipients[0].WrappedKey, body.Recipients[1].WrappedKey =
		body.Recipients[1].WrappedKey, body.Recipients[0].WrappedKey
	resignDirected(t, fx, body)

	// 交换只动了槽位内容，结构仍然合法：外层必须照常通过（中继无从判断）。
	if _, err := directed.VerifyBody(body, fx.set, fx.now); err != nil {
		t.Fatalf("D8 外层不应因槽位搬移而失败（AD 失配只对收件人可见）: %v", err)
	}
	for i := 0; i < 2; i++ {
		_, err := directed.Open(fx.recips[i].KeySeed, fx.recips[i].ID, body)
		expectErrIs(t, err, housekitchen.ErrNotAuthorized, "D8 槽位搬移后收件人无法解密")
	}
}

// D9 — 把另一条消息的 eph_pub 移植过来：共享密钥变了，unwrap 必然失败。
func TestDirectedNegative_D9_ForeignEphPub(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)

	// 构造"另一条消息"：换 blind_salt / content_key / eph 私钥 / nonce。
	other := sealDirected(t, directedSpec{
		set: fx.set, keys: fx.keys, recips: fx.recips,
		nowNanos: fx.now.UnixNano(), ttlNanos: time.Hour.Nanoseconds(),
		topic: "alerts", mediaType: "text/plain", text: "another directed message",
		bodyNonce:    seed32("futurecast/vector/directed/other-body-nonce")[:16],
		kernelNonce:  seed32("futurecast/vector/directed/other-kernel-nonce")[:16],
		blindSalt:    seed32("futurecast/vector/directed/other-blind-salt")[:16],
		contentKey:   seed32("futurecast/vector/directed/other-content-key"),
		contentNonce: seed32("futurecast/vector/directed/other-content-nonce")[:12],
		ephPrivs: [][]byte{
			seed32("futurecast/vector/directed/other-eph-0"),
			seed32("futurecast/vector/directed/other-eph-1"),
			seed32("futurecast/vector/directed/other-eph-2"),
		},
		wrapNonces: [][]byte{
			seed32("futurecast/vector/directed/other-wrap-nonce-0")[:12],
			seed32("futurecast/vector/directed/other-wrap-nonce-1")[:12],
			seed32("futurecast/vector/directed/other-wrap-nonce-2")[:12],
		},
	})
	if _, err := directed.VerifyBody(other.body, fx.set, fx.now); err != nil {
		t.Fatalf("D9 前提失败：另一条消息自身应有效: %v", err)
	}
	if _, err := directed.Open(fx.recips[0].KeySeed, fx.recips[0].ID, other.body); err != nil {
		t.Fatalf("D9 前提失败：另一条消息应能被收件人 0 解开: %v", err)
	}

	// (a) 只换槽位 0：alice 解不开，未被动过的 bob 仍然可解（攻击只影响被篡改的槽位）。
	one := cloneDirected(t, fx.sealed.body)
	one.Recipients[0].EphPub = append([]byte(nil), other.body.GetRecipients()[0].GetEphPub()...)
	resignDirected(t, fx, one)
	if _, err := directed.Open(fx.recips[0].KeySeed, fx.recips[0].ID, one); !errors.Is(err, housekitchen.ErrNotAuthorized) {
		t.Fatalf("D9(a) 移植外来 eph_pub 后 alice 应得到 ErrNotAuthorized，实为: %v", err)
	} else {
		t.Logf("D9(a) 正确拒绝 -> %v", err)
	}
	if _, err := directed.Open(fx.recips[1].KeySeed, fx.recips[1].ID, one); err != nil {
		t.Fatalf("D9(a) 前提失败：未被动过的 bob 槽位应仍可解: %v", err)
	}

	// (b) 把所有槽位的 eph_pub 都换成另一条消息的：无人可解。
	all := cloneDirected(t, fx.sealed.body)
	for i := range all.Recipients {
		all.Recipients[i].EphPub = append([]byte(nil), other.body.GetRecipients()[i].GetEphPub()...)
	}
	resignDirected(t, fx, all)
	if _, err := directed.VerifyBody(all, fx.set, fx.now); err != nil {
		t.Fatalf("D9(b) 外层不应因 eph_pub 更换而失败: %v", err)
	}
	for i := range fx.recips {
		_, err := directed.Open(fx.recips[i].KeySeed, fx.recips[i].ID, all)
		expectErrIs(t, err, housekitchen.ErrNotAuthorized, "D9(b) 全部槽位 eph_pub 被换后无法解密")
	}
}

// D10 — 同一收件人在两条消息里的 recipient_tag 必须不同（不可关联）。
func TestDirectedNegative_D10_TagsUnlinkableAcrossMessages(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)
	other := sealDirected(t, directedSpec{
		set: fx.set, keys: fx.keys, recips: fx.recips,
		nowNanos: fx.now.UnixNano(), ttlNanos: time.Hour.Nanoseconds(),
		topic: "alerts", mediaType: "text/plain", text: fx.dv.Kernel.Body, // 内容与第一条完全相同
		bodyNonce:    seed32("futurecast/vector/directed/link-body-nonce")[:16],
		kernelNonce:  seed32("futurecast/vector/directed/link-kernel-nonce")[:16],
		blindSalt:    seed32("futurecast/vector/directed/link-blind-salt")[:16],
		contentKey:   seed32("futurecast/vector/directed/link-content-key"),
		contentNonce: seed32("futurecast/vector/directed/link-content-nonce")[:12],
		ephPrivs: [][]byte{
			seed32("futurecast/vector/directed/link-eph-0"),
			seed32("futurecast/vector/directed/link-eph-1"),
			seed32("futurecast/vector/directed/link-eph-2"),
		},
		wrapNonces: [][]byte{
			seed32("futurecast/vector/directed/link-wrap-nonce-0")[:12],
			seed32("futurecast/vector/directed/link-wrap-nonce-1")[:12],
			seed32("futurecast/vector/directed/link-wrap-nonce-2")[:12],
		},
	})
	for i := range fx.recips {
		t1 := fx.sealed.body.GetRecipients()[i].GetRecipientTag()
		t2 := other.body.GetRecipients()[i].GetRecipientTag()
		if housekitchen.ConstantTimeEqual(t1, t2) {
			t.Fatalf("收件人 %d 在两条消息里的 recipient_tag 相同 —— 观察者能跨消息关联名单", i)
		}
		e1 := fx.sealed.body.GetRecipients()[i].GetEphPub()
		e2 := other.body.GetRecipients()[i].GetEphPub()
		if housekitchen.ConstantTimeEqual(e1, e2) {
			t.Fatalf("收件人 %d 在两条消息里的 eph_pub 相同 —— 同样可关联", i)
		}
	}
	// 不可关联不能以牺牲功能为代价：两条消息都必须能被收件人解开。
	for i := range fx.recips {
		if _, err := directed.Open(fx.recips[i].KeySeed, fx.recips[i].ID, other.body); err != nil {
			t.Fatalf("第二条消息收件人 %d 解不开: %v", i, err)
		}
	}
	t.Log("D10 OK：同收件人跨消息的 recipient_tag 与 eph_pub 均不同，且两条消息都可解。")
}

// ---------- 文档/实现不一致的固化 ----------

// F14 — recipient_tag 是 HMAC-SHA256(blind_key, domain||node_id)[:16]，不是 proto 注释里的 SHA-256 公式。
func TestDirectedFinding_F14_TagIsHMACNotSHA256(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)
	blindKey := mustHex(t, fx.dv.BlindKeyHex)
	tag := mustHex(t, fx.dv.Recipients[0].RecipientTagHex)

	want := testHMACSHA256(blindKey, append([]byte(housekitchen.DomainDirectedTag), fx.recips[0].ID.Bytes()...))[:16]
	requireEqual(t, "recipient_tag 必须是 HMAC", want, tag)

	// proto 注释里的错误公式（SHA-256(content_key || ...)）：与真值必然不同。
	contentKey := mustHex(t, fx.dv.ContentKeyHex)
	notTag := sha256Sum(bytes.Join([][]byte{[]byte(housekitchen.DomainDirectedTag), contentKey, tag, contentKey}, nil))[:16]
	if bytes.Equal(notTag, tag) {
		t.Fatal("SHA-256 形式竟与 HMAC 形式相同")
	}
	knownIssue(t, "F14", "high",
		"proto/futurecast/v1/message.proto:149 把 recipient_tag 注释成 SHA-256(\"futurecast/v1/dirtag\\0\"||content_key||sealed_key||content_key_again)，"+
			"与实现和 PROTOCOL 附录 E.2 的 HMAC-SHA256(blind_key, domain||node_id)[:16] 不一致。")
}

// F16 已由 Lead 修复：废弃的 DirectedKernel.outer_msg_id 已从 proto 删除
// （field 7 保留号），housekitchen.DirectedBodyHash 也一并删除。
// 这里做正向守卫，防止死字段与误导性注释回退。
func TestResolvedFinding_F16_OuterMsgIDRemoved(t *testing.T) {
	fx := rebuildDirectedFromVectors(t)
	if got := fx.sealed.body.GetRecipients(); len(got) == 0 {
		t.Fatal("前提失败")
	}
	// 内层不应再出现字段 7；收件人仍应能正常解开。
	opened, err := directed.Open(fx.recips[0].KeySeed, fx.recips[0].ID, fx.sealed.body)
	if err != nil {
		t.Fatalf("收件人 0 解不开: %v", err)
	}
	if opened.Kernel.GetTopic() == "" {
		t.Fatal("内层 topic 不应为空")
	}
}

// F17 已由 Lead 修复：无调用方的 housekitchen.DomainDirectedKey 已删除。
// 该常量无法从 conformance 侧做"不存在"断言（编译期即失败），
// 因此这里只留一条说明性测试，真正的守卫由编译本身完成。
func TestResolvedFinding_F17_DomainDirectedKeyRemoved(t *testing.T) {
	// 若有人重新引入该常量，应当在附录 E 里同时说明它服务于哪条派生公式；
	// 目前 content_key 是纯随机值，不需要 HKDF。
}

// ---------- 向量结构自洽 ----------

func TestDirectedVectorWellFormed(t *testing.T) {
	v := build()
	dv := v.Directed
	if dv.Kind != uint32(pb.MessageKind_MESSAGE_KIND_DIRECTED_BROADCAST) {
		t.Fatalf("kind 应为 4，实为 %d", dv.Kind)
	}
	if dv.RecipientCount != uint32(len(dv.Recipients)) {
		t.Fatalf("recipient_count=%d 与槽位 %d 不符", dv.RecipientCount, len(dv.Recipients))
	}
	if dv.SignerSetHashHex != v.AdminSet.AdminSetHashHex {
		t.Fatalf("signer_set_hash 应与 admin_set 段一致\n want=%s\n got =%s", v.AdminSet.AdminSetHashHex, dv.SignerSetHashHex)
	}
	if len(dv.Signers) != 2 {
		t.Fatalf("应有 2 个签名者，实为 %d", len(dv.Signers))
	}
	for i, r := range dv.Recipients {
		if r.Index != i {
			t.Fatalf("recipients[%d].index=%d", i, r.Index)
		}
		if len(mustHex(t, r.RecipientTagHex)) != 16 {
			t.Fatalf("recipient_tag 应为 16 字节")
		}
		if len(mustHex(t, r.EphPubHex)) != 32 {
			t.Fatalf("eph_pub 应为 32 字节")
		}
		if len(mustHex(t, r.WrappedKeyHex)) != 12+32+16 {
			t.Fatalf("wrapped_key 应为 nonce(12)+ct(32)+tag(16)=60 字节，实为 %d", len(mustHex(t, r.WrappedKeyHex)))
		}
	}
	if len(mustHex(t, dv.ContentNonceHex)) != 12 {
		t.Fatal("content_nonce 应为 12 字节")
	}
	if len(mustHex(t, dv.BlindSaltHex)) != 16 {
		t.Fatal("blind_salt 应为 16 字节")
	}
	if len(mustHex(t, dv.CiphertextHex)) != len(mustHex(t, dv.Kernel.KernelBytesHex))+16 {
		t.Fatal("ciphertext 应为 KERNEL_BYTES + 16 字节 GCM tag")
	}
	// 名单隐私：序列化后的外层里不得出现收件人 node_id / 公钥 / 正文。
	blob := mustHex(t, dv.DirectedBytesHex)
	for _, r := range dv.Recipients {
		for _, leak := range [][]byte{mustHex(t, r.NodeIDHex), mustHex(t, r.Ed25519PubHex), mustHex(t, r.X25519PubHex)} {
			if bytes.Contains(blob, leak) {
				t.Fatal("DIRECTED_BYTES 中出现了收件人身份明文")
			}
		}
	}
	if bytes.Contains(blob, []byte(dv.Kernel.Body)) {
		t.Fatal("DIRECTED_BYTES 中出现了内层正文明文")
	}
	t.Logf("定向广播向量结构自洽 OK：%d 个槽位，DIRECTED_BYTES=%d 字节", len(dv.Recipients), len(blob))
}
