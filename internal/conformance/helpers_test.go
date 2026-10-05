// 本文件提供测试共用的构造器，以及一套**独立于 Go protobuf 运行时**的最小
// proto3 编码器 / HKDF / HMAC 实现。独立实现的用途是证明：只要遵守
// CONTRACTS §5 的规则，任何语言都能算出与 Go 完全一致的字节——而不是"只因为
// 两边都用了同一个 Go 库所以碰巧一致"。
package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
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
)

const vectorTopic = "alerts"

// ---------- 固定密钥材料 ----------

func seed32(label string) []byte {
	s := sha256.Sum256([]byte(label))
	return s[:]
}

// testAdminKeys 返回按 key_id 字典序排序的 3 把固定管理员密钥。
func testAdminKeys(t *testing.T, tag string) []*identity.AdminKey {
	t.Helper()
	labels := []string{"alice", "bob", "carol"}
	keys := make([]*identity.AdminKey, 0, len(labels))
	for i, lbl := range labels {
		seed := seed32(fmt.Sprintf("conformance/%s/admin-%s-%d", tag, lbl, i+1))
		k, err := identity.AdminKeyFromSeed(seed, lbl, pb.AdminRole_ADMIN_ROLE_ROOT)
		if err != nil {
			t.Fatalf("构造管理员密钥失败: %v", err)
		}
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && lessKeyID(keys[j].KeyID, keys[j-1].KeyID); j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func lessKeyID(a, b housekitchen.KeyID) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// testSet 构造一个固定字段的 AdminSet。
func testSet(t *testing.T, keys []*identity.AdminKey, generation uint64, prev *pb.AdminSet) *pb.AdminSet {
	t.Helper()
	policy := &pb.SigningPolicy{
		Threshold:               2,
		Total:                   uint32(len(keys)),
		Scheme:                  pb.SigningScheme_SIGNING_SCHEME_ED25519_MULTISIG,
		ClockSkewToleranceNanos: housekitchen.DefaultClockSkewNanos,
	}
	set := &pb.AdminSet{
		Generation:         generation,
		Policy:             policy,
		CreatedAtUnixNanos: conformance.VectorTime.UnixNano(),
	}
	for _, k := range keys {
		set.Keys = append(set.Keys, k.Public())
		policy.RootKeyIds = append(policy.RootKeyIds, housekitchen.PBKeyID(k.KeyID))
	}
	if prev != nil {
		h, err := housekitchen.AdminSetHash(prev)
		if err != nil {
			t.Fatalf("计算 prev hash 失败: %v", err)
		}
		set.PreviousSetHash = housekitchen.PBHash(h)
	}
	return set
}

func newRegistry(t *testing.T, set *pb.AdminSet) *registry.Registry {
	t.Helper()
	r, err := registry.New(set, registry.Options{Now: func() time.Time { return conformance.VectorTime }})
	if err != nil {
		t.Fatalf("registry.New 失败: %v", err)
	}
	return r
}

type bodyMutator func(*pb.SignedBody)

// broadcast 组装并按门限签名一条管理员广播。
// mutate 在"计算 canonical 之前"生效，因此产生的 msg_id 与签名都是自洽的
// ——这正是构造 N6/N7 这类"签名有效但语义非法"负例所必需的。
func broadcast(t *testing.T, set *pb.AdminSet, keys []*identity.AdminKey, n int, now time.Time, mutate bodyMutator) (*pb.Envelope, *pb.SignedBody, []byte) {
	t.Helper()
	body, err := registry.NewAdminBroadcast(set, vectorTopic, "conformance vector text", "text/plain", time.Hour, now)
	if err != nil {
		t.Fatalf("NewAdminBroadcast 失败: %v", err)
	}
	if mutate != nil {
		mutate(body)
	}
	canonical, err := registry.CanonicalForSigning(body)
	if err != nil {
		t.Fatalf("CanonicalForSigning 失败: %v", err)
	}
	if n > len(keys) {
		t.Fatalf("需要 %d 把密钥，只有 %d 把", n, len(keys))
	}
	if err := registry.FinalizeAdminBody(body, canonical, keys[:n], n, now); err != nil {
		t.Fatalf("FinalizeAdminBody 失败: %v", err)
	}
	return registry.WrapEnvelope(body, now), body, canonical
}

func nodeMsg(t *testing.T, author *identity.NodeIdentity, set *pb.AdminSet, signer *identity.NodeIdentity, now time.Time) (*pb.Envelope, *pb.SignedBody) {
	t.Helper()
	return nodeMsgWith(t, author, set, signer, now, nil)
}

// nodeMsgWith 允许在计算 canonical 之前改写正文，用于构造"签名自洽但语义非法"的节点消息。
func nodeMsgWith(t *testing.T, author *identity.NodeIdentity, set *pb.AdminSet, signer *identity.NodeIdentity, now time.Time, mutate bodyMutator) (*pb.Envelope, *pb.SignedBody) {
	t.Helper()
	body, err := registry.NewNodeMessage(author, pb.MessageKind_MESSAGE_KIND_NODE_ANNOUNCE, vectorTopic,
		&pb.Payload{Payload: &pb.Payload_Liveness{Liveness: &pb.Liveness{IssuedAtUnixNanos: now.UnixNano(), Nonce: 7}}},
		set, time.Hour, now)
	if err != nil {
		t.Fatalf("NewNodeMessage 失败: %v", err)
	}
	if mutate != nil {
		mutate(body)
	}
	canonical, err := registry.CanonicalForSigning(body)
	if err != nil {
		t.Fatalf("CanonicalForSigning 失败: %v", err)
	}
	if err := registry.FinalizeNodeBody(body, canonical, signer, now); err != nil {
		t.Fatalf("FinalizeNodeBody 失败: %v", err)
	}
	return registry.WrapEnvelope(body, now), body
}

func expectErrIs(t *testing.T, err error, target error, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: 期望被拒绝（%v），实际通过了", label, target)
	}
	if !errors.Is(err, target) {
		t.Fatalf("%s: 期望 errors.Is(%v)，实际错误为: %v", label, target, err)
	}
	t.Logf("%s: 正确拒绝 -> %v", label, err)
}

func expectRejected(t *testing.T, err error, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: 期望被拒绝，实际通过了", label)
	}
	t.Logf("%s: 正确拒绝 -> %v", label, err)
}

// knownIssue 在默认模式下把已确认的问题记录为日志（保持测试全绿），
// 在 FUTURECAST_STRICT=1 下把它变成失败，便于 Lead 一键看到所有已固化的缺陷。
func knownIssue(t *testing.T, id, severity, summary string) {
	t.Helper()
	t.Logf("已知问题 %s [%s]: %s", id, severity, summary)
	if os.Getenv("FUTURECAST_STRICT") == "1" {
		t.Errorf("STRICT 模式：已知问题 %s 仍然可复现 -> %s", id, summary)
	}
}

// ---------- 独立于 Go protobuf 运行时的 proto3 编码器 ----------

func putVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func tag(field, wire int) []byte { return putVarint(nil, uint64(field)<<3|uint64(wire)) }

func encVarintField(field int, v uint64) []byte {
	if v == 0 {
		return nil // proto3 默认值省略
	}
	return append(tag(field, 0), putVarint(nil, v)...)
}

func encBytesField(field int, b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := tag(field, 2)
	out = putVarint(out, uint64(len(b)))
	return append(out, b...)
}

func encStringField(field int, s string) []byte {
	if s == "" {
		return nil
	}
	return encBytesField(field, []byte(s))
}

func encMsgField(field int, msg []byte) []byte { return encBytesField(field, msg) }

func encHashLike(value []byte) []byte { return encBytesField(1, value) }

func encPolicy(p *pb.SigningPolicy) []byte {
	if p == nil {
		return nil
	}
	var out []byte
	out = append(out, encVarintField(1, uint64(p.GetThreshold()))...)
	out = append(out, encVarintField(2, uint64(p.GetTotal()))...)
	for _, id := range p.GetRootKeyIds() {
		out = append(out, encMsgField(3, encHashLike(id.GetValue()))...)
	}
	out = append(out, encVarintField(4, uint64(p.GetScheme()))...)
	out = append(out, encVarintField(5, uint64(p.GetClockSkewToleranceNanos()))...)
	return out
}

func encAdminKey(k *pb.AdminKey) []byte {
	var out []byte
	out = append(out, encMsgField(1, encHashLike(k.GetKeyId().GetValue()))...)
	out = append(out, encMsgField(2, encBytesField(1, k.GetPublicKey().GetEd25519()))...)
	out = append(out, encStringField(3, k.GetLabel())...)
	out = append(out, encVarintField(4, uint64(k.GetRole()))...)
	return out
}

func encTextPayload(tp *pb.TextPayload) []byte {
	var out []byte
	out = append(out, encStringField(1, tp.GetMediaType())...)
	out = append(out, encStringField(2, tp.GetBody())...)
	return out
}

// encSignedBody 手工编码 SignedBody：字段升序、proto3 默认值省略、
// 且按 CONTRACTS §5 规则清空 msg_id(field 4) 与 signers(field 12)。
// 注意：本函数完全不使用 google.golang.org/protobuf。
func encSignedBody(b *pb.SignedBody) []byte {
	var out []byte
	out = append(out, encVarintField(1, uint64(b.GetProtoVersion()))...)
	out = append(out, encVarintField(2, uint64(b.GetKind()))...)
	out = append(out, encStringField(3, b.GetTopic())...)
	// field 4 msg_id 被清空
	out = append(out, encVarintField(5, uint64(b.GetCreatedAtUnixNanos()))...)
	out = append(out, encVarintField(6, uint64(b.GetExpiresAtUnixNanos()))...)
	out = append(out, encBytesField(7, b.GetNonce())...)
	out = append(out, encVarintField(8, b.GetAdminSetGeneration())...)
	if h := housekitchen.GetHash(b.GetSignerSetHash()); !h.IsZero() {
		out = append(out, encMsgField(9, encHashLike(h.Bytes()))...)
	}
	if p := b.GetPolicy(); p != nil {
		out = append(out, encMsgField(10, encPolicy(p))...)
	}
	if n := housekitchen.GetNodeID(b.GetAuthor()); !n.IsZero() {
		out = append(out, encMsgField(11, encHashLike(n.Bytes()))...)
	}
	// field 12 signers 被清空
	if tp := b.GetPayload().GetText(); tp != nil {
		out = append(out, encMsgField(13, encMsgField(1, encTextPayload(tp)))...)
	}
	out = append(out, encVarintField(14, uint64(b.GetMaxHops()))...)
	out = append(out, encBytesField(15, b.GetAuthorPub())...)
	return out
}

// encAdminSet 手工编码 AdminSet（signers field 8 清空）。
func encAdminSet(s *pb.AdminSet) []byte {
	var out []byte
	out = append(out, encVarintField(1, s.GetGeneration())...)
	for _, k := range s.GetKeys() {
		out = append(out, encMsgField(2, encAdminKey(k))...)
	}
	if p := s.GetPolicy(); p != nil {
		out = append(out, encMsgField(3, encPolicy(p))...)
	}
	if h := housekitchen.GetHash(s.GetPreviousSetHash()); !h.IsZero() {
		out = append(out, encMsgField(4, encHashLike(h.Bytes()))...)
	}
	out = append(out, encVarintField(5, uint64(s.GetCreatedAtUnixNanos()))...)
	return out
}

// ---------- 独立实现的派生算法 ----------

func independentSignInput(canonical []byte, keyID housekitchen.KeyID, at int64) [32]byte {
	h := sha256.New()
	h.Write([]byte("futurecast/v1/signinput\x00"))
	h.Write(canonical)
	h.Write(keyID.Bytes())
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(at))
	h.Write(b[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// independentHKDF 是 RFC5869 HKDF-SHA256 的独立实现（salt 为空 = 32 个零字节）。
func independentHKDF(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	extract.Write(ikm)
	prk := extract.Sum(nil)

	var out, block []byte
	for i := byte(1); len(out) < length; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(block)
		m.Write(info)
		m.Write([]byte{i})
		block = m.Sum(nil)
		out = append(out, block...)
	}
	return out[:length]
}

func independentRelayTag(dailyKey []byte, msgID housekitchen.Hash, prev uint64) uint64 {
	m := hmac.New(sha256.New, dailyKey)
	m.Write([]byte(housekitchen.DomainRelayTag))
	m.Write(msgID.Bytes())
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], prev)
	m.Write(b[:])
	sum := m.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}

// requireEqual 比较并给出可读失败信息。
func requireEqual(t *testing.T, label string, want, got []byte) {
	t.Helper()
	if !bytes.Equal(want, got) {
		t.Fatalf("%s 不一致\n want=%x\n got =%x", label, want, got)
	}
}

func requireEqualString(t *testing.T, label, want, got string) {
	t.Helper()
	if want != got {
		t.Fatalf("%s 不一致\n want=%s\n got =%s", label, want, got)
	}
}

var _ = strings.Contains
var _ = fccrypto.PubKeySize
var _ = ed25519.PublicKeySize
var _ = proto.Clone

func mustKeyID(t *testing.T, s string) housekitchen.KeyID {
	t.Helper()
	k, err := housekitchen.KeyIDFromHex(s)
	if err != nil {
		t.Fatalf("KeyID 解析失败 %q: %v", s, err)
	}
	return k
}

func mustNodeID(t *testing.T, s string) housekitchen.NodeID {
	t.Helper()
	n, err := housekitchen.NodeIDFromHex(s)
	if err != nil {
		t.Fatalf("NodeID 解析失败 %q: %v", s, err)
	}
	return n
}

// reconstructSignedBody 仅用 vectors.json 里的字段级输入重建 SignedBody。
// full=true 时再填回 msg_id 与 signers（用于封存"完整正文"向量）。
func reconstructSignedBody(t *testing.T, v *conformance.Vectors, full bool) *pb.SignedBody {
	t.Helper()
	sb := v.SignedBody
	policy := &pb.SigningPolicy{
		Threshold:               sb.Policy.Threshold,
		Total:                   sb.Policy.Total,
		Scheme:                  pb.SigningScheme(sb.Policy.Scheme),
		ClockSkewToleranceNanos: sb.Policy.ClockSkewToleranceNanos,
	}
	for _, idHex := range sb.Policy.RootKeyIDsHex {
		policy.RootKeyIds = append(policy.RootKeyIds, housekitchen.PBKeyID(mustKeyID(t, idHex)))
	}
	body := &pb.SignedBody{
		ProtoVersion:       sb.ProtoVersion,
		Kind:               pb.MessageKind(sb.Kind),
		Topic:              sb.Topic,
		CreatedAtUnixNanos: sb.CreatedAtUnixNanos,
		ExpiresAtUnixNanos: sb.ExpiresAtUnixNanos,
		Nonce:              mustHex(t, sb.NonceHex),
		AdminSetGeneration: sb.AdminSetGeneration,
		SignerSetHash:      housekitchen.PBHash(mustHash(t, sb.SignerSetHashHex)),
		Policy:             policy,
		MaxHops:            sb.MaxHops,
	}
	if sb.PayloadText != nil {
		body.Payload = &pb.Payload{Payload: &pb.Payload_Text{Text: &pb.TextPayload{
			MediaType: sb.PayloadText.MediaType,
			Body:      sb.PayloadText.Body,
		}}}
	}
	if full {
		body.MsgId = housekitchen.PBHash(mustHash(t, sb.MsgIDHex))
		for _, s := range sb.Signers {
			body.Signers = append(body.Signers, &pb.Signature{
				KeyId:             housekitchen.PBKeyID(mustKeyID(t, s.KeyIDHex)),
				Signature:         mustHex(t, s.SignatureHex),
				SignedAtUnixNanos: s.SignedAtUnixNanos,
			})
		}
	}
	return body
}
