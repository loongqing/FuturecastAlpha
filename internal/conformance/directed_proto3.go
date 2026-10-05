// 本文件提供一套**不依赖 google.golang.org/protobuf** 的最小 proto3 编码器，
// 以及独立于 golang.org/x/crypto 的 HKDF-SHA256 / HMAC-SHA256 实现。
//
// 它们只服务于"复算并逐字节比对"：Build() 用它们独立算出
// DIRECTED_BYTES / KERNEL_BYTES / blind_key / recipient_tag，再与冻结实现
// （housekitchen.CanonicalXxx + crypto.HKDF）的输出逐字节比对。任何不一致都会让
// Build() 直接失败，从而保证 vectors.json 里的每个十六进制值都有两个独立来源。
//
// 编码规则与 housekitchen/canonical.go 的 proto.MarshalOptions{Deterministic:true}
// 完全一致：字段号升序、proto3 默认值省略、被清空的字段不出现。
package conformance

import (
	"crypto/hmac"
	"crypto/sha256"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// ---------- 最小 proto3 写入原语 ----------

func pbPutVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func pbTag(field, wire int) []byte {
	return pbPutVarint(nil, uint64(field)<<3|uint64(wire))
}

// pbVarintField 编码 varint 字段；proto3 默认值 0 一律省略。
func pbVarintField(field int, v uint64) []byte {
	if v == 0 {
		return nil
	}
	return append(pbTag(field, 0), pbPutVarint(nil, v)...)
}

// pbBytesField 编码 length-delimited 字段；空字节串一律省略。
func pbBytesField(field int, b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := pbTag(field, 2)
	out = pbPutVarint(out, uint64(len(b)))
	return append(out, b...)
}

func pbStringField(field int, s string) []byte {
	if s == "" {
		return nil
	}
	return pbBytesField(field, []byte(s))
}

func pbMsgField(field int, msg []byte) []byte {
	if len(msg) == 0 {
		return nil
	}
	return pbBytesField(field, msg)
}

// pbHashLike 编码 housekitchen 的定长 ID 包装（Hash / KeyID / NodeID 的 shape
// 都是 `message X { bytes value = 1; }`）。
func pbHashLike(value []byte) []byte {
	return pbBytesField(1, value)
}

// pbPolicyProto3 编码 SigningPolicy（common.proto）。
func pbPolicyProto3(p *pb.SigningPolicy) []byte {
	if p == nil {
		return nil
	}
	var out []byte
	out = append(out, pbVarintField(1, uint64(p.GetThreshold()))...)
	out = append(out, pbVarintField(2, uint64(p.GetTotal()))...)
	for _, id := range p.GetRootKeyIds() {
		out = append(out, pbMsgField(3, pbHashLike(id.GetValue()))...)
	}
	out = append(out, pbVarintField(4, uint64(p.GetScheme()))...)
	out = append(out, pbVarintField(5, uint64(p.GetClockSkewToleranceNanos()))...)
	return out
}

// ---------- 附录 E 的三个消息 ----------

// EncodeDirectRecipientProto3 编码 DirectRecipient{eph_pub=1, wrapped_key=2, recipient_tag=3}。
func EncodeDirectRecipientProto3(r *pb.DirectRecipient) []byte {
	if r == nil {
		return nil
	}
	var out []byte
	out = append(out, pbBytesField(1, r.GetEphPub())...)
	out = append(out, pbBytesField(2, r.GetWrappedKey())...)
	out = append(out, pbBytesField(3, r.GetRecipientTag())...)
	return out
}

// EncodeDirectedBodyProto3 编码 DirectedBody 的**待签名部分**：
// 跳过 msg_id(3) 与 signers(11)，其余字段按字段号升序，proto3 默认值省略。
func EncodeDirectedBodyProto3(b *pb.DirectedBody) []byte {
	if b == nil {
		return nil
	}
	var out []byte
	out = append(out, pbVarintField(1, uint64(b.GetProtoVersion()))...)
	out = append(out, pbVarintField(2, uint64(b.GetKind()))...)
	// field 3 msg_id：派生值，清空
	out = append(out, pbVarintField(4, uint64(b.GetCreatedAtUnixNanos()))...)
	out = append(out, pbVarintField(5, uint64(b.GetExpiresAtUnixNanos()))...)
	out = append(out, pbBytesField(6, b.GetNonce())...)
	out = append(out, pbVarintField(7, b.GetAdminSetGeneration())...)
	if h := b.GetSignerSetHash(); h != nil && len(h.GetValue()) > 0 {
		out = append(out, pbMsgField(8, pbHashLike(h.GetValue()))...)
	}
	out = append(out, pbMsgField(9, pbPolicyProto3(b.GetPolicy()))...)
	out = append(out, pbVarintField(10, uint64(b.GetMaxHops()))...)
	// field 11 signers：签名本体，清空
	for _, r := range b.GetRecipients() {
		out = append(out, pbMsgField(12, EncodeDirectRecipientProto3(r))...)
	}
	out = append(out, pbBytesField(13, b.GetCiphertext())...)
	out = append(out, pbBytesField(14, b.GetContentNonce())...)
	out = append(out, pbVarintField(15, uint64(b.GetRecipientCount()))...)
	out = append(out, pbBytesField(16, b.GetBlindSalt())...)
	return out
}

// EncodeDirectedKernelProto3 编码 DirectedKernel{topic=1, media_type=2, body=3,
// created_at=4, expires_at=5, nonce=6}。（field 7 已废弃保留，编码时不得出现）
func EncodeDirectedKernelProto3(k *pb.DirectedKernel) []byte {
	if k == nil {
		return nil
	}
	var out []byte
	out = append(out, pbStringField(1, k.GetTopic())...)
	out = append(out, pbStringField(2, k.GetMediaType())...)
	out = append(out, pbStringField(3, k.GetBody())...)
	out = append(out, pbVarintField(4, uint64(k.GetCreatedAtUnixNanos()))...)
	out = append(out, pbVarintField(5, uint64(k.GetExpiresAtUnixNanos()))...)
	out = append(out, pbBytesField(6, k.GetNonce())...)
	return out
}

// ---------- 独立实现的 HKDF-SHA256 与 HMAC-SHA256 ----------

// hkdfSHA256 是 RFC5869 HKDF-SHA256 的独立实现（salt 为空 = RFC5869 默认的
// HashLen 个 0x00，即 32 字节零）。
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
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

// hmacSHA256 是标准库 HMAC-SHA256 的薄封装（用于独立复算 recipient_tag）。
func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
