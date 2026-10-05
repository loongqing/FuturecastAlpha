package housekitchen

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// 本文件定义协议中所有"被签名/被哈希"的规范化（canonical）编码。
//
// 规则：
//  1. 域分隔前缀 + protobuf 确定性序列化。
//  2. 签名与摘要字段在编码前一律清空，避免自引用（签名覆盖签名）。
//  3. 任何实现（Go/Rust/Python...）只要遵守同样规则就能互通。
//
// 签名覆盖的字段是 SignedBody 的全部字段，**除** msg_id 与 signers。
// 因此中转节点可以自由改写信封（Envelope）与签名列表的呈现顺序，而不会破坏签名。

// CanonicalSignedBody 返回 SignedBody 的规范化字节。
// 编码前清空 msg_id 与 signers；cipher 属于 Envelope 层，不在此处。
func CanonicalSignedBody(b *pb.SignedBody) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("futurecast: SignedBody 为空")
	}
	clone, ok := proto.Clone(b).(*pb.SignedBody)
	if !ok {
		return nil, fmt.Errorf("futurecast: SignedBody 克隆失败")
	}
	clone.MsgId = nil
	clone.Signers = nil

	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("futurecast: SignedBody 序列化失败: %w", err)
	}
	out := make([]byte, 0, len(DomainSignedBody)+len(raw))
	out = append(out, DomainSignedBody...)
	out = append(out, raw...)
	return out, nil
}

// CanonicalAdminSet 返回 AdminSet 的规范化字节，用于 signer_set_hash 与轮换链。
func CanonicalAdminSet(s *pb.AdminSet) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("futurecast: AdminSet 为空")
	}
	clone, ok := proto.Clone(s).(*pb.AdminSet)
	if !ok {
		return nil, fmt.Errorf("futurecast: AdminSet 克隆失败")
	}
	// 轮换签名覆盖 AdminSet 本体，必须清空 signers 以避免自引用。
	clone.Signers = nil
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("futurecast: AdminSet 序列化失败: %w", err)
	}
	out := make([]byte, 0, len(DomainAdminSet)+len(raw))
	out = append(out, DomainAdminSet...)
	out = append(out, raw...)
	return out, nil
}

// AdminSetHash 返回 SHA-256(CanonicalAdminSet)。
func AdminSetHash(s *pb.AdminSet) (Hash, error) {
	b, err := CanonicalAdminSet(s)
	if err != nil {
		return Hash{}, err
	}
	return Sum256(b), nil
}

// MsgIDFromCanonical 由规范化字节派生 msg_id。
func MsgIDFromCanonical(canonical []byte) Hash {
	return HashOf([]byte(DomainMsgID), canonical)
}

// MsgID 计算给定 SignedBody 的 msg_id。
func MsgID(b *pb.SignedBody) (Hash, error) {
	c, err := CanonicalSignedBody(b)
	if err != nil {
		return Hash{}, err
	}
	return MsgIDFromCanonical(c), nil
}

// VerifyMsgID 校验 body.msg_id 与重新计算的摘要是否一致。
func VerifyMsgID(b *pb.SignedBody) error {
	want, err := MsgID(b)
	if err != nil {
		return err
	}
	got := GetHash(b.GetMsgId())
	if got != want {
		return fmt.Errorf("%w: 期望 %s，实为 %s", ErrMsgIDMismatch, want.Short(), got.Short())
	}
	return nil
}

// SignInput 计算单个签名者的签名输入。
//
//	SIGN_INPUT = SHA-256( DomainSignInput || SIGNED_BYTES || signer_key_id || uint64_be(signed_at) )
//
// 绑定 key_id 与 signed_at 的目的是防止签名搬运：
// 同一份签名无法被搬到另一条消息，也无法被复制成两个不同 signer 的签名来凑门限。
func SignInput(canonical []byte, keyID KeyID, signedAtUnixNanos int64) Hash {
	return HashOf([]byte(DomainSignInput), canonical, keyID.Bytes(), Uint64BE(uint64(signedAtUnixNanos)))
}

// CanonicalNodeAnnounce 返回 NodeAnnounce 的规范化字节（清空 self_signature）。
func CanonicalNodeAnnounce(a *pb.NodeAnnounce) ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("futurecast: NodeAnnounce 为空")
	}
	clone, ok := proto.Clone(a).(*pb.NodeAnnounce)
	if !ok {
		return nil, fmt.Errorf("futurecast: NodeAnnounce 克隆失败")
	}
	clone.SelfSignature = nil
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("futurecast: NodeAnnounce 序列化失败: %w", err)
	}
	return append([]byte(DomainNodeAnnounce), raw...), nil
}

// CanonicalPeerExchange 返回 PeerExchange 的规范化字节（清空 self_signature）。
func CanonicalPeerExchange(p *pb.PeerExchange) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("futurecast: PeerExchange 为空")
	}
	clone, ok := proto.Clone(p).(*pb.PeerExchange)
	if !ok {
		return nil, fmt.Errorf("futurecast: PeerExchange 克隆失败")
	}
	clone.SelfSignature = nil
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("futurecast: PeerExchange 序列化失败: %w", err)
	}
	return append([]byte(DomainPeerExchange), raw...), nil
}

// CanonicalHello 返回 Hello 的规范化字节（清空 self_signature）。
func CanonicalHello(h *pb.Hello) ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("futurecast: Hello 为空")
	}
	clone, ok := proto.Clone(h).(*pb.Hello)
	if !ok {
		return nil, fmt.Errorf("futurecast: Hello 克隆失败")
	}
	clone.SelfSignature = nil
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("futurecast: Hello 序列化失败: %w", err)
	}
	return append([]byte(DomainHello), raw...), nil
}

// CanonicalDirectedBody 返回定向广播外层正文的规范化字节。
//
// 编码前清空 msg_id 与 signers —— 与 SignedBody 同一套规则。
// 中继可以验证门限签名，但**读不到正文**：正文在 ciphertext 里。
func CanonicalDirectedBody(b *pb.DirectedBody) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("futurecast: DirectedBody 为空")
	}
	clone, ok := proto.Clone(b).(*pb.DirectedBody)
	if !ok {
		return nil, fmt.Errorf("futurecast: DirectedBody 克隆失败")
	}
	clone.MsgId = nil
	clone.Signers = nil
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("futurecast: DirectedBody 序列化失败: %w", err)
	}
	out := make([]byte, 0, len(DomainDirectedBody)+len(raw))
	out = append(out, DomainDirectedBody...)
	out = append(out, raw...)
	return out, nil
}

// DirectedMsgID 计算定向广播外层正文的 msg_id。
func DirectedMsgID(b *pb.DirectedBody) (Hash, error) {
	c, err := CanonicalDirectedBody(b)
	if err != nil {
		return Hash{}, err
	}
	return MsgIDFromCanonical(c), nil
}

// VerifyDirectedMsgID 校验定向广播外层的 msg_id。
func VerifyDirectedMsgID(b *pb.DirectedBody) error {
	want, err := DirectedMsgID(b)
	if err != nil {
		return err
	}
	if GetHash(b.GetMsgId()) != want {
		return fmt.Errorf("%w: 期望 %s，实为 %s", ErrMsgIDMismatch, want.Short(), GetHash(b.GetMsgId()).Short())
	}
	return nil
}

// CanonicalDirectedKernel 返回定向广播内层机密的规范化字节。
func CanonicalDirectedKernel(k *pb.DirectedKernel) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("futurecast: DirectedKernel 为空")
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("futurecast: DirectedKernel 序列化失败: %w", err)
	}
	return append([]byte(DomainDirectedKernel), raw...), nil
}

// CanonicalSealedPayload 返回 SealedPayload 的规范化字节，用于提交方自证。
func CanonicalSealedPayload(s *pb.SealedPayload) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("futurecast: SealedPayload 为空")
	}
	clone, ok := proto.Clone(s).(*pb.SealedPayload)
	if !ok {
		return nil, fmt.Errorf("futurecast: SealedPayload 克隆失败")
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("futurecast: SealedPayload 序列化失败: %w", err)
	}
	return append([]byte(DomainSealedPayload), raw...), nil
}

// CanonicalEnvelope 返回 Envelope 的规范化字节，用于整包内容校验与去重。
func CanonicalEnvelope(e *pb.Envelope) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("futurecast: Envelope 为空")
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("futurecast: Envelope 序列化失败: %w", err)
	}
	return raw, nil
}

// ---------- 协议对象 ↔ 定长 ID 的转换 ----------

// GetHash 从 proto Hash 取值，nil 或长度不符时返回零值。
func GetHash(h *pb.Hash) Hash {
	var out Hash
	if h == nil {
		return out
	}
	if len(h.Value) != HashSize {
		return out
	}
	copy(out[:], h.Value)
	return out
}

// GetKeyID 从 proto KeyID 取值。
func GetKeyID(k *pb.KeyID) KeyID {
	var out KeyID
	if k == nil {
		return out
	}
	if len(k.Value) != KeyIDSize {
		return out
	}
	copy(out[:], k.Value)
	return out
}

// GetNodeID 从 proto NodeID 取值。
func GetNodeID(n *pb.NodeID) NodeID {
	var out NodeID
	if n == nil {
		return out
	}
	if len(n.Value) != NodeIDSize {
		return out
	}
	copy(out[:], n.Value)
	return out
}

// PBHash 把 Hash 转成 proto 表示。
func PBHash(h Hash) *pb.Hash { return &pb.Hash{Value: h.Bytes()} }

// PBKeyID 把 KeyID 转成 proto 表示。
func PBKeyID(k KeyID) *pb.KeyID { return &pb.KeyID{Value: k.Bytes()} }

// PBNodeID 把 NodeID 转成 proto 表示。
func PBNodeID(n NodeID) *pb.NodeID { return &pb.NodeID{Value: n.Bytes()} }
