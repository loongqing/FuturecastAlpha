package directed

import (
	"fmt"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// NewDirectedBody 组装一条待签名的定向广播。
//
// 流程与普通管理员广播一致：先组装 → 拿规范化字节去离线收集门限签名 →
// Finalize 回填 signers 与 msg_id。
func NewDirectedBody(set *pb.AdminSet, recipients []Recipient, topic, mediaType, text string, now time.Time, ttl time.Duration) (*pb.DirectedBody, error) {
	if set == nil {
		return nil, fmt.Errorf("futurecast: AdminSet 为空")
	}
	setHash, err := housekitchen.AdminSetHash(set)
	if err != nil {
		return nil, err
	}
	// 先建好 body 并填齐全部"进签名覆盖范围"的字段，再交给 Seal 做加密封装。
	// 顺序反了会导致内层 AAD 基于不完整的摘要，收件人永远解不开。
	body := &pb.DirectedBody{
		AdminSetGeneration: set.GetGeneration(),
		SignerSetHash:      housekitchen.PBHash(setHash),
		Policy:             set.GetPolicy(),
	}
	return Seal(body, recipients, topic, mediaType, text, now, ttl)
}

// CanonicalForSigning 返回定向广播外层的规范化字节（待签名内容）。
func CanonicalForSigning(body *pb.DirectedBody) ([]byte, error) {
	return housekitchen.CanonicalDirectedBody(body)
}

// Finalize 收集门限签名并回填 msg_id 与 signers。
//
// signers 按 key_id 字典序排列，保证不同实现产出的信封字节一致。
func Finalize(body *pb.DirectedBody, canonical []byte, keys []*identity.AdminKey, threshold int, now time.Time) error {
	if len(keys) < threshold {
		return fmt.Errorf("%w: 需要 %d 把密钥，仅提供 %d", housekitchen.ErrThresholdNotMet, threshold, len(keys))
	}
	sigs := make([]*pb.Signature, 0, len(keys))
	for _, k := range keys {
		if k == nil {
			continue
		}
		sigs = append(sigs, k.Sign(canonical, now))
	}
	sortSignatures(sigs)
	body.Signers = sigs
	body.MsgId = housekitchen.PBHash(housekitchen.MsgIDFromCanonical(canonical))
	return nil
}

// Envelope 把定向正文包进路由信封。
func Envelope(body *pb.DirectedBody, now time.Time) *pb.Envelope {
	return &pb.Envelope{
		MsgId:              body.GetMsgId(),
		Hops:               0,
		MaxHops:            uint32(body.GetMaxHops()),
		FirstSeenUnixNanos: now.UnixNano(),
		DirectedBody:       body,
	}
}

// VerifyResult 是定向广播外层校验的结果。
type VerifyResult struct {
	// Generation 是使用的管理员集合代数。
	Generation uint64
	// Signers 是有效管理员签名者。
	Signers []housekitchen.KeyID
}

// VerifyBody 校验定向广播外层：内容寻址、时间窗、代数、集合绑定、门限签名。
//
// **中继与任何节点都能执行这个校验，且全程不需要解密正文。**
// 这正是把"可验签外层"与"机密内层"分开的价值。
func VerifyBody(body *pb.DirectedBody, set *pb.AdminSet, now time.Time) (VerifyResult, error) {
	var out VerifyResult
	if body == nil {
		return out, fmt.Errorf("futurecast: DirectedBody 为空")
	}
	if body.GetKind() != pb.MessageKind_MESSAGE_KIND_DIRECTED_BROADCAST {
		return out, fmt.Errorf("%w: kind 应为 DIRECTED_BROADCAST", housekitchen.ErrDirectedInvalid)
	}
	// 0. 协议版本
	if v := body.GetProtoVersion(); v < housekitchen.MinProtoVersion || v > housekitchen.ProtoVersion {
		return out, fmt.Errorf("%w: 正文声明版本 %d", housekitchen.ErrProtocolVersion, v)
	}
	// 1. 内容寻址（最先：篡改优先于一切语义检查）
	if err := housekitchen.VerifyDirectedMsgID(body); err != nil {
		return out, err
	}
	// 2. 时间窗
	created, exp := body.GetCreatedAtUnixNanos(), body.GetExpiresAtUnixNanos()
	if created <= 0 {
		return out, fmt.Errorf("%w: created_at 必须为正数", housekitchen.ErrClockSkew)
	}
	if exp <= created {
		return out, fmt.Errorf("%w: expires_at 必须晚于 created_at", housekitchen.ErrExpired)
	}
	nowNanos := now.UnixNano()
	if nowNanos > exp {
		return out, fmt.Errorf("%w: 定向广播已过期", housekitchen.ErrExpired)
	}
	if created > nowNanos+housekitchen.DefaultClockSkewNanos {
		return out, fmt.Errorf("%w: created_at 超前", housekitchen.ErrClockSkew)
	}
	// 3. 代数与集合绑定
	if set == nil {
		return out, fmt.Errorf("%w: 本地缺少该代 AdminSet", housekitchen.ErrGenerationMismatch)
	}
	if body.GetAdminSetGeneration() != set.GetGeneration() {
		return out, fmt.Errorf("%w: 消息代数 %d 与本地 %d 不符",
			housekitchen.ErrGenerationMismatch, body.GetAdminSetGeneration(), set.GetGeneration())
	}
	wantHash, err := housekitchen.AdminSetHash(set)
	if err != nil {
		return out, err
	}
	if housekitchen.GetHash(body.GetSignerSetHash()) != wantHash {
		return out, fmt.Errorf("%w: signer_set_hash 与本地集合不符", housekitchen.ErrSignerSetMismatch)
	}
	// 4. 收件人槽位结构性检查
	if len(body.GetRecipients()) == 0 {
		return out, fmt.Errorf("%w: 没有收件人槽位", housekitchen.ErrDirectedInvalid)
	}
	if int(body.GetRecipientCount()) != len(body.GetRecipients()) {
		return out, fmt.Errorf("%w: recipient_count 与槽位数不一致", housekitchen.ErrDirectedInvalid)
	}
	if len(body.GetContentNonce()) != NonceSize {
		return out, fmt.Errorf("%w: content_nonce 长度应为 %d", housekitchen.ErrDirectedInvalid, NonceSize)
	}
	// blind_salt 既是内层与各槽位的 AAD 绑定源，也是名单盲化的盐。
	// 必须在**外层**就检查长度：否则一条"重签过的短盐"消息能通过所有中继的
	// 外层校验并被全网转发，而只有收件人在解密时才发现打不开。
	if len(body.GetBlindSalt()) != BlindSaltSize {
		return out, fmt.Errorf("%w: blind_salt 长度应为 %d，实为 %d",
			housekitchen.ErrDirectedInvalid, BlindSaltSize, len(body.GetBlindSalt()))
	}
	if len(body.GetCiphertext()) == 0 {
		return out, fmt.Errorf("%w: 缺少密文", housekitchen.ErrDirectedInvalid)
	}
	// 5. 门限签名 —— 门限与 root_key_ids 一律取自**本地** AdminSet，
	//    绝不相信消息自带的 policy（同 registry 的 F4 修复）。
	canonical, err := housekitchen.CanonicalDirectedBody(body)
	if err != nil {
		return out, err
	}
	local := set.GetPolicy()
	if bodyPolicy := body.GetPolicy(); bodyPolicy != nil {
		if bodyPolicy.GetThreshold() != local.GetThreshold() || bodyPolicy.GetTotal() != local.GetTotal() {
			return out, fmt.Errorf("%w: 正文声明的门限 %d/%d 与本地 %d/%d 不符",
				housekitchen.ErrThresholdNotMet, bodyPolicy.GetThreshold(), bodyPolicy.GetTotal(),
				local.GetThreshold(), local.GetTotal())
		}
	}
	skew := time.Duration(local.GetClockSkewToleranceNanos())
	if skew <= 0 {
		skew = time.Duration(housekitchen.DefaultClockSkewNanos)
	}
	res, ok, err := crypto.MultisigVerify(canonical, body.GetSigners(), identity.RootKeyIDs(set),
		identity.PubKeyResolver(set), int(local.GetThreshold()), now, skew)
	if err != nil {
		return out, err
	}
	if !ok {
		return out, fmt.Errorf("%w: 定向广播需要 %d/%d 签名，实际有效 %d（被忽略 %d）",
			housekitchen.ErrThresholdNotMet, local.GetThreshold(), local.GetTotal(),
			res.Valid, len(res.Rejected))
	}
	out.Generation = body.GetAdminSetGeneration()
	out.Signers = res.Signers
	return out, nil
}

func sortSignatures(sigs []*pb.Signature) {
	for i := 1; i < len(sigs); i++ {
		for j := i; j > 0 && lessSig(sigs[j], sigs[j-1]); j-- {
			sigs[j], sigs[j-1] = sigs[j-1], sigs[j]
		}
	}
}

func lessSig(a, b *pb.Signature) bool {
	ka, kb := housekitchen.GetKeyID(a.GetKeyId()), housekitchen.GetKeyID(b.GetKeyId())
	for i := range ka {
		if ka[i] != kb[i] {
			return ka[i] < kb[i]
		}
	}
	return false
}
