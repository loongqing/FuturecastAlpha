package registry

import (
	"fmt"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// NewAdminBroadcast 组装一条待签名的管理员广播。
//
// 返回的 SignedBody 尚未填充 msg_id 与 signers —— 先把 canonical 字节交给各签名者，
// 收集齐后再用 FinalizeAdminBody 写回。
func NewAdminBroadcast(set *pb.AdminSet, topic, text, mediaType string, ttl time.Duration, now time.Time) (*pb.SignedBody, error) {
	if set == nil {
		return nil, fmt.Errorf("futurecast: AdminSet 为空")
	}
	setHash, err := housekitchen.AdminSetHash(set)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = time.Duration(housekitchen.DefaultMsgTTLNanos)
	}
	body := &pb.SignedBody{
		ProtoVersion:       housekitchen.ProtoVersion,
		Kind:               pb.MessageKind_MESSAGE_KIND_ADMIN_BROADCAST,
		Topic:              topic,
		CreatedAtUnixNanos: now.UnixNano(),
		ExpiresAtUnixNanos: now.Add(ttl).UnixNano(),
		Nonce:              housekitchen.RandomNonce(),
		AdminSetGeneration: set.GetGeneration(),
		SignerSetHash:      housekitchen.PBHash(setHash),
		Policy:             set.GetPolicy(),
		MaxHops:            housekitchen.DefaultMaxHops,
		Payload: &pb.Payload{Payload: &pb.Payload_Text{Text: &pb.TextPayload{
			MediaType: mediaType,
			Body:      text,
		}}},
	}
	return body, nil
}

// NewNodeMessage 组装一条由普通节点自签的消息（如节点动态、普通主题发言）。
func NewNodeMessage(author *identity.NodeIdentity, kind pb.MessageKind, topic string, payload *pb.Payload, set *pb.AdminSet, ttl time.Duration, now time.Time) (*pb.SignedBody, error) {
	if author == nil {
		return nil, fmt.Errorf("futurecast: 节点身份为空")
	}
	var setHash housekitchen.Hash
	var gen uint64
	var policy *pb.SigningPolicy
	if set != nil {
		h, err := housekitchen.AdminSetHash(set)
		if err != nil {
			return nil, err
		}
		setHash, gen, policy = h, set.GetGeneration(), set.GetPolicy()
	}
	if ttl <= 0 {
		ttl = time.Duration(housekitchen.DefaultMsgTTLNanos)
	}
	return &pb.SignedBody{
		ProtoVersion:       housekitchen.ProtoVersion,
		Kind:               kind,
		Topic:              topic,
		CreatedAtUnixNanos: now.UnixNano(),
		ExpiresAtUnixNanos: now.Add(ttl).UnixNano(),
		Nonce:              housekitchen.RandomNonce(),
		AdminSetGeneration: gen,
		SignerSetHash:      housekitchen.PBHash(setHash),
		Policy:             policy,
		Author:             housekitchen.PBNodeID(author.ID),
		AuthorPub:          author.Pub,
		MaxHops:            housekitchen.DefaultMaxHops,
		Payload:            payload,
	}, nil
}

// CanonicalForSigning 返回待签名正文的规范化字节。
func CanonicalForSigning(body *pb.SignedBody) ([]byte, error) {
	return housekitchen.CanonicalSignedBody(body)
}

// FinalizeAdminBody 收集门限签名并写回 msg_id 与 signers。
//
// signers 的顺序按 key_id 字典序排列，保证不同节点对同一条消息算出同样的信封字节。
func FinalizeAdminBody(body *pb.SignedBody, canonical []byte, keys []*identity.AdminKey, threshold int, now time.Time) error {
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
	msgID := housekitchen.MsgIDFromCanonical(canonical)
	body.MsgId = housekitchen.PBHash(msgID)
	return nil
}

// FinalizeNodeBody 用节点身份自签并写回 msg_id 与 signers。
func FinalizeNodeBody(body *pb.SignedBody, canonical []byte, author *identity.NodeIdentity, now time.Time) error {
	if author == nil {
		return fmt.Errorf("futurecast: 节点身份为空")
	}
	keyID := housekitchen.KeyIDFromPub(author.Pub)
	sig := crypto.SignBody(author.Priv, canonical, keyID, now)
	body.Signers = []*pb.Signature{sig}
	body.MsgId = housekitchen.PBHash(housekitchen.MsgIDFromCanonical(canonical))
	return nil
}

func sortSignatures(sigs []*pb.Signature) {
	for i := 1; i < len(sigs); i++ {
		for j := i; j > 0 && lessSig(sigs[j], sigs[j-1]); j-- {
			sigs[j], sigs[j-1] = sigs[j-1], sigs[j]
		}
	}
}

func lessSig(a, b *pb.Signature) bool {
	ka := housekitchen.GetKeyID(a.GetKeyId())
	kb := housekitchen.GetKeyID(b.GetKeyId())
	for i := range ka {
		if ka[i] != kb[i] {
			return ka[i] < kb[i]
		}
	}
	return false
}

// WrapEnvelope 用 SignedBody 组装一个全新的信封（hops=0）。
func WrapEnvelope(body *pb.SignedBody, now time.Time) *pb.Envelope {
	return &pb.Envelope{
		MsgId:              body.GetMsgId(),
		Hops:               0,
		MaxHops:            uint32(body.GetMaxHops()),
		FirstSeenUnixNanos: now.UnixNano(),
		Body:               body,
	}
}

// SignAdminSet 用旧集合的密钥为一组新 AdminSet 收集轮换签名。
func SignAdminSet(next *pb.AdminSet, prev *pb.AdminSet, keys []*identity.AdminKey, threshold int, now time.Time) error {
	canonical, err := housekitchen.CanonicalAdminSet(next)
	if err != nil {
		return err
	}
	prevHash, err := housekitchen.AdminSetHash(prev)
	if err != nil {
		return err
	}
	next.PreviousSetHash = housekitchen.PBHash(prevHash)
	// previous_set_hash 变更会改变规范化字节，必须重算。
	canonical, err = housekitchen.CanonicalAdminSet(next)
	if err != nil {
		return err
	}
	// signers 只做签名收集，不在这里判断门限：
	// 门限是否达标属于"验证"职责，由 ValidateAdminSet / Install 判定。
	sigs := make([]*pb.Signature, 0, len(keys))
	for _, k := range keys {
		if k == nil {
			continue
		}
		sigs = append(sigs, k.Sign(canonical, now))
	}
	sortSignatures(sigs)
	next.Signers = sigs
	return nil
}
