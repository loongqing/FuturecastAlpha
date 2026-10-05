// Package directed 实现"定向广播"：只有指定收件人能解密的管理员广播。
//
// 与 sealed 模式的区别：
//   - sealed 隐藏的是**发送方**（谁提交的、超管在哪台机器）；
//   - directed 隐藏的是**接收方名单与内容**（除了被点名的人，谁都读不到）。
//
// 两层结构（关键设计）：
//
//	DirectedBody   明文 + 超管门限签名 → 任何节点都能验签，中继无需解密
//	  ciphertext   用一次性 content_key 加密的 DirectedKernel → 只有收件人能解
//	  recipients[] content_key 的逐收件人封装（X25519 + HKDF + AES-GCM）
//
// 名单隐私：消息里**不出现**任何收件人的 NodeID 或公钥。每个槽位只有
// 随机 eph_pub、密文 wrapped_key，以及由 (content_key, blind_key) 派生的
// recipient_tag。只有真正持有私钥、能算出自己 tag 的收件人才认得出自己的槽位，
// 外界无法枚举也无法反查名单。
package directed

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// ContentKeySize 是内容密钥长度。
const ContentKeySize = 32

// BlindSaltSize 是盲化盐长度。
const BlindSaltSize = 16

// NonceSize 是内层 AES-GCM nonce 长度。
const NonceSize = 12

// Recipient 是一个收件人。
type Recipient struct {
	// NodeID 是收件人标识（= SHA-256(ed25519_pub)）。
	NodeID housekitchen.NodeID
	// Ed25519Pub 是收件人的签名公钥；其 X25519 公钥由它确定性派生。
	Ed25519Pub []byte
}

// RecipientX25519 由收件人的 ed25519 公钥派生其 X25519 加密公钥。
//
// 这样超管只需知道对方的 node_id / ed25519 公钥，不必额外交换加密密钥。
func RecipientX25519(r Recipient) ([]byte, error) {
	if housekitchen.NodeIDFromPub(r.Ed25519Pub) != r.NodeID {
		return nil, fmt.Errorf("%w: 收件人公钥与 node_id 不匹配", housekitchen.ErrPeerIDMismatch)
	}
	return crypto.Ed25519ToX25519(r.Ed25519Pub)
}

// blindedKey 由内容密钥与盲化盐派生本消息专用的盲化密钥。
//
// 每消息独立随机 → 同一个收件人在不同消息里的 tag 完全不同，
// 观察者无法跨消息关联"这条和那条都发给了同一个节点"。
func blindedKey(contentKey, blindSalt []byte) ([]byte, error) {
	return crypto.HKDF(contentKey, blindSalt, housekitchen.DomainDirectedBlind, 32)
}

// recipientTag 计算某个收件人在本合同中的槽位标签。
//
//	tag = HMAC-SHA256( blindKey, "futurecast/v1/dirtag\0" || nodeID )[:16]
//
// 只有能由 content_key 派生出 blindKey 的人才能算出自己的 tag —— 也就是只有
// 真正的收件人。中继与外部观察者都拿不到 content_key。
func recipientTag(blindKey []byte, nodeID housekitchen.NodeID) []byte {
	mac := hmac.New(sha256.New, blindKey)
	mac.Write([]byte(housekitchen.DomainDirectedTag))
	mac.Write(nodeID.Bytes())
	return mac.Sum(nil)[:16]
}

// wrapKey 用"收件人 X25519 公钥 + 临时私钥"导出的密钥封装 content_key。
//
//	wrap_key = HKDF-SHA256( X25519(eph_priv, recipient_pub), salt=nil, info="fc/v1/directedwrap", 32 )
func wrapKey(ephPriv, recipientX25519Pub, contentKey, aad []byte) ([]byte, error) {
	shared, err := crypto.X25519Shared(ephPriv, recipientX25519Pub)
	if err != nil {
		return nil, err
	}
	wk, err := crypto.HKDF(shared, nil, housekitchen.DomainDirectedWrap, 32)
	if err != nil {
		return nil, err
	}
	return crypto.SealAEAD(wk, contentKey, aad)
}

// unwrapKey 解出 content_key。
func unwrapKey(selfX25519Scalar, ephPub, wrapped, aad []byte) ([]byte, error) {
	shared, err := crypto.X25519Shared(selfX25519Scalar, ephPub)
	if err != nil {
		return nil, err
	}
	wk, err := crypto.HKDF(shared, nil, housekitchen.DomainDirectedWrap, 32)
	if err != nil {
		return nil, err
	}
	return crypto.OpenAEAD(wk, wrapped, aad)
}

// innerAAD 是内层密文的关联数据。
//
// 绑定与「外层摘要」无关，只绑定本消息独有的随机盐与固定的域/主题串。
//
// 为什么不用外层摘要：摘要覆盖 ciphertext 本身，而 ciphertext 又要用摘要做 AAD，
// 这是循环依赖 —— 先算摘要就得先有密文，先有密文就得先有 AAD。
// 硬用"先算一次不完整摘要"的做法会让收件人重算时对不上（实现中真实踩过）。
//
// 用 blind_salt 替代是正确且更强的：
//   - blind_salt 是本消息独有随机值，且**在门限签名的覆盖范围内**，
//     因此中继无法把它改成另一条消息的值；
//   - 且不需要"先解密才知道 AAD"（topic 不用进 AAD）。
func innerAAD(blindSalt []byte) []byte {
	return append([]byte(housekitchen.DomainDirectedKernel), blindSalt...)
}

// wrapAAD 是 wrapped_key 的关联数据：绑定本消息的随机盐与槽位序号。
//
// 作用：防止把某个收件人的封装块搬到同一消息的其它槽位上（序号参与），
// 也防止跨消息复用（盐每消息不同且被签名覆盖）。
func wrapAAD(blindSalt []byte, index int) []byte {
	out := append([]byte("futurecast/v1/dirwrap\x00"), blindSalt...)
	return append(out, housekitchen.Uint64BE(uint64(index))...)
}

// Seal 为给定收件人集合构造定向广播的内层与密钥封装。
//
// **调用顺序很关键**：body 必须在调用本函数之前就把所有会进签名覆盖范围的字段
// （admin_set_generation / signer_set_hash / policy 等）填好。
// 因为这里算出的外层摘要会被写进内层与每个槽位的 AAD，
// 若之后再有字段变化，收件人重算的摘要就对不上、全部解不开
// —— 这是实现中真实踩过的坑，务必保持"先填字段、后封装、最后签名"的顺序。
func Seal(body *pb.DirectedBody, recipients []Recipient, topic, mediaType, text string, now time.Time, ttl time.Duration) (*pb.DirectedBody, error) {
	if body == nil {
		return nil, fmt.Errorf("futurecast: DirectedBody 为空")
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("futurecast: 定向广播至少需要一个收件人")
	}
	if ttl <= 0 {
		ttl = time.Duration(housekitchen.DefaultMsgTTLNanos)
	}
	// 封装所需的全部字段必须先就位。
	body.ProtoVersion = housekitchen.ProtoVersion
	body.Kind = pb.MessageKind_MESSAGE_KIND_DIRECTED_BROADCAST
	body.CreatedAtUnixNanos = now.UnixNano()
	body.ExpiresAtUnixNanos = now.Add(ttl).UnixNano()
	body.Nonce = housekitchen.RandomNonce()
	body.MaxHops = housekitchen.DefaultMaxHops
	body.BlindSalt = housekitchen.RandomBytes(BlindSaltSize)
	body.RecipientCount = uint32(len(recipients))
	body.MsgId = nil
	body.Signers = nil

	// AAD 只依赖 blind_salt（每消息随机、且被签名覆盖），
	// 因此不存在"摘要 ↔ 密文"的循环依赖，也不需要任何"先算一次"的技巧。
	salt := body.GetBlindSalt()

	// 内层机密。
	kernel := &pb.DirectedKernel{
		Topic:              topic,
		MediaType:          mediaType,
		Body:               text,
		CreatedAtUnixNanos: now.UnixNano(),
		ExpiresAtUnixNanos: now.Add(ttl).UnixNano(),
		Nonce:              housekitchen.RandomNonce(),
	}
	kernelBytes, err := housekitchen.CanonicalDirectedKernel(kernel)
	if err != nil {
		return nil, err
	}

	contentKey := housekitchen.RandomBytes(ContentKeySize)
	blinded, err := blindedKey(contentKey, body.GetBlindSalt())
	if err != nil {
		return nil, err
	}
	ct, err := crypto.SealAEAD(contentKey, kernelBytes, innerAAD(salt))
	if err != nil {
		return nil, err
	}
	// crypto.SealAEAD 输出 nonce||ct，拆成两个字段。
	body.ContentNonce = ct[:NonceSize]
	body.Ciphertext = ct[NonceSize:]

	for i, r := range recipients {
		xPub, err := RecipientX25519(r)
		if err != nil {
			return nil, err
		}
		eph, err := crypto.GenerateX25519()
		if err != nil {
			return nil, err
		}
		wrapped, err := wrapKey(eph.Private, xPub, contentKey, wrapAAD(salt, i))
		if err != nil {
			return nil, err
		}
		body.Recipients = append(body.Recipients, &pb.DirectRecipient{
			EphPub:       eph.Public,
			WrappedKey:   wrapped,
			RecipientTag: recipientTag(blinded, r.NodeID),
		})
	}
	return body, nil
}

// OpenResult 是收件人成功解密的结果。
type OpenResult struct {
	// Kernel 是解出的机密内容。
	Kernel *pb.DirectedKernel
	// Slot 是自己所在的槽位序号。
	Slot int
}

// Open 尝试以本节点身份解密一条定向广播。
//
// 返回的 error 包装 housekitchen.ErrNotAuthorized 表示"本节点不在收件人名单里" ——
// 这是一个正常结果（网络上绝大多数节点都会得到它），不是错误。
func Open(selfSeed []byte, selfNodeID housekitchen.NodeID, body *pb.DirectedBody) (*OpenResult, error) {
	if body == nil {
		return nil, fmt.Errorf("futurecast: DirectedBody 为空")
	}
	if len(body.GetRecipients()) == 0 {
		return nil, fmt.Errorf("futurecast: 定向广播没有收件人槽位")
	}
	if int(body.GetRecipientCount()) != len(body.GetRecipients()) {
		return nil, fmt.Errorf("%w: recipient_count=%d 与槽位数 %d 不一致",
			housekitchen.ErrDirectedInvalid, body.GetRecipientCount(), len(body.GetRecipients()))
	}
	selfScalar, err := crypto.Ed25519SeedToX25519Scalar(selfSeed)
	if err != nil {
		return nil, err
	}
	if len(body.GetBlindSalt()) != BlindSaltSize {
		return nil, fmt.Errorf("%w: blind_salt 长度应为 %d", housekitchen.ErrDirectedInvalid, BlindSaltSize)
	}
	salt := body.GetBlindSalt()
	for i, slot := range body.GetRecipients() {
		contentKey, err := unwrapKey(selfScalar, slot.GetEphPub(), slot.GetWrappedKey(), wrapAAD(salt, i))
		if err != nil {
			continue // 不是给我的，继续试下一个槽位
		}
		blinded, err := blindedKey(contentKey, body.GetBlindSalt())
		if err != nil {
			continue
		}
		// 关键一致性校验：槽位 tag 必须等于本节点按该 content_key 算出的 tag。
		// 少了这一步，构造错误槽位的攻击者可以让人以为消息是发给别人的。
		//
		// 注意必须用**本节点自己的 NodeID** 参与计算 —— 封端也是用收件人的
		// NodeID 算的；用从公钥推出来的那个值会算不出同一个 tag。
		want := recipientTag(blinded, selfNodeID)
		if !housekitchen.ConstantTimeEqual(want, slot.GetRecipientTag()) {
			continue
		}
		kernel, err := openKernel(contentKey, body, salt)
		if err != nil {
			continue
		}
		return &OpenResult{Kernel: kernel, Slot: i}, nil
	}
	return nil, fmt.Errorf("%w: 本节点不在该定向广播的收件人名单内", housekitchen.ErrNotAuthorized)
}

// openKernel 用已解出的 content_key 解开内层机密。
//
// 内层与"本条消息"的绑定由 AAD 里的 blind_salt 保证（每消息随机且被签名覆盖），
// 因此这里不需要再比较外层摘要 —— 也就不存在摘要与密文的循环依赖。
func openKernel(contentKey []byte, body *pb.DirectedBody, blindSalt []byte) (*pb.DirectedKernel, error) {
	sealed := append(append([]byte(nil), body.GetContentNonce()...), body.GetCiphertext()...)
	plain, err := crypto.OpenAEAD(contentKey, sealed, innerAAD(blindSalt))
	if err != nil {
		return nil, err
	}
	// plain 是 housekitchen.CanonicalDirectedKernel 的输出，即
	// "域前缀 || deterministic_proto(kernel)"。域前缀不是合法 protobuf，
	// 必须先剥掉再解析（这里踩过一次：直接 Unmarshal 会报 invalid wire-format）。
	const prefix = housekitchen.DomainDirectedKernel
	if len(plain) < len(prefix) || string(plain[:len(prefix)]) != prefix {
		return nil, fmt.Errorf("%w: 内层缺少域前缀", housekitchen.ErrDirectedInvalid)
	}
	kernel := &pb.DirectedKernel{}
	if err := proto.Unmarshal(plain[len(prefix):], kernel); err != nil {
		return nil, err
	}
	if kernel.GetTopic() == "" {
		return nil, fmt.Errorf("%w: 内层缺少 topic", housekitchen.ErrDirectedInvalid)
	}
	return kernel, nil
}
