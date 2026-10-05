// 本文件产出「定向广播」（docs/PROTOCOL.md 附录 E）的跨语言基准向量。
//
// 与其它向量一样，这里所有输入都是固定常量，所有随机量都由 SHA-256(label) 派生，
// 因此 Build() 在任意机器、任意次数运行下逐字节一致。
//
// 关键约束：internal/directed.Seal 内部使用系统随机源（blind_salt/content_key/
// eph 密钥/AEAD nonce），无法直接产出确定性向量。因此这里按附录 E.2 的公式
// **独立重算**一份完全等价的消息，然后把它交给冻结实现验收：
//   - directed.VerifyBody 必须接受（外层门限签名 + 内容寻址 + 结构检查）；
//   - directed.Open 必须让每个收件人解出同一份 DirectedKernel，且槽位序号正确；
//   - 非收件人必须得到 ErrNotAuthorized。
//
// 只有这三件事全部成立，向量才会被写出。
//
// 独立性：DIRECTED_BYTES / KERNEL_BYTES 由本包手写的 proto3 编码器复算，
// blind_key / recipient_tag 由独立 HMAC/HKDF 复算，并与冻结实现的输出逐字节比对。
package conformance

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
	fccrypto "github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/directed"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
)

// DirectedWrapADPrefix 是 wrapped_key 关联数据的前缀。
//
// 它在 internal/directed/directed.go 的 wrapAAD 中是**未导出字面量**
// （与 sealed 的 adPrefix 同类，Finding F12）。跨语言实现没有公开真源，
// 只能以本向量为准，因此这里显式镜像出来。
const DirectedWrapADPrefix = "futurecast/v1/dirwrap\x00"

// ---------- JSON 结构（字段名即跨语言 ABI，勿随意重命名） ----------

// DirectedRecipientVector 是一个收件人槽位的字段级输入与派生输出。
//
// 注意：node_id / ed25519_pub / x25519_pub / ed25519_seed / eph_priv 都是**封端
// 输入**，线格式里绝不出现（附录 E 的名单隐私设计）。它们在这里出现只是为了
// 让外部实现者能复现并自证；实际 DirectedBody 里只有 eph_pub / wrapped_key /
// recipient_tag 三个字段。
type DirectedRecipientVector struct {
	Index           int    `json:"index"`
	Label           string `json:"label"`
	NodeIDHex       string `json:"node_id_hex"`
	Ed25519SeedHex  string `json:"ed25519_seed_hex"`
	Ed25519PubHex   string `json:"ed25519_pub_hex"`
	X25519PubHex    string `json:"x25519_pub_hex"`
	EphPrivHex      string `json:"eph_priv_hex"`
	EphPubHex       string `json:"eph_pub_hex"`
	SharedSecretHex string `json:"shared_secret_hex"`
	WrapKeyHex      string `json:"wrap_key_hex"`
	WrapNonceHex    string `json:"wrap_nonce_hex"`
	WrapADHex       string `json:"wrap_ad_hex"`
	WrappedKeyHex   string `json:"wrapped_key_hex"`
	RecipientTagHex string `json:"recipient_tag_hex"`
}

// DirectedKernelVector 是内层机密（加密前）的字段级输入与规范化字节。
type DirectedKernelVector struct {
	Topic              string `json:"topic"`
	MediaType          string `json:"media_type"`
	Body               string `json:"body"`
	CreatedAtUnixNanos int64  `json:"created_at_unix_nanos"`
	ExpiresAtUnixNanos int64  `json:"expires_at_unix_nanos"`
	NonceHex           string `json:"nonce_hex"`
	// housekitchen.DirectedBodyHash 的注释里被描述为"绑定外层 msg_id"，但冻结
	// 实现从未填充它（见 Finding F16）。
	ProtoHex       string `json:"proto_hex"`
	KernelBytesHex string `json:"kernel_bytes_hex"`
}

// DirectedVector 是一条 2-of-3 超管定向广播的完整向量。
type DirectedVector struct {
	ProtoVersion       uint32       `json:"proto_version"`
	Kind               uint32       `json:"kind"`
	KindName           string       `json:"kind_name"`
	Topic              string       `json:"topic"`
	MediaType          string       `json:"media_type"`
	CreatedAtUnixNanos int64        `json:"created_at_unix_nanos"`
	ExpiresAtUnixNanos int64        `json:"expires_at_unix_nanos"`
	NowUnixNanos       int64        `json:"now_unix_nanos"`
	TTLNanos           int64        `json:"ttl_nanos"`
	NonceHex           string       `json:"nonce_hex"`
	AdminSetGeneration uint64       `json:"admin_set_generation"`
	SignerSetHashHex   string       `json:"signer_set_hash_hex"`
	Policy             PolicyVector `json:"policy"`
	MaxHops            int64        `json:"max_hops"`

	BlindSaltHex    string `json:"blind_salt_hex"`
	ContentKeyHex   string `json:"content_key_hex"`
	BlindKeyHex     string `json:"blind_key_hex"`
	ContentNonceHex string `json:"content_nonce_hex"`
	CiphertextHex   string `json:"ciphertext_hex"`
	RecipientCount  uint32 `json:"recipient_count"`

	Recipients []DirectedRecipientVector `json:"recipients"`
	Kernel     DirectedKernelVector      `json:"kernel"`

	DirectedProtoHex string            `json:"directed_proto_hex"`
	DirectedBytesHex string            `json:"directed_bytes_hex"`
	DirectedMsgIDHex string            `json:"directed_msg_id_hex"`
	Signers          []SignatureVector `json:"signers"`

	EnvelopeMsgIDHex  string `json:"envelope_msg_id_hex"`
	EnvelopeFirstSeen int64  `json:"envelope_first_seen_unix_nanos"`
	EnvelopeHops      uint32 `json:"envelope_hops"`

	Note string `json:"note"`
}

// buildDirected 构造定向广播向量并交给冻结实现验收。
func buildDirected(v *Vectors) error {
	set, keys, err := genesisAdminFixture()
	if err != nil {
		return err
	}
	setHash, err := housekitchen.AdminSetHash(set)
	if err != nil {
		return err
	}

	labels := []string{"alice", "bob", "carol"}
	recips := make([]*identity.NodeIdentity, 0, len(labels))
	for _, lbl := range labels {
		id, err := identity.NodeIdentityFromSeed(derive32("futurecast/vector/directed-recipient-" + lbl))
		if err != nil {
			return fmt.Errorf("构造收件人 %s 失败: %w", lbl, err)
		}
		recips = append(recips, id)
	}
	outsider, err := identity.NodeIdentityFromSeed(derive32("futurecast/vector/directed-outsider"))
	if err != nil {
		return err
	}

	const (
		text     = "futurecast directed interop vector #1"
		mediaTyp = "text/plain"
	)
	now := VectorTime
	ttl := time.Hour

	body := &pb.DirectedBody{
		ProtoVersion:       housekitchen.ProtoVersion,
		Kind:               pb.MessageKind_MESSAGE_KIND_DIRECTED_BROADCAST,
		CreatedAtUnixNanos: now.UnixNano(),
		ExpiresAtUnixNanos: now.Add(ttl).UnixNano(),
		Nonce:              derive32("futurecast/vector/directed/body-nonce")[:housekitchen.NonceSize],
		AdminSetGeneration: set.GetGeneration(),
		SignerSetHash:      housekitchen.PBHash(setHash),
		Policy:             set.GetPolicy(),
		MaxHops:            housekitchen.DefaultMaxHops,
		BlindSalt:          derive32("futurecast/vector/directed/blind-salt")[:directed.BlindSaltSize],
		RecipientCount:     uint32(len(recips)),
	}
	salt := body.GetBlindSalt()

	// content_key 与 blind_key（独立 HKDF 复算 + 冻结实现交叉验证）。
	contentKey := derive32("futurecast/vector/directed/content-key")
	blindKey := hkdfSHA256(contentKey, salt, []byte(housekitchen.DomainDirectedBlind), 32)
	goBlindKey, err := fccrypto.HKDF(contentKey, salt, housekitchen.DomainDirectedBlind, 32)
	if err != nil {
		return fmt.Errorf("冻结 crypto.HKDF(blind_key) 失败: %w", err)
	}
	if !bytes.Equal(blindKey, goBlindKey) {
		return fmt.Errorf("blind_key 独立实现与冻结实现不一致")
	}

	// 内层机密 KERNEL_BYTES（手写 proto3 编码器复算 + 冻结实现交叉验证）。
	kernel := &pb.DirectedKernel{
		Topic:              "alerts",
		MediaType:          mediaTyp,
		Body:               text,
		CreatedAtUnixNanos: now.UnixNano(),
		ExpiresAtUnixNanos: now.Add(ttl).UnixNano(),
		Nonce:              derive32("futurecast/vector/directed/kernel-nonce")[:housekitchen.NonceSize],
	}
	kernelBytes, err := housekitchen.CanonicalDirectedKernel(kernel)
	if err != nil {
		return err
	}
	manualKernel := EncodeDirectedKernelProto3(kernel)
	if !bytes.Equal(manualKernel, kernelBytes[len(housekitchen.DomainDirectedKernel):]) {
		return fmt.Errorf("手写 proto3 编码的 DirectedKernel 与确定性序列化不一致")
	}

	// 内层密文：AD = DomainDirectedKernel || blind_salt（附录 E.2）。
	contentNonce := derive32("futurecast/vector/directed/content-nonce")[:directed.NonceSize]
	innerAD := append([]byte(housekitchen.DomainDirectedKernel), salt...)
	ct, err := sealGCMFixedNonce(contentKey, contentNonce, kernelBytes, innerAD)
	if err != nil {
		return err
	}
	body.ContentNonce = contentNonce
	body.Ciphertext = ct

	recVecs := make([]DirectedRecipientVector, 0, len(recips))
	for i, id := range recips {
		xPub, err := directed.RecipientX25519(directed.Recipient{NodeID: id.ID, Ed25519Pub: id.Pub})
		if err != nil {
			return fmt.Errorf("收件人 %d 的 X25519 公钥派生失败: %w", i, err)
		}
		ephPriv := derive32(fmt.Sprintf("futurecast/vector/directed/eph-%d", i))
		ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
		if err != nil {
			return err
		}
		shared, err := fccrypto.X25519Shared(ephPriv, xPub)
		if err != nil {
			return err
		}
		wrapKey := hkdfSHA256(shared, nil, []byte(housekitchen.DomainDirectedWrap), 32)
		goWrapKey, err := fccrypto.HKDF(shared, nil, housekitchen.DomainDirectedWrap, 32)
		if err != nil {
			return err
		}
		if !bytes.Equal(wrapKey, goWrapKey) {
			return fmt.Errorf("槽位 %d 的 wrap_key 独立实现与冻结实现不一致", i)
		}
		wrapNonce := derive32(fmt.Sprintf("futurecast/vector/directed/wrap-nonce-%d", i))[:directed.NonceSize]
		wrapAD := append([]byte(DirectedWrapADPrefix), salt...)
		wrapAD = append(wrapAD, housekitchen.Uint64BE(uint64(i))...)
		wrapCT, err := sealGCMFixedNonce(wrapKey, wrapNonce, contentKey, wrapAD)
		if err != nil {
			return err
		}
		// 线格式里的 wrapped_key 与 crypto.SealAEAD 的输出形状一致：nonce(12) || ct||tag。
		wrapped := append(append([]byte(nil), wrapNonce...), wrapCT...)
		// recipient_tag = HMAC-SHA256(blind_key, DomainDirectedTag || node_id)[:16]
		mac := hmacSHA256(blindKey, append([]byte(housekitchen.DomainDirectedTag), id.ID.Bytes()...))
		tag := mac[:16]

		body.Recipients = append(body.Recipients, &pb.DirectRecipient{
			EphPub:       ephPub,
			WrappedKey:   wrapped,
			RecipientTag: tag,
		})
		recVecs = append(recVecs, DirectedRecipientVector{
			Index:           i,
			Label:           labels[i],
			NodeIDHex:       hexStr(id.ID.Bytes()),
			Ed25519SeedHex:  hexStr(id.KeySeed),
			Ed25519PubHex:   hexStr(id.Pub),
			X25519PubHex:    hexStr(xPub),
			EphPrivHex:      hexStr(ephPriv),
			EphPubHex:       hexStr(ephPub),
			SharedSecretHex: hexStr(shared),
			WrapKeyHex:      hexStr(wrapKey),
			WrapNonceHex:    hexStr(wrapNonce),
			WrapADHex:       hexStr(wrapAD),
			WrappedKeyHex:   hexStr(wrapped),
			RecipientTagHex: hexStr(tag),
		})
	}

	// DIRECTED_BYTES 与 DIRECTED_MSG_ID。
	canonical, err := housekitchen.CanonicalDirectedBody(body)
	if err != nil {
		return err
	}
	manualBody := EncodeDirectedBodyProto3(body)
	if !bytes.Equal(manualBody, canonical[len(housekitchen.DomainDirectedBody):]) {
		return fmt.Errorf("手写 proto3 编码的 DirectedBody 与确定性序列化不一致")
	}
	msgID := housekitchen.MsgIDFromCanonical(canonical)

	// 门限签名（signers 必须按 key_id 字典序；keys 已排序，取前 2 把）。
	sigVecs := make([]SignatureVector, 0, 2)
	for _, k := range keys[:2] {
		sig := k.Sign(canonical, now)
		body.Signers = append(body.Signers, sig)
		sigVecs = append(sigVecs, SignatureVector{
			KeyIDHex:          hexStr(k.KeyID.Bytes()),
			SignedAtUnixNanos: sig.GetSignedAtUnixNanos(),
			SignInputHex:      hexStr(housekitchen.SignInput(canonical, k.KeyID, sig.GetSignedAtUnixNanos()).Bytes()),
			SignatureHex:      hexStr(sig.GetSignature()),
		})
	}
	body.MsgId = housekitchen.PBHash(msgID)

	// ---------- 冻结实现验收 ----------
	if _, err := directed.VerifyBody(body, set, now); err != nil {
		return fmt.Errorf("golden 定向广播未被冻结 directed.VerifyBody 接受（向量本身有误）: %w", err)
	}
	for i, id := range recips {
		res, err := directed.Open(id.KeySeed, id.ID, body)
		if err != nil {
			return fmt.Errorf("golden 定向广播无法被收件人 %d 解开: %w", i, err)
		}
		if res.Slot != i {
			return fmt.Errorf("收件人 %d 解出的槽位序号为 %d，期望 %d", i, res.Slot, i)
		}
		if got := res.Kernel.GetBody(); got != text {
			return fmt.Errorf("收件人 %d 解出的正文 %q 与目录 %q 不符", i, got, text)
		}
		if got := res.Kernel.GetTopic(); got != kernel.GetTopic() {
			return fmt.Errorf("收件人 %d 解出的 topic %q 不符", i, got)
		}
	}
	if _, err := directed.Open(outsider.KeySeed, outsider.ID, body); !errors.Is(err, housekitchen.ErrNotAuthorized) {
		return fmt.Errorf("非收件人应得到 ErrNotAuthorized，实为: %v", err)
	}

	env := directed.Envelope(body, now)
	v.Directed = DirectedVector{
		ProtoVersion:       body.GetProtoVersion(),
		Kind:               uint32(body.GetKind()),
		KindName:           body.GetKind().String(),
		Topic:              "alerts",
		MediaType:          mediaTyp,
		CreatedAtUnixNanos: body.GetCreatedAtUnixNanos(),
		ExpiresAtUnixNanos: body.GetExpiresAtUnixNanos(),
		NowUnixNanos:       now.UnixNano(),
		TTLNanos:           ttl.Nanoseconds(),
		NonceHex:           hexStr(body.GetNonce()),
		AdminSetGeneration: body.GetAdminSetGeneration(),
		SignerSetHashHex:   hexStr(housekitchen.GetHash(body.GetSignerSetHash()).Bytes()),
		Policy:             policyVector(set.GetPolicy()),
		MaxHops:            int64(body.GetMaxHops()),

		BlindSaltHex:    hexStr(salt),
		ContentKeyHex:   hexStr(contentKey),
		BlindKeyHex:     hexStr(blindKey),
		ContentNonceHex: hexStr(body.GetContentNonce()),
		CiphertextHex:   hexStr(body.GetCiphertext()),
		RecipientCount:  body.GetRecipientCount(),

		Recipients: recVecs,
		Kernel: DirectedKernelVector{
			Topic:              kernel.GetTopic(),
			MediaType:          kernel.GetMediaType(),
			Body:               kernel.GetBody(),
			CreatedAtUnixNanos: kernel.GetCreatedAtUnixNanos(),
			ExpiresAtUnixNanos: kernel.GetExpiresAtUnixNanos(),
			NonceHex:           hexStr(kernel.GetNonce()),
			// 空串 = 线格式里该字段不存在（proto3 默认值省略）。
			ProtoHex:       hexStr(manualKernel),
			KernelBytesHex: hexStr(kernelBytes),
		},

		DirectedProtoHex: hexStr(manualBody),
		DirectedBytesHex: hexStr(canonical),
		DirectedMsgIDHex: hexStr(msgID.Bytes()),
		Signers:          sigVecs,

		EnvelopeMsgIDHex:  hexStr(housekitchen.GetHash(env.GetMsgId()).Bytes()),
		EnvelopeFirstSeen: env.GetFirstSeenUnixNanos(),
		EnvelopeHops:      env.GetHops(),

		Note: "签名覆盖 DirectedBody 除 msg_id(3)/signers(11) 外的全部字段；" +
			"ciphertext 不含 nonce（nonce 在 content_nonce），wrapped_key 含 12 字节 nonce 前缀。" +
			"recipients 里除 eph_pub/wrapped_key/recipient_tag 外的字段都是封端输入，不在线格式中。" +
			"内核字段已冻结：field 7 已废弃，编码时不得出现。",
	}
	return nil
}
