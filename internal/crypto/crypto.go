// Package crypto 提供 FutureCast 的全部密码学原语与签名封装。
//
// 本包的公开 API 是冻结接口：只做追加，不做破坏性修改。
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// SeedSize 是 ed25519 种子长度。
const SeedSize = ed25519.SeedSize

// PubKeySize 是 ed25519 公钥长度。
const PubKeySize = ed25519.PublicKeySize

// SigSize 是 ed25519 签名长度。
const SigSize = ed25519.SignatureSize

// X25519KeySize 是 X25519 公私钥长度。
const X25519KeySize = 32

// ---------- 基础签名 ----------

// Sign 用 ed25519 私钥签名。
func Sign(priv ed25519.PrivateKey, msg []byte) []byte { return ed25519.Sign(priv, msg) }

// Verify 校验 ed25519 签名。任何长度异常都返回 false，不 panic。
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != PubKeySize || len(sig) != SigSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// KeyFromSeed 由 32 字节种子派生 ed25519 私钥。
func KeyFromSeed(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("futurecast: 种子长度应为 %d，实为 %d", SeedSize, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// GenerateSeed 生成新的 ed25519 种子。
func GenerateSeed() ([]byte, error) {
	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("futurecast: 生成种子失败: %w", err)
	}
	return seed, nil
}

// ---------- SignedBody 签名与校验 ----------

// SignBody 用私钥对一个 SignedBody 生成签名。
//
// canonical 必须来自 housekitchen.CanonicalSignedBody，且该 body 的 signers 应为空。
// 返回的 Signature 带 signedAt 时间戳；同一 keyID 重复签名不会被计为两个 signer。
func SignBody(priv ed25519.PrivateKey, canonical []byte, keyID housekitchen.KeyID, signedAt time.Time) *pb.Signature {
	nanos := signedAt.UnixNano()
	input := housekitchen.SignInput(canonical, keyID, nanos)
	return &pb.Signature{
		KeyId:             housekitchen.PBKeyID(keyID),
		Signature:         Sign(priv, input[:]),
		SignedAtUnixNanos: nanos,
	}
}

// VerifySignature 校验单个签名是否对给定 canonical 字节有效。
func VerifySignature(pub ed25519.PublicKey, canonical []byte, sig *pb.Signature) error {
	if sig == nil {
		return housekitchen.ErrInvalidSignature
	}
	keyID := housekitchen.GetKeyID(sig.GetKeyId())
	if keyID.IsZero() {
		return fmt.Errorf("%w: key_id 为空或长度错误", housekitchen.ErrInvalidSignature)
	}
	input := housekitchen.SignInput(canonical, keyID, sig.GetSignedAtUnixNanos())
	if !Verify(pub, input[:], sig.GetSignature()) {
		return fmt.Errorf("%w: key %s", housekitchen.ErrInvalidSignature, keyID.Short())
	}
	return nil
}

// MultisigResult 是多签校验结果。
type MultisigResult struct {
	// Valid 是有效且互异的签名者数量。
	Valid int
	// Signers 是有效签名者的 key_id。
	Signers []housekitchen.KeyID
	// Rejected 是无效或被忽略的签名及原因。
	Rejected []RejectedSignature
}

// RejectedSignature 记录一个被忽略的签名。
type RejectedSignature struct {
	KeyID  housekitchen.KeyID
	Reason string
}

// MultisigVerify 对 canonical 字节做门限校验。
//
// 规则：
//   - 每个签名必须属于 rootKeys（可用 pubKeyOf 解析公钥）；
//   - 同一 key_id 只计一次（重复签名不能凑门限）；
//   - signed_at 必须落在 [now-skew, now+skew]；
//   - 签名无效 → 记入 Rejected，不计入 Valid。
//
// 返回 error 仅表示"整体无法判定"（如参数非法）；门限不足由 ok 表达。
func MultisigVerify(canonical []byte, sigs []*pb.Signature, rootKeys []housekitchen.KeyID,
	pubKeyOf func(housekitchen.KeyID) (ed25519.PublicKey, bool),
	threshold int, now time.Time, skew time.Duration) (MultisigResult, bool, error) {

	if threshold <= 0 {
		return MultisigResult{}, false, fmt.Errorf("futurecast: 门限必须为正数")
	}
	if len(rootKeys) == 0 {
		return MultisigResult{}, false, fmt.Errorf("futurecast: root_key_ids 为空")
	}
	root := make(map[housekitchen.KeyID]struct{}, len(rootKeys))
	for _, k := range rootKeys {
		root[k] = struct{}{}
	}

	res := MultisigResult{}
	seen := make(map[housekitchen.KeyID]struct{}, len(sigs))
	skewNanos := skew.Nanoseconds()

	for _, sig := range sigs {
		if sig == nil {
			continue
		}
		keyID := housekitchen.GetKeyID(sig.GetKeyId())
		switch {
		case keyID.IsZero():
			res.Rejected = append(res.Rejected, RejectedSignature{KeyID: keyID, Reason: "key_id 非法"})
			continue
		case !keyIDIn(root, keyID):
			res.Rejected = append(res.Rejected, RejectedSignature{KeyID: keyID, Reason: "不在 root_key_ids 内"})
			continue
		}
		if _, dup := seen[keyID]; dup {
			res.Rejected = append(res.Rejected, RejectedSignature{KeyID: keyID, Reason: "重复 key_id"})
			continue
		}
		skewErr := checkSkew(sig.GetSignedAtUnixNanos(), now.UnixNano(), skewNanos)
		if skewErr != nil {
			res.Rejected = append(res.Rejected, RejectedSignature{KeyID: keyID, Reason: skewErr.Error()})
			continue
		}
		pub, ok := pubKeyOf(keyID)
		if !ok || len(pub) != PubKeySize {
			res.Rejected = append(res.Rejected, RejectedSignature{KeyID: keyID, Reason: "公钥不可解析"})
			continue
		}
		if err := VerifySignature(pub, canonical, sig); err != nil {
			res.Rejected = append(res.Rejected, RejectedSignature{KeyID: keyID, Reason: err.Error()})
			continue
		}
		seen[keyID] = struct{}{}
		res.Valid++
		res.Signers = append(res.Signers, keyID)
	}
	return res, res.Valid >= threshold, nil
}

func keyIDIn(set map[housekitchen.KeyID]struct{}, k housekitchen.KeyID) bool {
	_, ok := set[k]
	return ok
}

func checkSkew(signedAt, now, skewNanos int64) error {
	if signedAt == 0 {
		return fmt.Errorf("%w: 缺少 signed_at", housekitchen.ErrClockSkew)
	}
	diff := now - signedAt
	if diff < 0 {
		diff = -diff
	}
	if diff > skewNanos {
		return fmt.Errorf("%w: 偏差 %dms", housekitchen.ErrClockSkew, diff/int64(time.Millisecond))
	}
	return nil
}

// ---------- 节点身份自证 ----------

// DomainDigest 计算域分隔摘要。
//
//	DomainDigest(domain, msg) = SHA-256( domain || msg )
func DomainDigest(domain string, msg []byte) housekitchen.Hash {
	return housekitchen.HashOf([]byte(domain), msg)
}

// SignCanonical 对一条**已自带域前缀的规范化字节**签名。
//
// v1 冻结约定（单前缀）：
//
//	canonical   = DOMAIN || deterministic_proto(msg)   // 由 housekitchen.CanonicalXxx 产出
//	signature   = Ed25519_sign(priv, canonical)        // 直接签，域仅出现一次
//
// 适用于 Hello / NodeAnnounce / PeerExchange / SealedPayload。
//
// 历史坑（已修，勿回退）：早期版本让 canonical 自带域前缀、又在签名函数里
// 用 HashOf(domain, canonical) 再加一次域，实际摘要变成
// SHA256(DOMAIN || DOMAIN || proto) —— 域出现两次。
// 为彻底消除这个陷阱，签名函数**不再接受 domain 参数**：
// 域由 housekitchen.CanonicalXxx 唯一负责，调用方无法重复施加。
func SignCanonical(priv ed25519.PrivateKey, canonical []byte) []byte {
	return Sign(priv, canonical)
}

// VerifyCanonical 校验一条规范化字节上的签名。
func VerifyCanonical(pub ed25519.PublicKey, canonical, sig []byte) bool {
	return Verify(pub, canonical, sig)
}

// Ed25519ToX25519 把 ed25519 公钥确定性地转换为 X25519 公钥。
//
//	X25519_pub = birational_map( ed25519_pub 的 Edwards y 坐标 )
//
// 用途：sealed 模式需要向中继的 X25519 公钥加密，但协议里不为每个节点
// 单独携带 X25519 公钥。用 ed25519 公钥确定性派生可以：
//   - 不在线格式里增加字段；
//   - 把加密身份与签名身份天然绑定（同一把私钥既是签名身份也是解密身份）。
//
// 注意：这是公钥的确定性映射，不是"用 ed25519 私钥做 X25519 运算"。
func Ed25519ToX25519(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != PubKeySize {
		return nil, fmt.Errorf("futurecast: ed25519 公钥长度非法")
	}
	pt, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("futurecast: ed25519 公钥无法解析: %w", err)
	}
	return pt.BytesMontgomery(), nil
}

// Ed25519SeedToX25519Scalar 把 ed25519 种子确定性转换为 X25519 **私钥标量**。
//
// 与 libsodium crypto_sign_ed25519_sk_to_curve25519 一致：
// 对种子做 SHA-512，取前 32 字节并 clamp，即为对应的 X25519 标量。
//
// 注意：返回的是**私钥**，不是公钥。公钥请用 Ed25519ToX25519，
// 或对返回值调用 X25519(scalar, Basepoint)。
// 早期版本此处错误地返回了公钥，导致解密方拿公钥当私钥用（握手成功但解封必然失败）。
func Ed25519SeedToX25519Scalar(seed []byte) ([]byte, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("futurecast: 种子长度非法")
	}
	h := sha512.Sum512(seed)
	var scalar [32]byte
	copy(scalar[:], h[:32])
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	return scalar[:], nil
}

// Ed25519SeedToX25519Public 由 ed25519 种子派生 X25519 公钥。
func Ed25519SeedToX25519Public(seed []byte) ([]byte, error) {
	scalar, err := Ed25519SeedToX25519Scalar(seed)
	if err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("futurecast: 派生 X25519 公钥失败: %w", err)
	}
	return pub, nil
}

// ---------- X25519 / HKDF / AEAD ----------

// X25519KeyPair 是一对 X25519 密钥。
type X25519KeyPair struct {
	Public  []byte
	Private []byte
}

// GenerateX25519 生成 X25519 密钥对。
func GenerateX25519() (X25519KeyPair, error) {
	priv := make([]byte, X25519KeySize)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return X25519KeyPair{}, fmt.Errorf("futurecast: 生成 X25519 私钥失败: %w", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return X25519KeyPair{}, fmt.Errorf("futurecast: 派生 X25519 公钥失败: %w", err)
	}
	return X25519KeyPair{Public: pub, Private: priv}, nil
}

// X25519Shared 计算共享密钥。
func X25519Shared(priv, peerPub []byte) ([]byte, error) {
	if len(priv) != X25519KeySize || len(peerPub) != X25519KeySize {
		return nil, errors.New("futurecast: X25519 密钥长度非法")
	}
	shared, err := curve25519.X25519(priv, peerPub)
	if err != nil {
		return nil, fmt.Errorf("futurecast: X25519 协商失败: %w", err)
	}
	return shared, nil
}

// HKDF 用 SHA-256 派生指定长度的密钥。
func HKDF(secret, salt []byte, info string, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("futurecast: HKDF 派生失败: %w", err)
	}
	return out, nil
}

// SealAEAD 用 AES-256-GCM 加密，返回 nonce||ciphertext。
func SealAEAD(key, plaintext, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("futurecast: AES 初始化失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("futurecast: GCM 初始化失败: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("futurecast: 生成 nonce 失败: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, associatedData), nil
}

// OpenAEAD 解密 SealAEAD 的输出。
func OpenAEAD(key, sealed, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("futurecast: AES 初始化失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("futurecast: GCM 初始化失败: %w", err)
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("futurecast: 密文长度不足")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, associatedData)
	if err != nil {
		// 不回显密钥材料，只回显关联数据的摘要，便于对账而不足以离线爆破。
		adSum := sha256.Sum256(associatedData)
		return nil, fmt.Errorf("futurecast: 解密失败: %w (ad=%x)", err, adSum[:8])
	}
	return pt, nil
}

// SealForRecipient 用发送方临时私钥 + 接收方 X25519 公钥加密。
// 输出 ephemeral_pub || nonce || ciphertext，约定由调用方按字段拆分。
func SealForRecipient(ephPriv, recipientPub, plaintext, associatedData []byte, info string) (ephemeralPub, sealed []byte, err error) {
	shared, err := X25519Shared(ephPriv, recipientPub)
	if err != nil {
		return nil, nil, err
	}
	key, err := HKDF(shared, nil, info, 32)
	if err != nil {
		return nil, nil, err
	}
	pub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("futurecast: 派生临时公钥失败: %w", err)
	}
	ct, err := SealAEAD(key, plaintext, associatedData)
	if err != nil {
		return nil, nil, err
	}
	return pub, ct, nil
}

// OpenFromSender 用接收方私钥 + 发送方临时公钥解密。
func OpenFromSender(recipientPriv, ephemeralPub, sealed, associatedData []byte, info string) ([]byte, error) {
	shared, err := X25519Shared(recipientPriv, ephemeralPub)
	if err != nil {
		return nil, err
	}
	key, err := HKDF(shared, nil, info, 32)
	if err != nil {
		return nil, err
	}
	return OpenAEAD(key, sealed, associatedData)
}

// ---------- 轮换标签 ----------

// RelayTag 计算不泄露拓扑的轮换跳标签。
//
//	relay_tag = HMAC-SHA256( dailyKey, relayTagDomain || msgID || previousTag )[0:8]
//
// 每天轮换 dailyKey，因此历史标签无法被长期关联。
func RelayTag(dailyKey []byte, msgID housekitchen.Hash, previousTag uint64) uint64 {
	mac := hmac.New(sha256.New, dailyKey)
	mac.Write([]byte(housekitchen.DomainRelayTag))
	mac.Write(msgID.Bytes())
	mac.Write(housekitchen.Uint64BE(previousTag))
	sum := mac.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}

// ---------- 主题密钥 ----------

// WrapTopicKey 用接收方 X25519 公钥封装主题密钥。
func WrapTopicKey(ephPriv, recipientPub, topicKey, associatedData []byte) ([]byte, error) {
	_, sealed, err := SealForRecipient(ephPriv, recipientPub, topicKey, associatedData, housekitchen.DomainTopicKey)
	return sealed, err
}

// UnwrapTopicKey 解封主题密钥。
func UnwrapTopicKey(recipientPriv, ephemeralPub, wrapped, associatedData []byte) ([]byte, error) {
	return OpenFromSender(recipientPriv, ephemeralPub, wrapped, associatedData, housekitchen.DomainTopicKey)
}
