package sealed

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// 主题密钥：sealed 模式的可选内容保密层。
//
// 设计取舍（重要）：
//   - 主题密钥让 **没有密钥的观察者与中继只能看到密文**，从而真正实现
//     "外部无法判定这是一条超管广播"。
//   - 代价是**验证范围收窄到持密钥者**（设计文档 §5.6 的诚实声明）。
//   - 若不配置主题密钥，sealed 退化为"只隐藏提交者、不隐藏内容"，
//     节点会在启动时明确告警，不静默降级。

// TopicKeySize 是主题密钥长度。
const TopicKeySize = 32

// topicKeyInfo 是主题密钥派生的 HKDF info。
const topicKeyInfo = housekitchen.DomainTopicKey

// DeriveTopicKey 由共享口令与主题名派生主题密钥。
//
//	topic_key = HKDF-SHA256(secret = sha256(passphrase), salt = sha256(topic), info = "fc/v1/topickey", 32)
//
// 任何持有同一口令与主题名的订阅者都能算出同一把密钥，因此不需要额外的密钥分发通道。
func DeriveTopicKey(passphrase, topic string) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("%w: 主题口令为空", housekitchen.ErrSealedInvalid)
	}
	secret := sha256.Sum256([]byte(passphrase))
	salt := sha256.Sum256([]byte(topic))
	r := hkdf.New(sha256.New, secret[:], salt[:], []byte(topicKeyInfo))
	key := make([]byte, TopicKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("futurecast: 派生主题密钥失败: %w", err)
	}
	return key, nil
}

// TopicKeyID 返回主题密钥标识。
func TopicKeyID(key []byte) housekitchen.KeyID {
	return housekitchen.KeyIDFromPub(key)
}

// EncryptInner 用主题密钥加密内层管理员正文。
func EncryptInner(topicKey, innerBody []byte, topic string) (ciphertext, nonce []byte, err error) {
	if len(topicKey) != TopicKeySize {
		return nil, nil, fmt.Errorf("%w: 主题密钥长度应为 %d", housekitchen.ErrSealedInvalid, TopicKeySize)
	}
	// 关联数据绑定主题名，防止把密文搬到另一个主题上重用。
	ad := []byte("futurecast/v1/innerbody\x00" + topic)
	sealed, err := crypto.SealAEAD(topicKey, innerBody, ad)
	if err != nil {
		return nil, nil, err
	}
	// crypto.SealAEAD 输出 nonce||ct，这里拆成两个字段以匹配 proto。
	n := 12
	return sealed[n:], sealed[:n], nil
}

// DecryptInner 解密内层正文。
func DecryptInner(topicKey, ciphertext, nonce []byte, topic string) ([]byte, error) {
	if len(topicKey) != TopicKeySize {
		return nil, fmt.Errorf("%w: 主题密钥长度应为 %d", housekitchen.ErrSealedInvalid, TopicKeySize)
	}
	ad := []byte("futurecast/v1/innerbody\x00" + topic)
	return crypto.OpenAEAD(topicKey, append(append([]byte(nil), nonce...), ciphertext...), ad)
}

// IsEncrypted 判断封存载荷是否带内容加密。
func IsEncrypted(sp *pb.SealedPayload) bool {
	return sp != nil && len(sp.GetInnerCiphertext()) > 0
}
