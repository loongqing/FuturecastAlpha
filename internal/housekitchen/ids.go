// Package housekitchen 提供全项目共用的基础类型、常量与编码原语。
// 本包的公开 API 是冻结接口：只做追加，不做破坏性修改。
package housekitchen

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// HashSize 是 SHA-256 摘要长度。
	HashSize = 32
	// KeyIDSize 是 KeyID 长度：SHA-256(ed25519_pub)[:16]。
	KeyIDSize = 16
	// NodeIDSize 是 NodeID 长度：SHA-256(ed25519_pub)。
	NodeIDSize = 32
	// NonceSize 是消息 nonce 长度。
	NonceSize = 16

	// ProtoVersion 当前协议版本。
	ProtoVersion = 1
	// MinProtoVersion 可接受的最低对端版本。
	MinProtoVersion = 1

	// DomainSignedBody 是 SignedBody 规范化编码的域分隔前缀。
	DomainSignedBody = "futurecast/v1/signedbody\x00"
	// DomainAdminSet 是 AdminSet 规范化编码的域分隔前缀。
	//
	// 注意：AdminSet 曾错误地复用 DomainSignedBody，导致两个不同结构共享同一域。
	// 这会破坏域分隔的本意（防跨类型签名/哈希搬运），已修正为独立域。
	DomainAdminSet = "futurecast/v1/adminset\x00"
	// DomainSealedPayload 是封存载荷自证用的域分隔前缀。
	DomainSealedPayload = "futurecast/v1/sealedpayload\x00"
	// DomainDirectedBody 是定向广播外层正文的域分隔前缀。
	DomainDirectedBody = "futurecast/v1/directedbody\x00"
	// DomainDirectedKernel 是定向广播内层机密的域分隔前缀。
	DomainDirectedKernel = "futurecast/v1/directedkernel\x00"
	// DomainDirectedWrap 是收件人密钥封装的 HKDF info。
	DomainDirectedWrap = "fc/v1/directedwrap"
	// DomainDirectedBlind 是收件人 tag 盲化密钥的 HKDF info。
	DomainDirectedBlind = "fc/v1/directedblind"
	// DomainDirectedTag 是 recipient_tag 的域分隔前缀。
	DomainDirectedTag = "futurecast/v1/dirtag\x00"
	// DomainMsgID 是 msg_id 派生的域分隔前缀。
	DomainMsgID = "futurecast/v1/msgid\x00"
	// DomainSignInput 是单签名输入的域分隔前缀。
	DomainSignInput = "futurecast/v1/signinput\x00"
	// DomainNodeAnnounce 是节点动态自签的域分隔前缀。
	DomainNodeAnnounce = "futurecast/v1/nodeannounce\x00"
	// DomainPeerExchange 是邻居互推自签的域分隔前缀。
	DomainPeerExchange = "futurecast/v1/peerexchange\x00"
	// DomainHello 是握手自签的域分隔前缀。
	DomainHello = "futurecast/v1/hello\x00"
	// DomainInbox 是 sealed 信箱 rendezvous_id 的 HKDF info。
	DomainInbox = "fc/v1/inbox"
	// DomainRelayTag 是 relay_tag 派生的域分隔前缀。
	DomainRelayTag = "futurecast/v1/relaytag\x00"
	// DomainTopicKey 是主题密钥封装的 HKDF info。
	DomainTopicKey = "fc/v1/topickey"
)

// 默认限额与超时（可被配置覆盖）。
const (
	DefaultMaxFrameSize     = 1 << 20 // 1 MiB
	DefaultMaxHops          = 32
	DefaultFanout           = 6
	DefaultMinPeers         = 8
	DefaultMaxPeers         = 64
	DefaultGossipIntervalMS = 3000
	DefaultBucketRefreshMS  = 30000
	DefaultLivenessMS       = 90000
	DefaultMsgTTLNanos      = int64(7 * 24 * 3600 * 1e9)
	DefaultClockSkewNanos   = int64(300 * 1e9)
	DefaultDedupCapacity    = 50000
	DefaultRawJitterMS      = 300
)

// 项目错误。调用方用 errors.Is 判定。
var (
	ErrInvalidSignature   = errors.New("futurecast: invalid signature")
	ErrThresholdNotMet    = errors.New("futurecast: admin threshold not met")
	ErrGenerationMismatch = errors.New("futurecast: admin set generation mismatch")
	ErrSignerSetMismatch  = errors.New("futurecast: signer set hash mismatch")
	ErrMsgIDMismatch      = errors.New("futurecast: msg_id does not match body")
	ErrExpired            = errors.New("futurecast: message expired")
	ErrClockSkew          = errors.New("futurecast: signature timestamp outside tolerance")
	ErrMaxHops            = errors.New("futurecast: max hops exceeded")
	ErrUnknownTopic       = errors.New("futurecast: topic not permitted by policy")
	ErrDuplicate          = errors.New("futurecast: duplicate message")
	ErrRateLimited        = errors.New("futurecast: rate limited")
	ErrBanned             = errors.New("futurecast: peer banned")
	ErrFrameTooLarge      = errors.New("futurecast: frame too large")
	ErrProtocolVersion    = errors.New("futurecast: unsupported protocol version")
	ErrPeerIDMismatch     = errors.New("futurecast: peer identity proof mismatch")
	ErrSealedInvalid      = errors.New("futurecast: sealed envelope invalid")
	ErrDirectedInvalid    = errors.New("futurecast: directed broadcast invalid")
	ErrNotAuthorized      = errors.New("futurecast: not authorized")
)

// ---------- 定长 ID 类型 ----------

// Hash 是 SHA-256 摘要。
type Hash [HashSize]byte

// KeyID 是管理员密钥标识。
type KeyID [KeyIDSize]byte

// NodeID 是节点标识。
type NodeID [NodeIDSize]byte

// Sum256 计算 SHA-256。
func Sum256(b []byte) Hash { return Hash(sha256.Sum256(b)) }

// HashOf 计算任意数据的 SHA-256。
func HashOf(parts ...[]byte) Hash {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleOrLeaf 占位：内容分片的哈希。
func ChunkHash(data []byte) Hash { return Sum256(data) }

// KeyIDFromPub 由 ed25519 公钥派生 KeyID。
func KeyIDFromPub(pub []byte) KeyID {
	s := sha256.Sum256(pub)
	var k KeyID
	copy(k[:], s[:KeyIDSize])
	return k
}

// NodeIDFromPub 由 ed25519 公钥派生 NodeID。
func NodeIDFromPub(pub []byte) NodeID {
	s := sha256.Sum256(pub)
	return NodeID(s)
}

func (h Hash) IsZero() bool   { return h == Hash{} }
func (k KeyID) IsZero() bool  { return k == KeyID{} }
func (n NodeID) IsZero() bool { return n == NodeID{} }

func (h Hash) Bytes() []byte   { return h[:] }
func (k KeyID) Bytes() []byte  { return k[:] }
func (n NodeID) Bytes() []byte { return n[:] }

func (h Hash) String() string   { return hex.EncodeToString(h[:]) }
func (k KeyID) String() string  { return hex.EncodeToString(k[:]) }
func (n NodeID) String() string { return hex.EncodeToString(n[:]) }

// Short 返回前 8 个十六进制字符，用于日志与 UI。
func (h Hash) Short() string   { return hex.EncodeToString(h[:4]) }
func (k KeyID) Short() string  { return hex.EncodeToString(k[:4]) }
func (n NodeID) Short() string { return hex.EncodeToString(n[:4]) }

// KeyIDFromBytes 解析 KeyID，长度必须精确匹配。
func KeyIDFromBytes(b []byte) (KeyID, error) {
	var k KeyID
	if len(b) != KeyIDSize {
		return k, fmt.Errorf("futurecast: KeyID 长度应为 %d，实为 %d", KeyIDSize, len(b))
	}
	copy(k[:], b)
	return k, nil
}

// NodeIDFromBytes 解析 NodeID。
func NodeIDFromBytes(b []byte) (NodeID, error) {
	var n NodeID
	if len(b) != NodeIDSize {
		return n, fmt.Errorf("futurecast: NodeID 长度应为 %d，实为 %d", NodeIDSize, len(b))
	}
	copy(n[:], b)
	return n, nil
}

// HashFromBytes 解析 Hash。
func HashFromBytes(b []byte) (Hash, error) {
	var h Hash
	if len(b) != HashSize {
		return h, fmt.Errorf("futurecast: Hash 长度应为 %d，实为 %d", HashSize, len(b))
	}
	copy(h[:], b)
	return h, nil
}

// KeyIDFromHex 解析十六进制 KeyID。
func KeyIDFromHex(s string) (KeyID, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return KeyID{}, err
	}
	return KeyIDFromBytes(b)
}

// NodeIDFromHex 解析十六进制 NodeID。
func NodeIDFromHex(s string) (NodeID, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return NodeID{}, err
	}
	return NodeIDFromBytes(b)
}

// HashFromHex 解析十六进制 Hash。
func HashFromHex(s string) (Hash, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return Hash{}, err
	}
	return HashFromBytes(b)
}

// XorDistance 返回两节点 ID 的异或距离，用于 Kademlia 路由。
func XorDistance(a, b NodeID) NodeID {
	var d NodeID
	for i := range d {
		d[i] = a[i] ^ b[i]
	}
	return d
}

// CommonPrefixLen 返回两个节点 ID 的公共前缀比特数，即 Kademlia 桶序号。
func CommonPrefixLen(a, b NodeID) int {
	for i := 0; i < NodeIDSize; i++ {
		x := a[i] ^ b[i]
		if x == 0 {
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if x&(1<<uint(bit)) != 0 {
				return i*8 + (7 - bit)
			}
		}
	}
	return NodeIDSize * 8
}

// CompareNodeID 比较异或距离大小：-1 表示 a 更近，1 表示 b 更近，0 表示相等。
func CompareNodeID(target, a, b NodeID) int {
	da := XorDistance(target, a)
	db := XorDistance(target, b)
	for i := 0; i < NodeIDSize; i++ {
		switch {
		case da[i] < db[i]:
			return -1
		case da[i] > db[i]:
			return 1
		}
	}
	return 0
}

// ConstantTimeEqual 常数时间比较，用于比较摘要类数据。
func ConstantTimeEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// RandomBytes 返回密码学安全随机字节。
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("futurecast: 系统随机源不可用: " + err.Error())
	}
	return b
}

// RandomNonce 返回 16 字节 nonce。
func RandomNonce() []byte { return RandomBytes(NonceSize) }

// RandomUint64 返回随机 64 位无符号整数。
func RandomUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("futurecast: 系统随机源不可用: " + err.Error())
	}
	return binary.BigEndian.Uint64(b[:])
}

// Uint64BE 大端编码。
func Uint64BE(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// PutUint32BE 写入 4 字节大端长度前缀。
func PutUint32BE(dst []byte, v uint32) { binary.BigEndian.PutUint32(dst, v) }

// Uint32BE 读取 4 字节大端。
func Uint32BE(b []byte) uint32 { return binary.BigEndian.Uint32(b) }
