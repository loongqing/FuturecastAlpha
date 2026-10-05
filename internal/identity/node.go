// Package identity 管理节点身份密钥与超级管理员密钥。
package identity

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// NodeIdentity 是一个节点的长期身份。
type NodeIdentity struct {
	ID      housekitchen.NodeID
	Priv    ed25519.PrivateKey
	Pub     ed25519.PublicKey
	KeySeed []byte
}

// NewNodeIdentity 生成全新节点身份。
func NewNodeIdentity() (*NodeIdentity, error) {
	seed, err := crypto.GenerateSeed()
	if err != nil {
		return nil, err
	}
	return NodeIdentityFromSeed(seed)
}

// NodeIdentityFromSeed 由 32 字节种子派生节点身份。
func NodeIdentityFromSeed(seed []byte) (*NodeIdentity, error) {
	priv, err := crypto.KeyFromSeed(seed)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &NodeIdentity{
		ID:      housekitchen.NodeIDFromPub(pub),
		Priv:    priv,
		Pub:     pub,
		KeySeed: append([]byte(nil), seed...),
	}, nil
}

// LoadOrCreateNodeIdentity 从 path 加载节点身份，不存在则创建并写入。
func LoadOrCreateNodeIdentity(path string) (*NodeIdentity, error) {
	if raw, err := os.ReadFile(path); err == nil {
		seed, decErr := decodeSeedFile(raw)
		if decErr != nil {
			return nil, fmt.Errorf("futurecast: 解析节点密钥 %s 失败: %w", path, decErr)
		}
		return NodeIdentityFromSeed(seed)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("futurecast: 读取节点密钥 %s 失败: %w", path, err)
	}

	id, err := NewNodeIdentity()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("futurecast: 创建密钥目录失败: %w", err)
	}
	if err := os.WriteFile(path, encodeSeedFile(id.KeySeed), 0o600); err != nil {
		return nil, fmt.Errorf("futurecast: 写入节点密钥失败: %w", err)
	}
	return id, nil
}

// SignHello 对握手消息自证，证明 node_id 与公钥的绑定关系。
func (n *NodeIdentity) SignHello(h *pb.Hello) ([]byte, error) {
	canonical, err := housekitchen.CanonicalHello(h)
	if err != nil {
		return nil, err
	}
	return crypto.SignCanonical(n.Priv, canonical), nil
}

// VerifyHello 校验对端握手自证，并确认 node_id 确实源自其公钥。
func VerifyHello(h *pb.Hello) error {
	pub := h.GetPublicKey().GetEd25519()
	if len(pub) != crypto.PubKeySize {
		return fmt.Errorf("%w: 公钥长度非法", housekitchen.ErrPeerIDMismatch)
	}
	want := housekitchen.NodeIDFromPub(pub)
	if housekitchen.GetNodeID(h.GetNodeId()) != want {
		return fmt.Errorf("%w: node_id 与公钥不匹配", housekitchen.ErrPeerIDMismatch)
	}
	canonical, err := housekitchen.CanonicalHello(h)
	if err != nil {
		return err
	}
	if !crypto.VerifyCanonical(ed25519.PublicKey(pub), canonical, h.GetSelfSignature()) {
		return fmt.Errorf("%w: 握手签名无效", housekitchen.ErrPeerIDMismatch)
	}
	return nil
}

// SignPeerExchange 对邻居互推列表自证。
func (n *NodeIdentity) SignPeerExchange(pe *pb.PeerExchange) ([]byte, error) {
	canonical, err := housekitchen.CanonicalPeerExchange(pe)
	if err != nil {
		return nil, err
	}
	return crypto.SignCanonical(n.Priv, canonical), nil
}

// VerifyPeerExchange 校验邻居互推列表的自证签名。
func VerifyPeerExchange(pub ed25519.PublicKey, pe *pb.PeerExchange) error {
	canonical, err := housekitchen.CanonicalPeerExchange(pe)
	if err != nil {
		return err
	}
	if !crypto.VerifyCanonical(pub, canonical, pe.GetSelfSignature()) {
		return fmt.Errorf("%w: 邻居互推签名无效", housekitchen.ErrInvalidSignature)
	}
	return nil
}

// SignNodeAnnounce 对节点动态自证。
func (n *NodeIdentity) SignNodeAnnounce(a *pb.NodeAnnounce) ([]byte, error) {
	canonical, err := housekitchen.CanonicalNodeAnnounce(a)
	if err != nil {
		return nil, err
	}
	return crypto.SignCanonical(n.Priv, canonical), nil
}

// VerifyNodeAnnounceWithPub 用已知公钥校验节点动态。
func VerifyNodeAnnounceWithPub(pub ed25519.PublicKey, a *pb.NodeAnnounce) error {
	if len(pub) != crypto.PubKeySize {
		return fmt.Errorf("%w: 公钥长度非法", housekitchen.ErrInvalidSignature)
	}
	if housekitchen.NodeIDFromPub(pub) != housekitchen.GetNodeID(a.GetNodeId()) {
		return fmt.Errorf("%w: node_id 与公钥不匹配", housekitchen.ErrPeerIDMismatch)
	}
	canonical, err := housekitchen.CanonicalNodeAnnounce(a)
	if err != nil {
		return err
	}
	if !crypto.VerifyCanonical(pub, canonical, a.GetSelfSignature()) {
		return fmt.Errorf("%w: 节点动态签名无效", housekitchen.ErrInvalidSignature)
	}
	return nil
}

// NodeIDOf 由公钥推导 NodeID。
func NodeIDOf(pub ed25519.PublicKey) housekitchen.NodeID {
	return housekitchen.NodeIDFromPub(pub)
}
