package identity

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// AdminKey 是一把超级管理员密钥（含私钥，仅签发侧持有）。
type AdminKey struct {
	KeyID      housekitchen.KeyID
	Label      string
	Role       pb.AdminRole
	Priv       ed25519.PrivateKey
	Pub        ed25519.PublicKey
	KeySeed    []byte
	X25519Priv []byte
}

// NewAdminKey 生成一把新的超级管理员密钥。
func NewAdminKey(label string, role pb.AdminRole) (*AdminKey, error) {
	seed, err := crypto.GenerateSeed()
	if err != nil {
		return nil, err
	}
	return AdminKeyFromSeed(seed, label, role)
}

// AdminKeyFromSeed 由种子派生管理员密钥。
func AdminKeyFromSeed(seed []byte, label string, role pb.AdminRole) (*AdminKey, error) {
	priv, err := crypto.KeyFromSeed(seed)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &AdminKey{
		KeyID:   housekitchen.KeyIDFromPub(pub),
		Label:   label,
		Role:    role,
		Priv:    priv,
		Pub:     pub,
		KeySeed: append([]byte(nil), seed...),
	}, nil
}

// Public 返回该密钥的公开表示。
func (k *AdminKey) Public() *pb.AdminKey {
	return &pb.AdminKey{
		KeyId:     housekitchen.PBKeyID(k.KeyID),
		PublicKey: &pb.PubKey{Ed25519: k.Pub},
		Label:     k.Label,
		Role:      k.Role,
	}
}

// Sign 用该密钥对 canonical 字节签名。
func (k *AdminKey) Sign(canonical []byte, at time.Time) *pb.Signature {
	return crypto.SignBody(k.Priv, canonical, k.KeyID, at)
}

// VerifyAgainst 用该密钥校验一个签名。
func (k *AdminKey) VerifyAgainst(canonical []byte, sig *pb.Signature) error {
	return crypto.VerifySignature(k.Pub, canonical, sig)
}

// Keyring 是签发侧持有的管理员密钥集合。
type Keyring struct {
	Keys map[housekitchen.KeyID]*AdminKey
}

// NewKeyring 创建空密钥环。
func NewKeyring() *Keyring { return &Keyring{Keys: map[housekitchen.KeyID]*AdminKey{}} }

// Add 加入一把密钥。
func (r *Keyring) Add(k *AdminKey) { r.Keys[k.KeyID] = k }

// Get 按键 ID 取密钥。
func (r *Keyring) Get(id housekitchen.KeyID) (*AdminKey, bool) {
	k, ok := r.Keys[id]
	return k, ok
}

// BuildAdminSet 由密钥环构建创世 AdminSet（或指定代数的集合）。
func (r *Keyring) BuildAdminSet(generation uint64, threshold, total uint32, label string) (*pb.AdminSet, error) {
	if threshold == 0 || threshold > total {
		return nil, fmt.Errorf("futurecast: 门限 %d 必须落在 (0, %d]", threshold, total)
	}
	if len(r.Keys) < int(total) {
		return nil, fmt.Errorf("futurecast: 需要 %d 把密钥，实有 %d", total, len(r.Keys))
	}
	set := &pb.AdminSet{
		Generation: generation,
		Policy: &pb.SigningPolicy{
			Threshold:               threshold,
			Total:                   total,
			Scheme:                  pb.SigningScheme_SIGNING_SCHEME_ED25519_MULTISIG,
			ClockSkewToleranceNanos: housekitchen.DefaultClockSkewNanos,
		},
		CreatedAtUnixNanos: time.Now().UnixNano(),
	}
	// 按 KeyID 字典序排序，保证任何实现构建出的 AdminSet 字节一致。
	ids := make([]housekitchen.KeyID, 0, len(r.Keys))
	for id := range r.Keys {
		ids = append(ids, id)
	}
	sortKeyIDs(ids)
	for _, id := range ids {
		k := r.Keys[id]
		set.Keys = append(set.Keys, k.Public())
		set.Policy.RootKeyIds = append(set.Policy.RootKeyIds, housekitchen.PBKeyID(id))
	}
	return set, nil
}

func sortKeyIDs(ids []housekitchen.KeyID) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && lessKeyID(ids[j], ids[j-1]); j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}

func lessKeyID(a, b housekitchen.KeyID) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// pubKeyResolver 由 AdminSet 构建 key_id → 公钥 的解析器。
func PubKeyResolver(set *pb.AdminSet) func(housekitchen.KeyID) (ed25519.PublicKey, bool) {
	index := make(map[housekitchen.KeyID]ed25519.PublicKey, len(set.GetKeys()))
	for _, k := range set.GetKeys() {
		id := housekitchen.GetKeyID(k.GetKeyId())
		pub := k.GetPublicKey().GetEd25519()
		index[id] = ed25519.PublicKey(pub)
	}
	return func(id housekitchen.KeyID) (ed25519.PublicKey, bool) {
		p, ok := index[id]
		return p, ok
	}
}

// RootKeyIDs 提取 AdminSet 的 root_key_ids。
func RootKeyIDs(set *pb.AdminSet) []housekitchen.KeyID {
	ids := set.GetPolicy().GetRootKeyIds()
	out := make([]housekitchen.KeyID, 0, len(ids))
	for _, id := range ids {
		out = append(out, housekitchen.GetKeyID(id))
	}
	return out
}
