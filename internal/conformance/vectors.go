// Package conformance 导出跨语言互通的确定性基准向量，并以攻击者/外部实现者的
// 视角固化 FutureCast 冻结协议（docs/CONTRACTS.md §2/§3/§4/§5）的行为。
//
// 本包是纯只读消费者：不修改 housekitchen / crypto / identity / registry / sealed
// 中的任何字节码或语义，只调用其公开 API。所有向量输入均为固定常量（种子由
// SHA-256(label) 派生），因此 Build() 的输出在任意机器、任意次数运行下逐字节一致。
//
// 目标：让一个不导入任何 Go 代码的 Rust/Python 实现，仅凭 vectors.json 里的
// 输入 + 公式，就能算出同样的 SIGNED_BYTES / MSG_ID / SIGN_INPUT / relay_tag /
// 封存密钥，并用本文件的 golden 十六进制自证互通。
//
// 注意：冻结接口在本文件编写期间发生过一次演进（AdminSet/SealedPayload 独立域
// 前缀、SignWithDomain 改为单前缀）。本包所有的域前缀都从 housekitchen 的导出常量
// 读取，因此接口再次演进时向量会随之更新，而"冻结守卫"测试会立刻报错提醒复核。
package conformance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
	fccrypto "github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
	"github.com/loongqing/FuturecastAlpha/internal/registry"
)

// SealedBodyInfo / SealedADPrefix 镜像 internal/sealed/sealed.go 中**未导出**的
// sealedInfo 与 adPrefix 常量。它们不是公开接口，跨语言实现只能以本向量为准
// （Finding F12）。
const (
	SealedBodyInfo = "fc/v1/sealed"
	SealedADPrefix = "futurecast/v1/sealed\x00"
)

// VectorTime 是所有向量使用的固定时刻：2023-11-14T22:13:20Z。
var VectorTime = time.Unix(1700000000, 0)

// ---------- JSON 结构（字段名即跨语言 ABI，勿随意重命名） ----------

// Vectors 是一份完整的跨语言基准向量集。
type Vectors struct {
	Meta         Meta               `json:"meta"`
	Domains      []DomainVector     `json:"domains"`
	Derivations  []Derivation       `json:"derivations"`
	Findings     []Finding          `json:"findings"`
	AdminSet     AdminSetVector     `json:"admin_set"`
	SignedBody   SignedBodyVector   `json:"signed_body"`
	NodeAnnounce NodeAnnounceVector `json:"node_announce"`
	Sealed       SealedVector       `json:"sealed"`
	Directed     DirectedVector     `json:"directed"`
	RelayTag     RelayTagVector     `json:"relay_tag"`
	Negative     []NegativeVector   `json:"negative_expectations"`
}

// Meta 描述向量集的来源与复现方式。
type Meta struct {
	FormatVersion    string `json:"format_version"`
	Protocol         string `json:"protocol"`
	ProtoVersion     uint32 `json:"proto_version"`
	GeneratedBy      string `json:"generated_by"`
	Determinism      string `json:"determinism"`
	Reproduce        string `json:"reproduce"`
	ContractRevision string `json:"contract_revision_note"`
}

// DomainVector 是一个域分隔前缀的原始字节。
type DomainVector struct {
	Name        string `json:"name"`
	ASCII       string `json:"ascii"`
	Hex         string `json:"hex"`
	Purpose     string `json:"purpose"`
	Implemented bool   `json:"implemented_in_housekitchen"`
}

// Derivation 是一条可实现的派生公式（伪代码）。
type Derivation struct {
	Name    string `json:"name"`
	Formula string `json:"formula"`
}

// Finding 记录一处跨语言歧义、文档与实现冲突，或协议安全缺口。
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
	Contract string `json:"contract_reference"`
	Evidence string `json:"evidence"`
	Status   string `json:"status"`
}

// PolicyVector 是 SigningPolicy 的字段级输入。
type PolicyVector struct {
	Threshold               uint32   `json:"threshold"`
	Total                   uint32   `json:"total"`
	RootKeyIDsHex           []string `json:"root_key_ids_hex"`
	Scheme                  uint32   `json:"scheme"`
	SchemeName              string   `json:"scheme_name"`
	ClockSkewToleranceNanos int64    `json:"clock_skew_tolerance_nanos"`
}

// AdminKeyVector 是一把管理员密钥的固定输入与其派生值。
type AdminKeyVector struct {
	Label    string `json:"label"`
	Role     uint32 `json:"role"`
	RoleName string `json:"role_name"`
	SeedHex  string `json:"seed_hex"`
	PubHex   string `json:"pub_hex"`
	KeyIDHex string `json:"key_id_hex"`
}

// AdminSetVector 是创世 AdminSet 的规范化向量。
type AdminSetVector struct {
	Generation         uint64           `json:"generation"`
	CreatedAtUnixNanos int64            `json:"created_at_unix_nanos"`
	Policy             PolicyVector     `json:"policy"`
	Keys               []AdminKeyVector `json:"keys"`
	DomainUsedASCII    string           `json:"domain_used_ascii"`
	DomainUsedHex      string           `json:"domain_used_hex"`
	ProtoHex           string           `json:"proto_hex"`
	SignedBytesHex     string           `json:"signed_bytes_hex"`
	AdminSetHashHex    string           `json:"admin_set_hash_hex"`
	Note               string           `json:"note"`
}

// SignatureVector 是单个门限签名的固定输入与输出。
type SignatureVector struct {
	KeyIDHex          string `json:"key_id_hex"`
	SignedAtUnixNanos int64  `json:"signed_at_unix_nanos"`
	SignInputHex      string `json:"sign_input_hex"`
	SignatureHex      string `json:"signature_hex"`
}

// TextPayloadInput 是 TextPayload 的字段级输入。
type TextPayloadInput struct {
	MediaType string `json:"media_type"`
	Body      string `json:"body"`
}

// SignedBodyVector 是一条 2-of-3 管理员广播的完整向量。
type SignedBodyVector struct {
	ProtoVersion       uint32            `json:"proto_version"`
	Kind               uint32            `json:"kind"`
	KindName           string            `json:"kind_name"`
	Topic              string            `json:"topic"`
	CreatedAtUnixNanos int64             `json:"created_at_unix_nanos"`
	ExpiresAtUnixNanos int64             `json:"expires_at_unix_nanos"`
	NonceHex           string            `json:"nonce_hex"`
	AdminSetGeneration uint64            `json:"admin_set_generation"`
	SignerSetHashHex   string            `json:"signer_set_hash_hex"`
	Policy             PolicyVector      `json:"policy"`
	MaxHops            int64             `json:"max_hops"`
	PayloadOneof       string            `json:"payload_oneof"`
	PayloadText        *TextPayloadInput `json:"payload_text,omitempty"`
	ProtoHex           string            `json:"proto_hex"`
	SignedBytesHex     string            `json:"signed_bytes_hex"`
	MsgIDHex           string            `json:"msg_id_hex"`
	Signers            []SignatureVector `json:"signers"`
	EnvelopeMsgIDHex   string            `json:"envelope_msg_id_hex"`
	EnvelopeFirstSeen  int64             `json:"envelope_first_seen_unix_nanos"`
	EnvelopeHops       uint32            `json:"envelope_hops"`
	Note               string            `json:"note"`
}

// NodeAnnounceVector 是节点自证的规范化与签名向量。
//
// 当前实现（SignWithDomain 单前缀）：被签名的字节就是 CanonicalNodeAnnounce
// 的输出，即 DOMAIN || deterministic_proto(msg)，域只出现一次。
type NodeAnnounceVector struct {
	NodeSeedHex        string   `json:"node_seed_hex"`
	NodePubHex         string   `json:"node_pub_hex"`
	NodeIDHex          string   `json:"node_id_hex"`
	Addrs              []string `json:"addrs"`
	AddressPublic      bool     `json:"address_public"`
	RendezvousHintHex  string   `json:"rendezvous_hint_hex"`
	Seq                int64    `json:"seq"`
	IssuedAtUnixNanos  int64    `json:"issued_at_unix_nanos"`
	ProtoHex           string   `json:"proto_hex"`
	SignedBytesHex     string   `json:"signed_bytes_hex"`
	SignDigestInputHex string   `json:"sign_digest_input_hex"`
	SignDigestHex      string   `json:"sign_digest_hex"`
	SelfSignatureHex   string   `json:"self_signature_hex"`
	DomainPrefixCount  int      `json:"domain_prefix_count_in_digest"`
}

// TopicKeyWrapVector 是主题密钥封装（crypto.WrapTopicKey）向量。
type TopicKeyWrapVector struct {
	EphemeralX25519PrivHex string `json:"ephemeral_x25519_priv_hex"`
	EphemeralX25519PubHex  string `json:"ephemeral_x25519_pub_hex"`
	SharedSecretHex        string `json:"shared_secret_hex"`
	HKDFHash               string `json:"hkdf_hash"`
	HKDFSaltHex            string `json:"hkdf_salt_hex"`
	HKDFSaltNote           string `json:"hkdf_salt_note"`
	HKDFInfoASCII          string `json:"hkdf_info_ascii"`
	DerivedKeyHex          string `json:"derived_key_hex"`
	PlaintextTopicKeyHex   string `json:"plaintext_topic_key_hex"`
	AssociatedDataHex      string `json:"associated_data_hex"`
	NonceHex               string `json:"nonce_hex"`
	CiphertextHex          string `json:"ciphertext_hex"`
	SealedHex              string `json:"sealed_hex"`
}

// SealedBodyVector 是"超管 → 中继"封存整条 SignedBody 的向量，
// 形状对齐 internal/sealed/sealed.go（field 1 = rendezvous，ciphertext 承载完整正文）。
type SealedBodyVector struct {
	InfoASCII                 string `json:"hkdf_info_ascii"`
	AssociatedDataHex         string `json:"associated_data_hex"`
	AssociatedDataPrefix      string `json:"associated_data_prefix_ascii"`
	EphemeralX25519PrivHex    string `json:"ephemeral_x25519_priv_hex"`
	EphemeralX25519PubHex     string `json:"ephemeral_x25519_pub_hex"`
	SharedSecretHex           string `json:"shared_secret_hex"`
	DerivedKeyHex             string `json:"derived_key_hex"`
	NonceHex                  string `json:"nonce_hex"`
	CiphertextHex             string `json:"ciphertext_hex"`
	SealedHex                 string `json:"sealed_hex"`
	PlaintextFullBodyProtoHex string `json:"plaintext_full_body_proto_hex"`
	SealedPayloadProtoHex     string `json:"sealed_payload_proto_hex"`
	SealedPayloadSignedHex    string `json:"sealed_payload_signed_bytes_hex"`
}

// NodeRelaySealedVector 是 internal/node 的另一种封存形状：
// field 1 被复用为 SHA-256(inner_body) 承诺值，inner_body 明文承载完整正文，ciphertext 留空。
// 它与 SealedBodyVector 互不兼容（Finding F12）。
type NodeRelaySealedVector struct {
	InnerBodyProtoHex      string `json:"inner_body_proto_hex"`
	CommitmentHex          string `json:"inner_body_sha256_hex"`
	SealedPayloadProtoHex  string `json:"sealed_payload_proto_hex"`
	SealedPayloadSignedHex string `json:"sealed_payload_signed_bytes_hex"`
	Note                   string `json:"note"`
}

// SealedVector 汇总两条封存路径的向量。
type SealedVector struct {
	RecipientX25519PrivHex string                `json:"recipient_x25519_priv_hex"`
	RecipientX25519PubHex  string                `json:"recipient_x25519_pub_hex"`
	RendezvousHex          string                `json:"inbox_rendezvous_id_hex"`
	Epoch                  uint64                `json:"epoch"`
	JitterHintMS           uint64                `json:"jitter_hint_ms"`
	TopicKeyWrap           TopicKeyWrapVector    `json:"topic_key_wrap"`
	SealedBody             SealedBodyVector      `json:"sealed_body"`
	NodeRelay              NodeRelaySealedVector `json:"node_relay_sealed"`
	Note                   string                `json:"note"`
}

// RelayTagVector 是轮换中继标签的确定性向量。
type RelayTagVector struct {
	DailyKeyHex  string   `json:"daily_key_hex"`
	MsgIDHex     string   `json:"msg_id_hex"`
	PreviousTags []uint64 `json:"previous_tags"`
	Tags         []uint64 `json:"tags"`
	Formula      string   `json:"formula"`
}

// NegativeVector 描述一个必须失败的对抗性输入及其判定顺序。
type NegativeVector struct {
	ID            string `json:"id"`
	Attack        string `json:"attack"`
	ExpectedError string `json:"expected_error"`
	PipelineStep  string `json:"pipeline_step"`
	Construction  string `json:"construction"`
}

// ---------- 构建入口 ----------

// Build 构造全部向量。任何内部一致性校验失败都会返回错误——也就是说，
// vectors.json 只有在 golden 向量真的能被冻结实现接受时才会产出。
func Build() (*Vectors, error) {
	v := &Vectors{
		Meta: Meta{
			FormatVersion:    "1",
			Protocol:         "futurecast/v1",
			ProtoVersion:     housekitchen.ProtoVersion,
			GeneratedBy:      "github.com/loongqing/FuturecastAlpha/internal/conformance",
			Determinism:      "所有输入为常量；密钥种子 = SHA-256(label)；Ed25519 为 RFC8032 确定性签名；AEAD 使用固定 nonce",
			Reproduce:        "go run ./scripts/vectors",
			ContractRevision: "域前缀从 housekitchen 导出常量读取；冻结守卫测试会锁定其字节值",
		},
		Domains:     domainVectors(),
		Derivations: derivations(),
		Findings:    Findings(),
		Negative:    negativeVectors(),
	}

	body, err := buildAdminSetAndBody(v)
	if err != nil {
		return nil, err
	}
	if err := buildNodeAnnounce(v); err != nil {
		return nil, err
	}
	if err := buildSealed(v, body); err != nil {
		return nil, err
	}
	if err := buildDirected(v); err != nil {
		return nil, err
	}
	buildRelayTag(v)
	return v, nil
}

// WriteJSON 把向量以缩进 JSON 写出，输出确定性（encoding/json 对结构体按声明序、
// 对 map 按键排序），并以换行结尾。
func WriteJSON(w io.Writer, v *Vectors) error {
	if v == nil {
		return fmt.Errorf("futurecast/conformance: 向量为空")
	}
	enc, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("futurecast/conformance: 序列化向量失败: %w", err)
	}
	if _, err := w.Write(enc); err != nil {
		return err
	}
	_, err = io.WriteString(w, "\n")
	return err
}

// ---------- 内部构建 ----------

// genesisAdminFixture 构造 admin_set 向量所用的那把创世 AdminSet（gen=1，2-of-3）
// 与三把已按 key_id 字典序排序的密钥。
//
// directed 向量复用同一份集合，因此它的 signer_set_hash 与 admin_set 段完全一致，
// 外部实现者只需要一份 AdminSet 就能同时复现两类消息。
func genesisAdminFixture() (*pb.AdminSet, []*identity.AdminKey, error) {
	labels := []string{"alice", "bob", "carol"}
	keys := make([]*identity.AdminKey, 0, 3)
	for i, lbl := range labels {
		seed := derive32(fmt.Sprintf("futurecast/vector/admin-%s-%d", lbl, i+1))
		k, err := identity.AdminKeyFromSeed(seed, lbl, pb.AdminRole_ADMIN_ROLE_ROOT)
		if err != nil {
			return nil, nil, fmt.Errorf("构造管理员密钥 %s 失败: %w", lbl, err)
		}
		keys = append(keys, k)
	}
	sortKeys(keys)

	policy := &pb.SigningPolicy{
		Threshold:               2,
		Total:                   3,
		Scheme:                  pb.SigningScheme_SIGNING_SCHEME_ED25519_MULTISIG,
		ClockSkewToleranceNanos: housekitchen.DefaultClockSkewNanos,
	}
	set := &pb.AdminSet{
		Generation:         1,
		Policy:             policy,
		CreatedAtUnixNanos: VectorTime.UnixNano(),
	}
	for _, k := range keys {
		set.Keys = append(set.Keys, k.Public())
		policy.RootKeyIds = append(policy.RootKeyIds, housekitchen.PBKeyID(k.KeyID))
	}
	return set, keys, nil
}

func buildAdminSetAndBody(v *Vectors) (*pb.SignedBody, error) {
	set, keys, err := genesisAdminFixture()
	if err != nil {
		return nil, err
	}
	policy := set.GetPolicy()
	keyVecs := make([]AdminKeyVector, 0, len(keys))
	for _, k := range keys {
		keyVecs = append(keyVecs, AdminKeyVector{
			Label:    k.Label,
			Role:     uint32(k.Role),
			RoleName: k.Role.String(),
			SeedHex:  hexStr(k.KeySeed),
			PubHex:   hexStr(k.Pub),
			KeyIDHex: hexStr(k.KeyID.Bytes()),
		})
	}

	canonicalSet, err := housekitchen.CanonicalAdminSet(set)
	if err != nil {
		return nil, err
	}
	setHash, err := housekitchen.AdminSetHash(set)
	if err != nil {
		return nil, err
	}
	adminDomain := housekitchen.DomainAdminSet
	v.AdminSet = AdminSetVector{
		Generation:         set.GetGeneration(),
		CreatedAtUnixNanos: set.GetCreatedAtUnixNanos(),
		Policy:             policyVector(policy),
		Keys:               keyVecs,
		DomainUsedASCII:    adminDomain,
		DomainUsedHex:      hexStr([]byte(adminDomain)),
		ProtoHex:           hexStr(canonicalSet[len(adminDomain):]),
		SignedBytesHex:     hexStr(canonicalSet),
		AdminSetHashHex:    hexStr(setHash.Bytes()),
		Note:               "AdminSet 使用独立域前缀 DomainAdminSet（曾与 SignedBody 共用前缀，已修正）。keys/root_key_ids 必须是按 key_id 字典序排序后的顺序。",
	}

	nonce := derive32("futurecast/vector/signed-body-nonce")[:housekitchen.NonceSize]
	body := &pb.SignedBody{
		ProtoVersion:       housekitchen.ProtoVersion,
		Kind:               pb.MessageKind_MESSAGE_KIND_ADMIN_BROADCAST,
		Topic:              "alerts",
		CreatedAtUnixNanos: VectorTime.UnixNano(),
		ExpiresAtUnixNanos: VectorTime.Add(time.Hour).UnixNano(),
		Nonce:              nonce,
		AdminSetGeneration: 1,
		SignerSetHash:      housekitchen.PBHash(setHash),
		Policy:             policy,
		MaxHops:            housekitchen.DefaultMaxHops,
		Payload: &pb.Payload{Payload: &pb.Payload_Text{Text: &pb.TextPayload{
			MediaType: "text/plain",
			Body:      "futurecast interop vector #1",
		}}},
	}
	canonicalBody, err := housekitchen.CanonicalSignedBody(body)
	if err != nil {
		return nil, err
	}
	msgID := housekitchen.MsgIDFromCanonical(canonicalBody)

	sigVecs := make([]SignatureVector, 0, 2)
	sigs := make([]*pb.Signature, 0, 2)
	for _, k := range keys[:2] {
		sig := k.Sign(canonicalBody, VectorTime)
		sigs = append(sigs, sig)
		sigVecs = append(sigVecs, SignatureVector{
			KeyIDHex:          hexStr(k.KeyID.Bytes()),
			SignedAtUnixNanos: sig.GetSignedAtUnixNanos(),
			SignInputHex:      hexStr(housekitchen.SignInput(canonicalBody, k.KeyID, sig.GetSignedAtUnixNanos()).Bytes()),
			SignatureHex:      hexStr(sig.GetSignature()),
		})
	}
	body.MsgId = housekitchen.PBHash(msgID)
	body.Signers = sigs

	reg, err := registry.New(set, registry.Options{Now: func() time.Time { return VectorTime }})
	if err != nil {
		return nil, fmt.Errorf("registry.New 失败: %w", err)
	}
	env := registry.WrapEnvelope(body, VectorTime)
	res, err := reg.VerifyMessage(env, registry.Session{Now: VectorTime})
	if err != nil {
		return nil, fmt.Errorf("golden 向量未被 registry 接受（向量本身有误）: %w", err)
	}
	if !res.AdminAuthorized || len(res.Signers) != 2 {
		return nil, fmt.Errorf("golden 向量未通过门限校验: admin=%v signers=%d", res.AdminAuthorized, len(res.Signers))
	}

	v.SignedBody = SignedBodyVector{
		ProtoVersion:       body.GetProtoVersion(),
		Kind:               uint32(body.GetKind()),
		KindName:           body.GetKind().String(),
		Topic:              body.GetTopic(),
		CreatedAtUnixNanos: body.GetCreatedAtUnixNanos(),
		ExpiresAtUnixNanos: body.GetExpiresAtUnixNanos(),
		NonceHex:           hexStr(body.GetNonce()),
		AdminSetGeneration: body.GetAdminSetGeneration(),
		SignerSetHashHex:   hexStr(housekitchen.GetHash(body.GetSignerSetHash()).Bytes()),
		Policy:             policyVector(policy),
		MaxHops:            body.GetMaxHops(),
		PayloadOneof:       "text",
		PayloadText:        &TextPayloadInput{MediaType: "text/plain", Body: "futurecast interop vector #1"},
		ProtoHex:           hexStr(canonicalBody[len(housekitchen.DomainSignedBody):]),
		SignedBytesHex:     hexStr(canonicalBody),
		MsgIDHex:           hexStr(msgID.Bytes()),
		Signers:            sigVecs,
		EnvelopeMsgIDHex:   hexStr(housekitchen.GetHash(env.GetMsgId()).Bytes()),
		EnvelopeFirstSeen:  env.GetFirstSeenUnixNanos(),
		EnvelopeHops:       env.GetHops(),
		Note:               "canonical 编码前清空 msg_id(field 4) 与 signers(field 12)；proto3 默认值省略；字段按字段号升序。",
	}
	return body, nil
}

func buildNodeAnnounce(v *Vectors) error {
	seed := derive32("futurecast/vector/node-1")
	node, err := identity.NodeIdentityFromSeed(seed)
	if err != nil {
		return err
	}
	announce := &pb.NodeAnnounce{
		NodeId:            housekitchen.PBNodeID(node.ID),
		Addrs:             []string{"127.0.0.1:7777"},
		AddressPublic:     true,
		RendezvousHint:    housekitchen.PBHash(housekitchen.Sum256([]byte("futurecast/vector/rendezvous"))),
		Seq:               42,
		IssuedAtUnixNanos: VectorTime.UnixNano(),
	}
	canonical, err := housekitchen.CanonicalNodeAnnounce(announce)
	if err != nil {
		return err
	}
	sig, err := node.SignNodeAnnounce(announce)
	if err != nil {
		return err
	}
	announce.SelfSignature = sig
	if err := identity.VerifyNodeAnnounceWithPub(node.Pub, announce); err != nil {
		return fmt.Errorf("golden NodeAnnounce 自证失败: %w", err)
	}
	digest := sha256.Sum256(canonical)

	v.NodeAnnounce = NodeAnnounceVector{
		NodeSeedHex:        hexStr(seed),
		NodePubHex:         hexStr(node.Pub),
		NodeIDHex:          hexStr(node.ID.Bytes()),
		Addrs:              announce.GetAddrs(),
		AddressPublic:      announce.GetAddressPublic(),
		RendezvousHintHex:  hexStr(housekitchen.GetHash(announce.GetRendezvousHint()).Bytes()),
		Seq:                announce.GetSeq(),
		IssuedAtUnixNanos:  announce.GetIssuedAtUnixNanos(),
		ProtoHex:           hexStr(canonical[len(housekitchen.DomainNodeAnnounce):]),
		SignedBytesHex:     hexStr(canonical),
		SignDigestInputHex: hexStr(canonical),
		SignDigestHex:      hexStr(digest[:]),
		SelfSignatureHex:   hexStr(sig),
		DomainPrefixCount:  1,
	}
	return nil
}

func buildSealed(v *Vectors, body *pb.SignedBody) error {
	recipientPriv := derive32("futurecast/vector/x25519-recipient")
	recipientPub, err := curve25519.X25519(recipientPriv, curve25519.Basepoint)
	if err != nil {
		return err
	}
	rendezvous := housekitchen.Sum256([]byte("futurecast/vector/rendezvous"))
	const epoch = uint64(7)
	const jitterHintMS = uint64(250)

	// ---- 路径 A：主题密钥封装（info = DomainTopicKey） ----
	ephPriv := derive32("futurecast/vector/x25519-ephemeral")
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return err
	}
	shared, err := fccrypto.X25519Shared(ephPriv, recipientPub)
	if err != nil {
		return err
	}
	topicKey := derive32("futurecast/vector/topic-key")
	topicAD := []byte("futurecast/vector/associated-data")
	topicKeyDerived, err := fccrypto.HKDF(shared, nil, housekitchen.DomainTopicKey, 32)
	if err != nil {
		return err
	}
	topicNonce := derive32("futurecast/vector/aead-nonce")[:12]
	topicCT, err := sealGCMFixedNonce(topicKeyDerived, topicNonce, topicKey, topicAD)
	if err != nil {
		return err
	}
	topicSealed := append(append([]byte{}, topicNonce...), topicCT...)
	if pt, err := fccrypto.OpenFromSender(recipientPriv, ephPub, topicSealed, topicAD, housekitchen.DomainTopicKey); err != nil {
		return fmt.Errorf("golden 主题密钥向量无法被冻结 crypto 解开: %w", err)
	} else if hexStr(pt) != hexStr(topicKey) {
		return fmt.Errorf("golden 主题密钥向量明文不符")
	}

	// ---- 路径 B：封存整条 SignedBody（对齐 sealed.go / node.sealed_relay.go） ----
	fullBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		return err
	}
	bodyEphPriv := derive32("futurecast/vector/x25519-sealed-eph")
	bodyEphPub, err := curve25519.X25519(bodyEphPriv, curve25519.Basepoint)
	if err != nil {
		return err
	}
	bodyShared, err := fccrypto.X25519Shared(bodyEphPriv, recipientPub)
	if err != nil {
		return err
	}
	bodyKey, err := fccrypto.HKDF(bodyShared, nil, SealedBodyInfo, 32)
	if err != nil {
		return err
	}
	bodyAD := append(append([]byte{}, SealedADPrefix...), rendezvous.Bytes()...)
	bodyAD = append(bodyAD, housekitchen.Uint64BE(epoch)...)
	bodyNonce := derive32("futurecast/vector/sealed-body-nonce")[:12]
	bodyCT, err := sealGCMFixedNonce(bodyKey, bodyNonce, fullBody, bodyAD)
	if err != nil {
		return err
	}
	bodySealed := append(append([]byte{}, bodyNonce...), bodyCT...)
	if pt, err := fccrypto.OpenFromSender(recipientPriv, bodyEphPub, bodySealed, bodyAD, SealedBodyInfo); err != nil {
		return fmt.Errorf("golden 封存正文向量无法被冻结 crypto 解开: %w", err)
	} else if hexStr(pt) != hexStr(fullBody) {
		return fmt.Errorf("golden 封存正文向量明文不符")
	}
	commitment := housekitchen.ChunkHash(fullBody)

	// 形状 1（sealed.Seal / sealed.Open）：field 1 = rendezvous，ciphertext 承载完整正文。
	spSealed := &pb.SealedPayload{
		InboxRendezvousId: housekitchen.PBHash(rendezvous),
		Epoch:             epoch,
		EphemeralX25519:   bodyEphPub,
		Ciphertext:        bodySealed,
		JitterHintMs:      jitterHintMS,
	}
	canonicalSealed, err := housekitchen.CanonicalSealedPayload(spSealed)
	if err != nil {
		return err
	}

	// 形状 2（node.publishAsRelay / node.Unseal）：field 1 = SHA-256(inner_body) 承诺值，
	// inner_body 明文承载完整正文，ciphertext 留空。
	spNode := &pb.SealedPayload{
		InboxRendezvousId: housekitchen.PBHash(commitment),
		InnerBody:         fullBody,
	}
	canonicalNode, err := housekitchen.CanonicalSealedPayload(spNode)
	if err != nil {
		return err
	}

	v.Sealed = SealedVector{
		RecipientX25519PrivHex: hexStr(recipientPriv),
		RecipientX25519PubHex:  hexStr(recipientPub),
		RendezvousHex:          hexStr(rendezvous.Bytes()),
		Epoch:                  epoch,
		JitterHintMS:           jitterHintMS,
		TopicKeyWrap: TopicKeyWrapVector{
			EphemeralX25519PrivHex: hexStr(ephPriv),
			EphemeralX25519PubHex:  hexStr(ephPub),
			SharedSecretHex:        hexStr(shared),
			HKDFHash:               "SHA-256",
			HKDFSaltHex:            "",
			HKDFSaltNote:           "salt 为空 = RFC5869 默认的 HashLen 个 0 字节（SHA-256 时为 32 个 0x00）",
			HKDFInfoASCII:          housekitchen.DomainTopicKey,
			DerivedKeyHex:          hexStr(topicKeyDerived),
			PlaintextTopicKeyHex:   hexStr(topicKey),
			AssociatedDataHex:      hexStr(topicAD),
			NonceHex:               hexStr(topicNonce),
			CiphertextHex:          hexStr(topicCT),
			SealedHex:              hexStr(topicSealed),
		},
		SealedBody: SealedBodyVector{
			InfoASCII:                 SealedBodyInfo,
			AssociatedDataHex:         hexStr(bodyAD),
			AssociatedDataPrefix:      SealedADPrefix,
			EphemeralX25519PrivHex:    hexStr(bodyEphPriv),
			EphemeralX25519PubHex:     hexStr(bodyEphPub),
			SharedSecretHex:           hexStr(bodyShared),
			DerivedKeyHex:             hexStr(bodyKey),
			NonceHex:                  hexStr(bodyNonce),
			CiphertextHex:             hexStr(bodyCT),
			SealedHex:                 hexStr(bodySealed),
			PlaintextFullBodyProtoHex: hexStr(fullBody),
			SealedPayloadProtoHex:     hexStr(canonicalSealed[len(housekitchen.DomainSealedPayload):]),
			SealedPayloadSignedHex:    hexStr(canonicalSealed),
		},
		NodeRelay: NodeRelaySealedVector{
			InnerBodyProtoHex:      hexStr(fullBody),
			CommitmentHex:          hexStr(commitment.Bytes()),
			SealedPayloadProtoHex:  hexStr(canonicalNode[len(housekitchen.DomainSealedPayload):]),
			SealedPayloadSignedHex: hexStr(canonicalNode),
			Note:                   "field 1 在此形状下不是 rendezvous 而是 inner_body 的 SHA-256 承诺值；node.Unseal 只校验该承诺值并直接解析 inner_body，完全不解密 ciphertext。",
		},
		Note: "路径A = 主题密钥封装（info=\"fc/v1/topickey\"，AD 由调用方给定）。路径B = 封存整条 SignedBody（info=\"fc/v1/sealed\"，AD=\"futurecast/v1/sealed\\x00\" || rendezvous || u64be(epoch)）。node_relay_sealed 是同名字段的另一种互不兼容用法（Finding F12）。两条封存路径的 info/AD 常量在 sealed.go 中都是未导出私有值，跨语言实现没有公开真源。sealed = nonce(12) || AES-256-GCM ciphertext||tag。",
	}
	return nil
}

func buildRelayTag(v *Vectors) {
	dailyKey := derive32("futurecast/vector/daily-key")
	msgID, _ := housekitchen.HashFromHex(v.SignedBody.MsgIDHex)
	prev := []uint64{0, 0x0102030405060708, 0xffffffffffffffff}
	tags := make([]uint64, 0, len(prev))
	for _, p := range prev {
		tags = append(tags, fccrypto.RelayTag(dailyKey, msgID, p))
	}
	v.RelayTag = RelayTagVector{
		DailyKeyHex:  hexStr(dailyKey),
		MsgIDHex:     v.SignedBody.MsgIDHex,
		PreviousTags: prev,
		Tags:         tags,
		Formula:      "HMAC-SHA256(dailyKey, \"futurecast/v1/relaytag\\x00\" || msgID(32) || uint64_be(previousTag))[0:8] 按大端解释为 uint64",
	}
}

// ---------- 静态文本 ----------

func domainVectors() []DomainVector {
	return []DomainVector{
		{"DomainSignedBody", housekitchen.DomainSignedBody, hexStr([]byte(housekitchen.DomainSignedBody)), "SignedBody 规范化前缀", true},
		{"DomainAdminSet", housekitchen.DomainAdminSet, hexStr([]byte(housekitchen.DomainAdminSet)), "AdminSet 规范化前缀（已与 SignedBody 分离）", true},
		{"DomainSealedPayload", housekitchen.DomainSealedPayload, hexStr([]byte(housekitchen.DomainSealedPayload)), "SealedPayload 规范化前缀", true},
		{"DomainMsgID", housekitchen.DomainMsgID, hexStr([]byte(housekitchen.DomainMsgID)), "msg_id = SHA-256(该前缀 || SIGNED_BYTES)", true},
		{"DomainSignInput", housekitchen.DomainSignInput, hexStr([]byte(housekitchen.DomainSignInput)), "SIGN_INPUT 前缀（DESIGN.md §4.1 的公式仍漏写它，见 Finding F3）", true},
		{"DomainNodeAnnounce", housekitchen.DomainNodeAnnounce, hexStr([]byte(housekitchen.DomainNodeAnnounce)), "NodeAnnounce 规范化前缀；域只出现一次", true},
		{"DomainPeerExchange", housekitchen.DomainPeerExchange, hexStr([]byte(housekitchen.DomainPeerExchange)), "PeerExchange 规范化前缀", true},
		{"DomainHello", housekitchen.DomainHello, hexStr([]byte(housekitchen.DomainHello)), "Hello 规范化前缀", true},
		{"DomainRelayTag", housekitchen.DomainRelayTag, hexStr([]byte(housekitchen.DomainRelayTag)), "relay_tag HMAC 前缀", true},
		{"DomainInbox", housekitchen.DomainInbox, hexStr([]byte(housekitchen.DomainInbox)), "rendezvous_id 的 HKDF info 前缀（无 NUL 结尾；实际 info = 前缀 + \"/\" + 十进制(epoch)）", true},
		{"DomainTopicKey", housekitchen.DomainTopicKey, hexStr([]byte(housekitchen.DomainTopicKey)), "主题密钥封装的 HKDF info（无 NUL 结尾）", true},
		{"SealedBodyInfo", SealedBodyInfo, hexStr([]byte(SealedBodyInfo)), "封存整条 SignedBody 的 HKDF info；在 sealed.go 中是未导出常量 sealedInfo（Finding F12）", false},
		{"SealedADPrefix", SealedADPrefix, hexStr([]byte(SealedADPrefix)), "封存 AEAD 关联数据前缀；在 sealed.go 中是未导出常量 adPrefix（Finding F12）", false},
		{"DomainDirectedBody", housekitchen.DomainDirectedBody, hexStr([]byte(housekitchen.DomainDirectedBody)), "定向广播外层 DirectedBody 的规范化前缀（附录 E.2）", true},
		{"DomainDirectedKernel", housekitchen.DomainDirectedKernel, hexStr([]byte(housekitchen.DomainDirectedKernel)), "定向广播内层 DirectedKernel 的规范化前缀，同时是内层 AEAD 的 AD 前缀", true},
		{"DomainDirectedWrap", housekitchen.DomainDirectedWrap, hexStr([]byte(housekitchen.DomainDirectedWrap)), "wrapped_key 的 HKDF info（无 NUL 结尾，附录 E.2）", true},
		{"DomainDirectedBlind", housekitchen.DomainDirectedBlind, hexStr([]byte(housekitchen.DomainDirectedBlind)), "blind_key 的 HKDF info（无 NUL 结尾，附录 E.2）", true},
		{"DomainDirectedTag", housekitchen.DomainDirectedTag, hexStr([]byte(housekitchen.DomainDirectedTag)), "recipient_tag 的 HMAC 域前缀（附录 E.2）", true},
		{"DirectedWrapADPrefix", DirectedWrapADPrefix, hexStr([]byte(DirectedWrapADPrefix)), "wrapped_key 的 AEAD AD 前缀；在 directed.go 的 wrapAAD 中是未导出字面量，跨语言实现只能以本向量为准", false},
	}
}

func derivations() []Derivation {
	return []Derivation{
		{"SIGNED_BYTES", "proto3_deterministic_marshal(SignedBody{msg_id=nil, signers=nil}) 前置 ASCII \"futurecast/v1/signedbody\\x00\""},
		{"MSG_ID", "SHA-256(\"futurecast/v1/msgid\\x00\" || SIGNED_BYTES)"},
		{"SIGN_INPUT", "SHA-256(\"futurecast/v1/signinput\\x00\" || SIGNED_BYTES || key_id(16) || uint64_be(signed_at_unix_nanos))"},
		{"KEY_ID", "SHA-256(ed25519_pub)[0:16]"},
		{"NODE_ID", "SHA-256(ed25519_pub)[0:32]"},
		{"ADMIN_SET_HASH", "SHA-256(\"futurecast/v1/adminset\\x00\" || proto3_deterministic_marshal(AdminSet{signers=nil}))"},
		{"RELAY_TAG", "HMAC-SHA256(dailyKey, \"futurecast/v1/relaytag\\x00\" || msg_id || uint64_be(prev))[0:8] 按大端读作 uint64"},
		{"TOPIC_KEY_SEAL", "sealed = nonce(12) || AES-256-GCM(HKDF-SHA256(X25519(ephPriv, recipientPub), salt=zeros(32), info=\"fc/v1/topickey\"), nonce, topicKey, ad)"},
		{"SEALED_BODY", "sealed = nonce(12) || AES-256-GCM(HKDF-SHA256(X25519(ephPriv, recipientPub), salt=zeros(32), info=\"fc/v1/sealed\"), nonce, deterministic_proto(SignedBody 完整含 msg_id+signers), ad)；ad = \"futurecast/v1/sealed\\x00\" || rendezvous(32) || u64be(epoch)"},
		{"INNER_BODY_COMMITMENT", "inbox_rendezvous_id = SHA-256(inner_body)；inner_body = deterministic_proto(内层 SignedBody)"},
		{"NODE_SELF_SIGN", "Ed25519_sign(nodePriv, CanonicalNodeAnnounce(msg))，域前缀只出现一次"},
		{"HELLO_SELF_SIGN", "Ed25519_sign(nodePriv, CanonicalHello(msg))，域前缀只出现一次"},
		{"DIRECTED_BYTES", "proto3_deterministic_marshal(DirectedBody{msg_id=nil, signers=nil}) 前置 ASCII \"futurecast/v1/directedbody\\x00\""},
		{"DIRECTED_MSG_ID", "SHA-256(\"futurecast/v1/msgid\\x00\" || DIRECTED_BYTES)（与 SignedBody 共用 DomainMsgID；域分隔靠 DIRECTED_BYTES 自带的前缀）"},
		{"KERNEL_BYTES", "\"futurecast/v1/directedkernel\\x00\" || proto3_deterministic_marshal(DirectedKernel)"},
		{"DIRECTED_BLIND_KEY", "HKDF-SHA256(secret=content_key, salt=blind_salt, info=\"fc/v1/directedblind\", len=32)"},
		{"DIRECTED_RECIPIENT_TAG", "HMAC-SHA256(blind_key, \"futurecast/v1/dirtag\\x00\" || node_id)[:16]（**不是** SHA-256，见 Finding F14）"},
		{"DIRECTED_WRAP_KEY", "HKDF-SHA256(secret=X25519(eph_priv_i, recipient_x25519), salt=zeros(32), info=\"fc/v1/directedwrap\", len=32)"},
		{"DIRECTED_WRAPPED_KEY", "sealed = nonce(12) || AES-256-GCM(wrap_key_i, nonce, content_key, ad)；ad = \"futurecast/v1/dirwrap\\x00\" || blind_salt || u64be(i)"},
		{"DIRECTED_CIPHERTEXT", "ciphertext = AES-256-GCM(content_key, content_nonce, KERNEL_BYTES, ad) 去掉 12 字节 nonce 后的部分；ad = \"futurecast/v1/directedkernel\\x00\" || blind_salt"},
		{"DIRECTED_RECIPIENT_X25519", "recipient_x25519 = birational_map(ed25519_pub)（crypto.Ed25519ToX25519）；必须等于 X25519(clamp(SHA-512(seed)[:32]), basepoint)"},
	}
}

// Findings 汇总本次对抗性验证发现的问题与已确认修复项。
func Findings() []Finding {
	return []Finding{
		{
			ID:       "F1",
			Severity: "resolved",
			Summary:  "CONTRACTS §2 曾列出但代码中不存在的 housekitchen.DomainSealedPayload，现已补齐，CanonicalSealedPayload 改为引用该常量。",
			Contract: "docs/CONTRACTS.md §2 vs internal/housekitchen/ids.go:37-38, canonical.go:171-187",
			Evidence: "ids.go 现有 DomainSealedPayload = \"futurecast/v1/sealedpayload\\x00\"，canonical.go 使用它。",
			Status:   "fixed-during-run（我在首次读取时该常量尚不存在，Lead 于本轮补齐）",
		},
		{
			ID:       "F2",
			Severity: "resolved",
			Summary:  "节点自证曾是双域前缀：CanonicalXxx 已含域前缀，SignWithDomain 又 HashOf(domain, canonical) 再加一次。现已改为单前缀：SignWithDomain 直接对 canonical 签名。",
			Contract: "internal/crypto/crypto.go:213-240 vs internal/identity/node.go:74-151",
			Evidence: "SignWithDomain 现在执行 _ = domain; return Sign(priv, canonical)。",
			Status:   "fixed-during-run（向量已按单前缀重算）",
		},
		{
			ID:       "F3",
			Severity: "high",
			Summary:  "DESIGN.md 内部自相矛盾：§3（line 91）的 SIGN_INPUT 公式含 DomainSignInput 前缀且与实现一致，但 §4.1（line 121）仍是旧公式 SHA-256(SIGNED_BYTES||key_id||u64(at))，缺少域前缀。按 §4.1 实现的外部签名者会与 Go 完全不兼容。",
			Contract: "docs/DESIGN.md:91（正确） vs docs/DESIGN.md:121（错误） vs internal/housekitchen/canonical.go:107-109",
			Evidence: "TestKnownIssue_F3 用 §4.1 公式算出的签名被 crypto.VerifySignature 拒绝。",
			Status:   "open — 建议删除/修正 DESIGN.md:121 的公式，指向 §3 的唯一定义。",
		},
		{
			ID:       "F4",
			Severity: "high",
			Summary:  "门限阈值取自 SignedBody.policy（签名者自填）而非本地 AdminSet.policy。单把被控管理员密钥可自行声明 threshold=1 并成功广播，绕过 2-of-3 门限。",
			Contract: "docs/CONTRACTS.md §5.1 第 6 步 vs internal/registry/registry.go:330-339",
			Evidence: "registry.go:330-332 先取 body.GetPolicy()，非 nil 即用作门限；TestKnownIssue_F4 复现：1 把密钥 + 自声明 threshold=1 的广播被接受。",
			Status:   "open — 建议验证侧以本地 set.GetPolicy().Threshold 为准，或要求 body.policy 与本地完全一致。",
		},
		{
			ID:       "F5",
			Severity: "resolved",
			Summary:  "CanonicalAdminSet 曾复用 DomainSignedBody，AdminSet 与 SignedBody 之间没有域分隔。现已引入独立 DomainAdminSet。",
			Contract: "internal/housekitchen/canonical.go:44-63",
			Evidence: "admin_set.domain_used_ascii == \"futurecast/v1/adminset\\x00\"。",
			Status:   "fixed-during-run",
		},
		{
			ID:       "F6",
			Severity: "medium",
			Summary:  "VerifyMessage 完全不校验 proto_version。声明 proto_version=999 的消息会被正常接受，§5.1 管线中也没有版本步骤。",
			Contract: "docs/CONTRACTS.md §5.1（7 步无版本检查）vs housekitchen.ProtoVersion/MinProtoVersion",
			Evidence: "TestKnownIssue_F6 显示 proto_version=999 仍通过校验。",
			Status:   "open — 建议在管线第 0 步加版本检查并返回 ErrProtocolVersion。",
		},
		{
			ID:       "F7",
			Severity: "low",
			Summary:  "\"管理员消息不得携带 author\" 的拒绝路径没有包装任何错误哨兵，调用方无法用 errors.Is 分类。",
			Contract: "docs/CONTRACTS.md §2 错误哨兵列表 vs internal/registry/registry.go:349-351",
			Evidence: "TestKnownIssue_F7 显示该错误不匹配任何哨兵。",
			Status:   "open — 建议改为包装 housekitchen.ErrNotAuthorized。",
		},
		{
			ID:       "F8",
			Severity: "medium",
			Summary:  "Registry.Install 对同一代数的不同集合静默返回 nil（幂等语义过宽），无法检测同代 equivocation（两个互相冲突的第 N 代 AdminSet）。",
			Contract: "docs/CONTRACTS.md §5 Install（幂等）vs internal/registry/registry.go:189-192",
			Evidence: "TestKnownIssue_F8 显示两个不同的第 2 代集合都被 Install 接受（第二个被当作 no-op）。",
			Status:   "open — 建议 Install 发现同代但摘要不同时返回明确错误。",
		},
		{
			ID:       "F9",
			Severity: "info",
			Summary:  "注册表层对重放完全无状态：同一信封可无限次通过 VerifyMessage。去重由 store.Seen 承担（现已在 internal/store 实现）。集成层必须先 Seen 再 VerifyMessage。",
			Contract: "docs/CONTRACTS.md §6.1 Store.Seen vs §5.1 管线",
			Evidence: "TestNegative_N10_Replay 显示：无 store 时两次均通过；接入 store.Seen 后第二次被去重。",
			Status:   "accepted-by-design — 需在 node 集成层固化调用顺序并把该顺序写进 PROTOCOL.md。",
		},
		{
			ID:       "F10",
			Severity: "medium",
			Summary:  "expires_at_unix_nanos == 0 被当作\"永不过期\"（registry.go:299 的条件 exp != 0），且 created_at 没有下界。跨语言实现若把 0 解释为 Unix 纪元（早已过期）就会与 Go 分歧；恶意节点也可发布永不过期的消息。",
			Contract: "docs/CONTRACTS.md §5.1 第 3 步 vs internal/registry/registry.go:299-304",
			Evidence: "TestKnownIssue_F10：expires_at=0 的消息在 now+10 年仍然被接受。",
			Status:   "open — 建议明确\"0 = 永不过期\"写入 PROTOCOL.md，或在验证侧要求 expires_at > created_at > 0。",
		},
		{
			ID:       "F11",
			Severity: "low",
			Summary:  "crypto.SignWithDomain/VerifyWithDomain 完全忽略 domain 参数（_ = domain），而注释声称\"domain 参数保留仅用于断言调用方传对了域（见 domainMatches）\"——domainMatches 函数并不存在。传错域不会有任何反馈。",
			Contract: "internal/crypto/crypto.go:213-240",
			Evidence: "grep -rn domainMatches internal/ 只命中该注释本身。",
			Status:   "open — 建议删除该注释中的 domainMatches 引用，或真正实现断言（域已由 CanonicalXxx 保证，可考虑直接去掉 domain 参数）。",
		},
		{
			ID:       "F12",
			Severity: "high",
			Summary:  "封存载荷存在两种互不兼容的形状：internal/sealed.Seal 产出 ciphertext、inner_body 为空；internal/node.publishAsRelay 产出 inner_body、无 ciphertext，并把 inbox_rendezvous_id 复用为 SHA-256(inner_body) 承诺值；node.Unseal 要求 inner_body 非空并完全忽略 ciphertext。因此 sealed.Seal 的产物无法被 node.Unseal 接受。此外两条路径的 HKDF info 与 AD 前缀都是未导出私有常量，跨语言实现没有公开真源。",
			Contract: "docs/CONTRACTS.md §6.2 SealedPayload 字段语义 vs internal/sealed/sealed.go:31-32,77-114 vs internal/node/sealed_relay.go:137-160,377-392",
			Evidence: "TestKnownIssue_F12 显示 sealed.Seal 返回的 SealedPayload.GetInnerBody() 为空，而 node.Unseal 在 sealed_relay.go:380 直接以\"封存载荷为空\"拒绝。",
			Status:   "open — 建议统一为一条封存路径（要么 inner_body 承诺 + 内层完整正文，要么 X25519 密文），并导出 sealed 的 info/AD 常量、写入 PROTOCOL.md。",
		},
		{
			ID:       "F13",
			Severity: "medium",
			Summary:  "契约与实现的节点消息语义已漂移：CONTRACTS §5.1 第 7 步仍写“必须由 author 本人自签（会话公钥必须匹配 author）”，但 SignedBody 新增了 author_pub(field 15) 并绑定在签名范围内；验证时 author_pub 优先，会话对端只有在“自称就是 author”时才被交叉校验。于是中继可以把作者的消息转发给任意对端而仍被接受。",
			Contract: "docs/CONTRACTS.md §5.1 第 7 步 vs internal/registry/registry.go:373-441 + proto/futurecast/v1/message.proto:150",
			Evidence: "TestNegative_N8 用例 (b)/(h)：会话对端为冒充者时，带正确 author_pub 与作者自签的中继转发消息被接受；不带 author_pub 的旧式消息才走“会话公钥必须等于 author”的兼容路径。",
			Status:   "open — 属功能性演进，建议同步修订 CONTRACTS §5.1 与 PROTOCOL.md，明确 author_pub 的信任模型（它把“连接对端身份”与“消息作者身份”解耦）。",
		},
		{
			ID:       "F14",
			Severity: "high",
			Summary:  "proto 里 DirectRecipient.recipient_tag 的注释公式是错的：写成 SHA-256(\"futurecast/v1/dirtag\\0\" || content_key || sealed_key || content_key_again)，而实现与 PROTOCOL 附录 E.2 都是 HMAC-SHA256(blind_key, \"futurecast/v1/dirtag\\0\" || node_id)[:16]。按注释实现的外部方既算不对 tag，还会误以为 recipient_tag 泄露 content_key 的哈希。另外注释里的 sealed_key 在定向广播里根本不存在（那是 sealed 模式的概念）。",
			Contract: "proto/futurecast/v1/message.proto:149（错误） vs docs/PROTOCOL.md 附录 E.2（正确） vs internal/directed/directed.go:74-79",
			Evidence: "TestDirectedInterop_* 按 E.2 公式独立复算的 16 字节 tag 与 directed.Open 内部判定一致；按注释公式计算则与向量不符。",
			Status:   "resolved — Lead 已修正 proto 注释，与附录 E.2 的 HMAC 公式一致",
		},
		{
			ID:       "F15",
			Severity: "medium",
			Summary:  "PROTOCOL 附录 E.3 外层第 7 步要求校验 blind_salt 长度 16，但 directed.VerifyBody 只检查 recipients 非空、recipient_count、content_nonce 长度与 ciphertext 非空，**没有 blind_salt 长度检查**；该检查只存在于 directed.Open（且排在 recipient_count 之后）。后果：一条 blind_salt 长度为 0/8 的消息，只要门限签名自洽就能通过所有中继的外层校验并被全网转发，直到收件人尝试解密才失败。",
			Contract: "docs/PROTOCOL.md 附录 E.3 第 7 步 vs internal/directed/directed.go:130-142（VerifyBody）与 :243-245（Open）",
			Evidence: "TestDirectedNegative_D4_BlindSaltLength：重新签名后的 8 字节 blind_salt 消息被 directed.VerifyBody 接受（err=nil），只有 directed.Open 报 ErrDirectedInvalid。",
			Status:   "open — 建议在 VerifyBody 第 4 步补 len(blind_salt)==16 -> ErrDirectedInvalid。",
		},
		{
			ID:       "F16",
			Severity: "medium",
			Summary:  "DirectedKernel.outer_msg_id(field 7) 从未被填充：directed.Seal 构造 kernel 时只写 topic/media_type/body/created_at/expires_at/nonce；housekitchen.DirectedBodyHash 的注释声称该摘要“被写进内层 outer_msg_id 用于把密文绑死到外层消息”，但 DirectedBodyHash 在整个仓库里没有任何调用方。附录 E 的 E.1 字段表也漏列了该字段。实际能防密文搬运的是内层 AD 里的 blind_salt（已被签名覆盖），所以安全结论不变，但文档描述与实现不符、且该字段是永不出现的死字段。",
			Contract: "proto/futurecast/v1/message.proto:184 + internal/housekitchen/canonical.go:186-199 vs internal/directed/directed.go:168-175（kernel 构造）与 docs/PROTOCOL.md 附录 E.1/E.2",
			Evidence: "grep -rn 'OuterMsgId|outer_msg_id' 只命中 proto/生成物与 canonical.go 的注释；向量 directed.kernel.outer_msg_id_hex 为空串。",
			Status:   "resolved — Lead 已删除该废弃字段（field 7 保留号）与 DirectedBodyHash",
		},
		{
			ID:       "F17",
			Severity: "low",
			Summary:  "housekitchen.DomainDirectedKey（\"fc/v1/directedkey\"）已声明但全仓库无任何调用方：附录 E.2 里 content_key 是纯随机值，不需要 HKDF 派生。它容易让外部实现者以为存在第三条派生公式。",
			Contract: "internal/housekitchen/ids.go:47-48 vs docs/PROTOCOL.md 附录 E.2",
			Evidence: "grep -rn 'DomainDirectedKey' 只命中 ids.go 的定义与 conformance 的域向量表。",
			Status:   "resolved — Lead 已删除该无调用方常量",
		},
	}
}

func negativeVectors() []NegativeVector {
	return []NegativeVector{
		{"N1", "声明本地未知的 admin_set_generation", "ErrGenerationMismatch", "5.1-4", "用有效密钥对 gen=7 的伪造集合签名，msg_id/签名自洽"},
		{"N2", "signer_set_hash 指向另一个 AdminSet", "ErrSignerSetMismatch", "5.1-5", "本地注册 setA，消息由 setB 以同代数签名"},
		{"N3", "同一把密钥的签名复制 N 份凑门限", "ErrThresholdNotMet", "5.1-6", "同一 *pb.Signature 重复 3 次；同一 key_id 只计 1"},
		{"N4", "篡改正文 1 字节（payload/topic/created_at）", "ErrMsgIDMismatch", "5.1-1", "先改字节再校验；msg_id 首先不符（设计意图）"},
		{"N5", "msg_id 与正文不符（正文或信封任一）", "ErrMsgIDMismatch", "5.1-1/2", "分别篡改 body.msg_id 与 envelope.msg_id"},
		{"N6", "过期 / created_at 超前（签名自洽）", "ErrExpired / ErrClockSkew", "5.1-3", "先设置非法时间再签名，使签名与 msg_id 都有效"},
		{"N7", "管理员消息携带 author 字段", "非哨兵错误（F7）", "5.1-6", "签名前写入 author，使 msg_id 自洽；门限达标后才检查 author"},
		{"N8", "节点消息由非 author 的密钥自签", "ErrInvalidSignature / ErrPeerIDMismatch", "5.1-7(已演进)", "author=A 但签名 key_id 来自 B；author_pub 与 author 不符；无 author_pub 时会话公钥≠author"},
		{"N9", "轮换链：代数跳号 / previous_set_hash 不符 / 旧集合仅 1 签 / 新集合自签", "ErrGenerationMismatch / ErrThresholdNotMet", "ValidateAdminSet", "分别构造 gen=3、错误 prev hash、1 把旧密钥签名、2 把新密钥自签"},
		{"N10", "重放：同一消息二次投递", "注册表层无拒绝（F9）；store.Seen 拒绝", "集成层 Seen→Verify", "无 store 时两次均通过；接入 store 后第二次 Seen=false"},
		{"N11", "定向广播只带 1/3 门限签名", "ErrThresholdNotMet", "E.3-8", "签名与 msg_id 都自洽（signers 不参与 canonical），仅删到 1 个签名者"},
		{"N12", "篡改定向广播 created_at", "ErrMsgIDMismatch", "E.3-3", "created_at 参与签名覆盖，内容寻址先于时间窗检查"},
		{"N13", "recipient_count 与槽位数不符", "ErrMsgIDMismatch（直接篡改）/ ErrDirectedInvalid（重签自洽）", "E.3-3 / E.3-7", "直接改字段先被 msg_id 拦下；要触发结构检查必须改字段后重签并回填 msg_id"},
		{"N14", "blind_salt 长度不是 16", "Open: ErrDirectedInvalid；VerifyBody 当前不检查（F15）", "E.3-7 / E.3-内层", "重签自洽后外层仍被接受；只有 directed.Open 在 :243 报错"},
		{"N15", "用另一个 AdminSet 校验定向广播", "ErrSignerSetMismatch", "E.3-6", "另一套密钥组成的同代(gen=1)集合；代数检查通过后 signer_set_hash 不符"},
		{"N16", "已过期的定向广播（签名自洽）", "ErrExpired", "E.3-4", "now 取 expires_at 之后 2 小时"},
		{"N17", "非收件人尝试解密定向广播", "ErrNotAuthorized（正常结果，非故障）", "E.3-9", "陌生节点逐槽 unwrap 全部失败；Open 包装 ErrNotAuthorized"},
		{"N18", "把 A 槽位的 wrapped_key 搬到 B 槽位", "ErrNotAuthorized（谁也解不开）", "E.3-9", "wrap AD 含 u64be(i)，序号变了 GCM 认证失败；改后需重签才可送入 VerifyBody"},
		{"N19", "把另一条消息的 eph_pub 移植过来", "ErrNotAuthorized", "E.3-9", "eph_pub 变了 -> 共享密钥变 -> wrap_key 变 -> unwrap 失败"},
		{"N20", "同一收件人在两条消息里的 recipient_tag", "必须不同（不可关联）", "E.2", "blind_salt 与 content_key 每消息独立随机，tag 无稳定标识"},
	}
}

// ---------- 小工具 ----------

func derive32(label string) []byte {
	s := sha256.Sum256([]byte(label))
	return s[:]
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

// sealGCMFixedNonce 用固定 nonce 做 AES-256-GCM 加密，用于产出确定性向量。
// 它与 crypto.SealAEAD 的唯一差别是不随机生成 nonce。
func sealGCMFixedNonce(key, nonce, plaintext, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce 长度应为 %d，实为 %d", gcm.NonceSize(), len(nonce))
	}
	return gcm.Seal(nil, nonce, plaintext, ad), nil
}

func policyVector(p *pb.SigningPolicy) PolicyVector {
	ids := make([]string, 0, len(p.GetRootKeyIds()))
	for _, id := range p.GetRootKeyIds() {
		ids = append(ids, hexStr(housekitchen.GetKeyID(id).Bytes()))
	}
	return PolicyVector{
		Threshold:               p.GetThreshold(),
		Total:                   p.GetTotal(),
		RootKeyIDsHex:           ids,
		Scheme:                  uint32(p.GetScheme()),
		SchemeName:              p.GetScheme().String(),
		ClockSkewToleranceNanos: p.GetClockSkewToleranceNanos(),
	}
}

func sortKeys(keys []*identity.AdminKey) {
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && lessKeyID(keys[j].KeyID, keys[j-1].KeyID); j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
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
