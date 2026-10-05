// Command vectors 生成跨语言互通的基准向量文件，并打印人类可读摘要。
//
// 用法（在仓库根目录）：
//
//	go run ./scripts/vectors            # 写出 scripts/vectors/vectors.json 并打印摘要
//	go run ./scripts/vectors > /dev/null
//
// 输出是确定性的：同一份代码任意次数运行都会得到逐字节相同的 vectors.json。
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/loongqing/FuturecastAlpha/internal/conformance"
)

const outPath = "scripts/vectors/vectors.json"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "vectors: 失败: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	v, err := conformance.Build()
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := conformance.WriteJSON(&buf, v); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
		return err
	}
	abs, err := filepath.Abs(outPath)
	if err != nil {
		abs = outPath
	}
	fmt.Printf("已写出 %s（%d 字节，确定性）\n", abs, buf.Len())
	fmt.Printf("协议 %s / proto_version %d / 格式版本 %s\n\n", v.Meta.Protocol, v.Meta.ProtoVersion, v.Meta.FormatVersion)

	fmt.Println("== 域分隔前缀 ==")
	for _, d := range v.Domains {
		mark := "   "
		if !d.Implemented {
			mark = "(!)"
		}
		fmt.Printf("%s %-24s %s\n", mark, d.Name, d.Hex)
	}

	fmt.Println("\n== AdminSet ==")
	fmt.Printf("  generation        = %d\n", v.AdminSet.Generation)
	fmt.Printf("  domain            = %s\n", v.AdminSet.DomainUsedASCII)
	for i, k := range v.AdminSet.Keys {
		fmt.Printf("  key[%d]            = %s  (%s)\n", i, k.KeyIDHex, k.Label)
	}
	fmt.Printf("  admin_set_hash    = %s\n", v.AdminSet.AdminSetHashHex)

	fmt.Println("\n== SignedBody（2-of-3 管理员广播）==")
	fmt.Printf("  kind              = %s\n", v.SignedBody.KindName)
	fmt.Printf("  topic             = %s\n", v.SignedBody.Topic)
	fmt.Printf("  msg_id            = %s\n", v.SignedBody.MsgIDHex)
	fmt.Printf("  signed_bytes      = %s\n", v.SignedBody.SignedBytesHex)
	for i, s := range v.SignedBody.Signers {
		fmt.Printf("  signer[%d].key_id  = %s\n", i, s.KeyIDHex)
		fmt.Printf("  signer[%d].input   = %s\n", i, s.SignInputHex)
		fmt.Printf("  signer[%d].sig     = %s\n", i, s.SignatureHex)
	}

	fmt.Println("\n== NodeAnnounce（节点自证）==")
	fmt.Printf("  node_id           = %s\n", v.NodeAnnounce.NodeIDHex)
	fmt.Printf("  signed_bytes      = %s\n", v.NodeAnnounce.SignedBytesHex)
	fmt.Printf("  sign digest       = %s（域前缀出现 %d 次）\n", v.NodeAnnounce.SignDigestHex, v.NodeAnnounce.DomainPrefixCount)
	fmt.Printf("  self_signature    = %s\n", v.NodeAnnounce.SelfSignatureHex)

	fmt.Println("\n== Sealed（X25519 + HKDF-SHA256 + AES-256-GCM）==")
	fmt.Printf("  recipient pub     = %s\n", v.Sealed.RecipientX25519PubHex)
	fmt.Printf("  [topic key] info  = %q\n", v.Sealed.TopicKeyWrap.HKDFInfoASCII)
	fmt.Printf("  [topic key] key   = %s\n", v.Sealed.TopicKeyWrap.DerivedKeyHex)
	fmt.Printf("  [topic key] sealed= %s\n", v.Sealed.TopicKeyWrap.SealedHex)
	fmt.Printf("  [body] info       = %q\n", v.Sealed.SealedBody.InfoASCII)
	fmt.Printf("  [body] ad         = %s\n", v.Sealed.SealedBody.AssociatedDataHex)
	fmt.Printf("  [body] key        = %s\n", v.Sealed.SealedBody.DerivedKeyHex)
	fmt.Printf("  [body] sealed     = %s\n", v.Sealed.SealedBody.SealedHex)
	fmt.Printf("  [body] plaintext  = %s\n", v.Sealed.SealedBody.PlaintextFullBodyProtoHex)
	fmt.Printf("  [node relay] inner_body commitment = %s\n", v.Sealed.NodeRelay.CommitmentHex)

	fmt.Println("\n== Directed（定向广播：可验签外层 + 只有收件人能解的内层，附录 E）==")
	fmt.Printf("  directed_msg_id   = %s\n", v.Directed.DirectedMsgIDHex)
	fmt.Printf("  directed_bytes    = %s…（%d 字节）\n", v.Directed.DirectedBytesHex[:32], len(v.Directed.DirectedBytesHex)/2)
	fmt.Printf("  blind_salt        = %s\n", v.Directed.BlindSaltHex)
	fmt.Printf("  content_key       = %s\n", v.Directed.ContentKeyHex)
	fmt.Printf("  blind_key         = %s\n", v.Directed.BlindKeyHex)
	fmt.Printf("  content_nonce     = %s\n", v.Directed.ContentNonceHex)
	fmt.Printf("  ciphertext        = %s…（%d 字节）\n", v.Directed.CiphertextHex[:32], len(v.Directed.CiphertextHex)/2)
	fmt.Printf("  kernel(topic/body)= %s / %q\n", v.Directed.Kernel.Topic, v.Directed.Kernel.Body)
	fmt.Printf("  recipients        = %d\n", v.Directed.RecipientCount)
	for i, r := range v.Directed.Recipients {
		fmt.Printf("  slot[%d] tag=%s wrap_key=%s\n", i, r.RecipientTagHex, r.WrapKeyHex)
	}
	for i, s := range v.Directed.Signers {
		fmt.Printf("  signer[%d].key_id  = %s\n", i, s.KeyIDHex)
	}

	fmt.Println("\n== RelayTag ==")
	fmt.Printf("  msg_id            = %s\n", v.RelayTag.MsgIDHex)
	for i, prev := range v.RelayTag.PreviousTags {
		fmt.Printf("  prev=%-20d tag=%016x\n", prev, v.RelayTag.Tags[i])
	}

	fmt.Println("\n== findings（详见 vectors.json 与测试日志）==")
	bySeverity := map[string][]string{}
	for _, f := range v.Findings {
		bySeverity[f.Severity] = append(bySeverity[f.Severity], f.ID)
	}
	severities := make([]string, 0, len(bySeverity))
	for s := range bySeverity {
		severities = append(severities, s)
	}
	sort.Strings(severities)
	for _, s := range severities {
		ids := bySeverity[s]
		sort.Strings(ids)
		fmt.Printf("  %-8s %v\n", s, ids)
	}

	fmt.Println("\n== 负例清单 ==")
	for _, n := range v.Negative {
		fmt.Printf("  %-4s %-48s -> %s（%s）\n", n.ID, n.Attack, n.ExpectedError, n.PipelineStep)
	}
	return nil
}
