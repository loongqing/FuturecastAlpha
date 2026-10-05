// Package cli 实现 futurecast 命令行界面。
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
	"github.com/loongqing/FuturecastAlpha/internal/registry"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// ---------- 通用 ----------

// usageError 表示命令用法错误，退出码 64。
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usageErrorf(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

// newFlagSet 创建统一风格的 flag 集合（错误输出到 stderr）。
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func marshalProtoJSON(m proto.Message) ([]byte, error) {
	return protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(m)
}

// writeProtoJSONFile 写出 protobuf JSON（容忍注释，便于人工审阅）。
func writeProtoJSONFile(path string, m proto.Message, mode os.FileMode) error {
	raw, err := marshalProtoJSON(m)
	if err != nil {
		return fmt.Errorf("futurecast: 序列化失败: %w", err)
	}
	return os.WriteFile(path, append(raw, '\n'), mode)
}

// readProtoJSONFile 读取 protobuf JSON，跳过 # 注释行。
func readProtoJSONFile(path string, m proto.Message) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("futurecast: 读取 %s 失败: %w", path, err)
	}
	var b strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if err := protojson.Unmarshal([]byte(b.String()), m); err != nil {
		return fmt.Errorf("futurecast: 解析 %s 失败: %w", path, err)
	}
	return nil
}

func loadAdminSet(path string) (*pb.AdminSet, error) {
	set := &pb.AdminSet{}
	if err := readProtoJSONFile(path, set); err != nil {
		return nil, err
	}
	return set, nil
}

// ---------- 管理员命令 ----------

// cmdAdminKeygen 生成 M-of-N 管理员密钥环与创世 AdminSet。
func cmdAdminKeygen(args []string) error {
	fs := newFlagSet("admin keygen")
	out := fs.String("out", "admin-keys", "密钥环输出目录")
	threshold := fs.Uint("threshold", 2, "门限 M")
	total := fs.Uint("total", 3, "总数 N")
	topic := fs.String("topic", "alerts", "随创世集分发的主题")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *threshold == 0 || *threshold > *total {
		return usageErrorf("门限 M=%d 必须落在 (0, %d]", *threshold, *total)
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	kr := identity.NewKeyring()
	fmt.Printf("生成 %d 把管理员密钥（门限 %d/%d）→ %s\n\n", *total, *threshold, *total, *out)
	for i := 0; i < int(*total); i++ {
		label := fmt.Sprintf("admin-%d", i+1)
		k, err := identity.NewAdminKey(label, pb.AdminRole_ADMIN_ROLE_ROOT)
		if err != nil {
			return err
		}
		path := filepath.Join(*out, label+".key")
		if err := identity.SaveAdminKey(path, k); err != nil {
			return err
		}
		// 必须把密钥放进密钥环，否则 BuildAdminSet 会因"实有 0 把"失败。
		kr.Add(k)
		fmt.Printf("  %-10s %s  key_id=%s\n", label, path, k.KeyID.Short())
	}
	set, err := kr.BuildAdminSet(1, uint32(*threshold), uint32(*total), "genesis")
	if err != nil {
		return err
	}
	set.TopicPolicies = []*pb.TopicPolicy{{
		Topic:           *topic,
		WritePolicy:     pb.WritePolicy_WRITE_POLICY_NODE_ALLOWED,
		ReadPolicy:      pb.ReadPolicy_READ_POLICY_PUBLIC,
		DefaultTtlNanos: housekitchen.DefaultMsgTTLNanos,
	}}
	setPath := filepath.Join(*out, "admin-set.json")
	if err := writeProtoJSONFile(setPath, set, 0o644); err != nil {
		return err
	}
	hash, err := housekitchen.AdminSetHash(set)
	if err != nil {
		return err
	}
	fmt.Printf("\n创世 AdminSet : %s\n", setPath)
	fmt.Printf("代数          : %d\n", set.GetGeneration())
	fmt.Printf("集合摘要      : %s\n", hash)
	fmt.Printf("主题策略      : %s（节点可写、公开可读）\n", *topic)
	fmt.Printf("\n请把 %d 份 .key 文件分别离线保存 —— 任意 1 份泄露都不足以签发广播。\n", *total)
	fmt.Println("投入使用前务必核对上面的 key_id 指纹。")
	return nil
}

// cmdAdminSet 由密钥环构建指定代数的 AdminSet。
func cmdAdminSet(args []string) error {
	fs := newFlagSet("admin set")
	keyring := fs.String("keyring", "admin-keys", "密钥环目录")
	generation := fs.Uint64("generation", 1, "代数")
	threshold := fs.Uint("threshold", 2, "门限 M")
	total := fs.Uint("total", 3, "总数 N")
	topic := fs.String("topic", "alerts", "随创世集分发的主题")
	out := fs.String("out", "", "输出文件（默认 <keyring>/admin-set-<gen>.json）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	kr, err := identity.LoadKeyring(*keyring)
	if err != nil {
		return err
	}
	if int(*total) != len(kr.Keys) {
		return usageErrorf("--total=%d 与密钥环里的 %d 把密钥不一致", *total, len(kr.Keys))
	}
	set, err := kr.BuildAdminSet(*generation, uint32(*threshold), uint32(*total), fmt.Sprintf("gen-%d", *generation))
	if err != nil {
		return err
	}
	if *generation == 1 {
		set.TopicPolicies = []*pb.TopicPolicy{{
			Topic:           *topic,
			WritePolicy:     pb.WritePolicy_WRITE_POLICY_NODE_ALLOWED,
			ReadPolicy:      pb.ReadPolicy_READ_POLICY_PUBLIC,
			DefaultTtlNanos: housekitchen.DefaultMsgTTLNanos,
		}}
	}
	path := *out
	if path == "" {
		path = filepath.Join(*keyring, fmt.Sprintf("admin-set-%d.json", *generation))
	}
	if err := writeProtoJSONFile(path, set, 0o644); err != nil {
		return err
	}
	hash, _ := housekitchen.AdminSetHash(set)
	fmt.Printf("已写出 %s\n代数=%d 门限=%d/%d 摘要=%s\n", path, set.GetGeneration(), *threshold, *total, hash)
	return nil
}

// cmdAdminRotate 用旧集合的门限密钥为新集合收集轮换签名。
func cmdAdminRotate(args []string) error {
	fs := newFlagSet("admin rotate")
	oldKeyring := fs.String("old-keyring", "", "旧密钥环目录（必填）")
	oldSetPath := fs.String("old-set", "", "旧 AdminSet 文件（必填）")
	newKeyring := fs.String("new-keyring", "", "新密钥环目录（必填）")
	generation := fs.Uint64("generation", 2, "新代数")
	signWith := fs.String("sign-with", "", "用哪几把旧密钥签名（序号或 key_id 前缀，逗号分隔；留空取门限数量）")
	out := fs.String("out", "", "输出新 AdminSet")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *oldKeyring == "" || *oldSetPath == "" || *newKeyring == "" {
		return usageErrorf("必须提供 --old-keyring、--old-set、--new-keyring")
	}
	oldSet, err := loadAdminSet(*oldSetPath)
	if err != nil {
		return err
	}
	if *generation != oldSet.GetGeneration()+1 {
		return usageErrorf("新代数必须严格 +1（旧 %d，新 %d）", oldSet.GetGeneration(), *generation)
	}
	newKR, err := identity.LoadKeyring(*newKeyring)
	if err != nil {
		return err
	}
	th, total := oldSet.GetPolicy().GetThreshold(), oldSet.GetPolicy().GetTotal()
	if uint32(len(newKR.Keys)) != total {
		return usageErrorf("新密钥环需有 %d 把密钥，实有 %d 把", total, len(newKR.Keys))
	}
	next, err := newKR.BuildAdminSet(*generation, th, total, fmt.Sprintf("gen-%d", *generation))
	if err != nil {
		return err
	}
	oldKR, err := identity.LoadKeyring(*oldKeyring)
	if err != nil {
		return err
	}
	selected, err := selectKeys(oldKR, oldSet, *signWith)
	if err != nil {
		return err
	}
	if len(selected) < int(th) {
		return usageErrorf("轮换需要旧集合至少 %d 把密钥签名，当前选了 %d 把", th, len(selected))
	}
	if err := registry.SignAdminSet(next, oldSet, selected, int(th), time.Now()); err != nil {
		return err
	}
	// 自校验：绝不写出一个连自己都验不过的集合。
	if err := registry.ValidateAdminSet(next, oldSet, time.Now()); err != nil {
		return fmt.Errorf("futurecast: 轮换自校验失败（不会写出无效集合）: %w", err)
	}
	path := *out
	if path == "" {
		path = filepath.Join(*newKeyring, fmt.Sprintf("admin-set-%d.json", *generation))
	}
	if err := writeProtoJSONFile(path, next, 0o644); err != nil {
		return err
	}
	hash, _ := housekitchen.AdminSetHash(next)
	fmt.Printf("已写出 %s\n新代数=%d 摘要=%s\n用 %d/%d 把旧密钥签名，自校验通过。\n",
		path, next.GetGeneration(), hash, len(selected), th)
	return nil
}

// selectKeys 按 spec 选择旧密钥：支持序号（1,2）或 key_id 十六进制前缀。
func selectKeys(kr *identity.Keyring, set *pb.AdminSet, spec string) ([]*identity.AdminKey, error) {
	ordered := make([]*identity.AdminKey, 0, len(set.GetKeys()))
	for _, k := range set.GetKeys() {
		id := housekitchen.GetKeyID(k.GetKeyId())
		ak, ok := kr.Get(id)
		if !ok {
			return nil, fmt.Errorf("futurecast: 密钥环缺少 %s", id.Short())
		}
		ordered = append(ordered, ak)
	}
	if strings.TrimSpace(spec) == "" {
		n := int(set.GetPolicy().GetThreshold())
		if n > len(ordered) {
			n = len(ordered)
		}
		return ordered[:n], nil
	}
	var out []*identity.AdminKey
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx, ok := parseIndex(part); ok {
			if idx < 1 || idx > len(ordered) {
				return nil, usageErrorf("密钥序号 %d 越界（1..%d）", idx, len(ordered))
			}
			out = append(out, ordered[idx-1])
			continue
		}
		var found *identity.AdminKey
		for _, k := range ordered {
			if strings.HasPrefix(k.KeyID.String(), strings.ToLower(part)) {
				found = k
				break
			}
		}
		if found == nil {
			return nil, usageErrorf("找不到匹配 %q 的密钥", part)
		}
		out = append(out, found)
	}
	return out, nil
}

func parseIndex(s string) (int, bool) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	if s == "" {
		return 0, false
	}
	return n, true
}

// cmdAdminCompose 组装一条待签名的管理员广播正文（离线流程的起点）。
func cmdAdminCompose(args []string) error {
	fs := newFlagSet("admin compose")
	setPath := fs.String("admin-set", "", "AdminSet 文件（必填，用于绑定代数与集合摘要）")
	topic := fs.String("topic", "alerts", "主题")
	text := fs.String("text", "", "正文（必填）")
	ttl := fs.Duration("ttl", 7*24*time.Hour, "有效期")
	out := fs.String("out", "body.json", "输出待签正文")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *setPath == "" || *text == "" {
		return usageErrorf("必须提供 --admin-set 与 --text")
	}
	set, err := loadAdminSet(*setPath)
	if err != nil {
		return err
	}
	body, err := registry.NewAdminBroadcast(set, *topic, *text, "text/plain", *ttl, time.Now())
	if err != nil {
		return err
	}
	if err := writeProtoJSONFile(*out, body, 0o644); err != nil {
		return err
	}
	fmt.Printf("已写出待签正文 %s\n代数=%d 主题=%q 有效期=%s\n",
		*out, set.GetGeneration(), *topic, *ttl)
	fmt.Printf("\n下一步（每把密钥在各自离线机器上执行）：\n")
	fmt.Printf("  futurecast admin sign --in %s --key <admin-N.key>\n", *out)
	fmt.Printf("然后收集签名：\n")
	fmt.Printf("  futurecast admin finalize --in %s --sigs sig1.json,sig2.json --admin-set %s\n", *out, *setPath)
	return nil
}

// cmdAdminSign 用一把密钥签一个 SignedBody（离线首签）。
func cmdAdminSign(args []string) error {
	fs := newFlagSet("admin sign")
	in := fs.String("in", "", "待签名的 SignedBody JSON（必填）")
	key := fs.String("key", "", "管理员密钥文件（必填）")
	out := fs.String("out", "", "签名输出文件")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *key == "" {
		return usageErrorf("必须提供 --in 与 --key")
	}
	body := &pb.SignedBody{}
	if err := readProtoJSONFile(*in, body); err != nil {
		return err
	}
	k, err := identity.LoadAdminKey(*key)
	if err != nil {
		return err
	}
	canonical, err := registry.CanonicalForSigning(body)
	if err != nil {
		return err
	}
	sig := k.Sign(canonical, time.Now())
	path := *out
	if path == "" {
		path = fmt.Sprintf("%s.sig-%s.json", *in, k.KeyID.Short())
	}
	if err := writeProtoJSONFile(path, sig, 0o644); err != nil {
		return err
	}
	fmt.Printf("已写出签名 %s\nkey_id=%s signed_at=%s\n", path, k.KeyID.Short(),
		time.Unix(0, sig.GetSignedAtUnixNanos()).Format(time.RFC3339))
	return nil
}

// cmdAdminFinalize 收集门限签名并写出完整信封。
func cmdAdminFinalize(args []string) error {
	fs := newFlagSet("admin finalize")
	in := fs.String("in", "", "待签名的 SignedBody JSON（必填）")
	sigs := fs.String("sigs", "", "逗号分隔的签名 JSON（必填）")
	setPath := fs.String("admin-set", "", "AdminSet 文件（必填）")
	out := fs.String("out", "", "输出信封")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *sigs == "" || *setPath == "" {
		return usageErrorf("必须提供 --in、--sigs、--admin-set")
	}
	body := &pb.SignedBody{}
	if err := readProtoJSONFile(*in, body); err != nil {
		return err
	}
	set, err := loadAdminSet(*setPath)
	if err != nil {
		return err
	}
	canonical, err := registry.CanonicalForSigning(body)
	if err != nil {
		return err
	}
	var collected []*pb.Signature
	for _, p := range strings.Split(*sigs, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		s := &pb.Signature{}
		if err := readProtoJSONFile(p, s); err != nil {
			return err
		}
		collected = append(collected, s)
	}
	body.Signers = collected
	body.MsgId = housekitchen.PBHash(housekitchen.MsgIDFromCanonical(canonical))
	env := registry.WrapEnvelope(body, time.Now())

	r, err := registry.New(set, registry.Options{})
	if err != nil {
		return err
	}
	if _, err := r.VerifyMessage(env, registry.Session{Now: time.Now()}); err != nil {
		return fmt.Errorf("futurecast: 门限校验失败，未写出信封: %w", err)
	}
	path := *out
	if path == "" {
		path = *in + ".envelope.json"
	}
	if err := writeProtoJSONFile(path, env, 0o644); err != nil {
		return err
	}
	fmt.Printf("已写出信封 %s\nmsg_id=%s 收集签名=%d 门限=%d/%d 自校验通过\n", path,
		housekitchen.GetHash(env.GetMsgId()).Short(), len(collected),
		set.GetPolicy().GetThreshold(), set.GetPolicy().GetTotal())
	return nil
}

// cmdVerify 离线校验一个信封。
func cmdVerify(args []string) error {
	fs := newFlagSet("verify")
	envPath := fs.String("envelope", "", "信封 JSON（必填）")
	setPath := fs.String("admin-set", "", "AdminSet 文件（必填）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *envPath == "" || *setPath == "" {
		return usageErrorf("必须提供 --envelope 与 --admin-set")
	}
	env := &pb.Envelope{}
	if err := readProtoJSONFile(*envPath, env); err != nil {
		return err
	}
	set, err := loadAdminSet(*setPath)
	if err != nil {
		return err
	}
	r, err := registry.New(set, registry.Options{})
	if err != nil {
		return err
	}
	v, err := r.VerifyMessage(env, registry.Session{Now: time.Now()})
	if err != nil {
		fmt.Printf("❌ 校验失败：%v\n", err)
		return err
	}
	body := env.GetBody()
	fmt.Println("✅ 校验通过")
	fmt.Printf("  kind       = %s\n", body.GetKind())
	fmt.Printf("  topic      = %q\n", body.GetTopic())
	fmt.Printf("  msg_id     = %s\n", housekitchen.GetHash(env.GetMsgId()))
	fmt.Printf("  代数       = %d\n", v.Generation)
	if v.AdminAuthorized {
		fmt.Printf("  管理员授权 = 是（有效签名 %d：%s）\n", len(v.Signers), joinKeyIDs(v.Signers))
	} else {
		fmt.Printf("  管理员授权 = 否（节点自签=%v）\n", v.NodeSigned)
	}
	fmt.Printf("  作者       = %s\n", describeAuthor(body))
	if txt := body.GetPayload().GetText().GetBody(); txt != "" {
		fmt.Printf("  正文       = %s\n", txt)
	}
	return nil
}

func describeAuthor(body *pb.SignedBody) string {
	id := housekitchen.GetNodeID(body.GetAuthor())
	if id.IsZero() {
		return "（无，管理员消息）"
	}
	return id.String()
}

func joinKeyIDs(ids []housekitchen.KeyID) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, id.Short())
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

var _ = io.Discard
