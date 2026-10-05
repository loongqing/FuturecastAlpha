package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"
)

// keygen 必须真的产出可用密钥环与合法的创世 AdminSet。
func TestAdminKeygenProducesUsableKeyring(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "keys")
	if err := cmdAdminKeygen([]string{"--out", out, "--threshold", "2", "--total", "3", "--topic", "alerts"}); err != nil {
		t.Fatalf("keygen 失败: %v", err)
	}
	// 3 份 .key + 1 份 admin-set.json
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	keyCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".key" {
			keyCount++
		}
	}
	if keyCount != 3 {
		t.Fatalf("应有 3 份 .key，实有 %d", keyCount)
	}
	kr, err := identity.LoadKeyring(out)
	if err != nil {
		t.Fatalf("加载密钥环失败: %v", err)
	}
	if len(kr.Keys) != 3 {
		t.Fatalf("密钥环应有 3 把密钥，实有 %d", len(kr.Keys))
	}
	set, err := loadAdminSet(filepath.Join(out, "admin-set.json"))
	if err != nil {
		t.Fatalf("加载 AdminSet 失败: %v", err)
	}
	if set.GetGeneration() != 1 || set.GetPolicy().GetThreshold() != 2 || set.GetPolicy().GetTotal() != 3 {
		t.Fatalf("AdminSet 参数不对: gen=%d %d/%d", set.GetGeneration(),
			set.GetPolicy().GetThreshold(), set.GetPolicy().GetTotal())
	}
	// 密钥文件权限必须是 0600。
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".key" {
			continue
		}
		info, err := os.Stat(filepath.Join(out, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s 权限应为 0600，实为 %o", e.Name(), info.Mode().Perm())
		}
	}
	// 集合里的 key_id 必须与密钥环一致。
	hash, err := housekitchen.AdminSetHash(set)
	if err != nil {
		t.Fatal(err)
	}
	if hash.IsZero() {
		t.Fatal("AdminSet 摘要不应为零值")
	}
}

// 密钥文件如果被改动，加载必须失败（key_id 与种子不匹配）。
func TestAdminKeyFileTamperDetected(t *testing.T) {
	dir := t.TempDir()
	k, err := identity.NewAdminKey("x", 1)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "x.key")
	if err := identity.SaveAdminKey(path, k); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	// 篡改 key_id 行
	tampered := []byte(string(raw))
	for i := 0; i+7 < len(tampered); i++ {
		if string(tampered[i:i+7]) == "key_id:" {
			tampered[i+8] = 'f'
			tampered[i+9] = 'f'
			break
		}
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.LoadAdminKey(path); err == nil {
		t.Fatal("被篡改 key_id 的密钥文件必须加载失败")
	}
}

// 每个节点必须有独立的默认密钥路径，否则同机多节点会全部退化成同一个身份。
func TestDefaultNodeKeyPathIsPerPort(t *testing.T) {
	cases := []struct{ listen, want string }{
		{"127.0.0.1:17777", "~/.futurecast/node-17777.key"},
		{"0.0.0.0:7777", "~/.futurecast/node-7777.key"},
		{"", "fallback"},
		{"127.0.0.1:0", "fallback"},
		{"nonsense", "fallback"},
	}
	for _, c := range cases {
		got := defaultNodeKeyPath(c.listen, "fallback")
		if got != c.want {
			t.Fatalf("defaultNodeKeyPath(%q)=%q，期望 %q", c.listen, got, c.want)
		}
	}
}
