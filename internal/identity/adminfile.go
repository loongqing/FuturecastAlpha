package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// AdminKeyFileMagic 是管理员密钥文件的标识行。
const AdminKeyFileMagic = "futurecast-adminkey-v1"

// SaveAdminKey 把一把管理员密钥写入文件（0600）。
//
// 文件格式（便于离线抄写与人工核对）：
//
//	futurecast-adminkey-v1
//	label: <label>
//	role: root
//	key_id: <hex>
//	seed: <base64>
func SaveAdminKey(path string, k *AdminKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("futurecast: 创建目录失败: %w", err)
	}
	role := "root"
	if k.Role == pb.AdminRole_ADMIN_ROLE_PUBLISHER {
		role = "publisher"
	}
	content := fmt.Sprintf("%s\nlabel: %s\nrole: %s\nkey_id: %s\nseed: %s\n",
		AdminKeyFileMagic, k.Label, role, k.KeyID.String(),
		base64Std(k.KeySeed))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("futurecast: 写入管理员密钥失败: %w", err)
	}
	return nil
}

// LoadAdminKey 从文件读取管理员密钥并校验 key_id 与种子一致。
func LoadAdminKey(path string) (*AdminKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("futurecast: 读取管理员密钥 %s 失败: %w", path, err)
	}
	var label, role, keyIDHex, seedB64 string
	lines := strings.Split(string(raw), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != AdminKeyFileMagic {
		return nil, fmt.Errorf("futurecast: %s 不是管理员密钥文件", path)
	}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "label":
			label = val
		case "role":
			role = val
		case "key_id":
			keyIDHex = val
		case "seed":
			seedB64 = val
		}
	}
	if seedB64 == "" {
		return nil, fmt.Errorf("futurecast: %s 缺少 seed 字段", path)
	}
	seed, err := base64Decode(seedB64)
	if err != nil {
		return nil, fmt.Errorf("futurecast: %s 的 seed 不是合法 base64: %w", path, err)
	}
	r := pb.AdminRole_ADMIN_ROLE_ROOT
	if role == "publisher" {
		r = pb.AdminRole_ADMIN_ROLE_PUBLISHER
	}
	k, err := AdminKeyFromSeed(seed, label, r)
	if err != nil {
		return nil, err
	}
	if keyIDHex != "" {
		want, err := housekitchen.KeyIDFromHex(keyIDHex)
		if err != nil {
			return nil, fmt.Errorf("futurecast: %s 的 key_id 非法: %w", path, err)
		}
		if want != k.KeyID {
			return nil, fmt.Errorf("futurecast: %s 的 key_id 与种子不匹配（文件被改动过？）", path)
		}
	}
	return k, nil
}

// LoadKeyring 读取目录下全部 *.key 文件。
func LoadKeyring(dir string) (*Keyring, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("futurecast: 读取密钥环目录 %s 失败: %w", dir, err)
	}
	kr := NewKeyring()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		k, err := LoadAdminKey(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		kr.Add(k)
	}
	if len(kr.Keys) == 0 {
		return nil, fmt.Errorf("futurecast: 目录 %s 下没有 *.key 管理员密钥", dir)
	}
	return kr, nil
}

var _ = crypto.SeedSize
