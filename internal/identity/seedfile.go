package identity

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"
)

const seedFileMagic = "futurecast-seed-v1"

// encodeSeedFile 把种子编码成带 magic 的文本文件内容。
func encodeSeedFile(seed []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(seed)
	return []byte(fmt.Sprintf("# %s\n# 该文件是节点身份私钥，请勿泄露。\n%s\n", seedFileMagic, b64))
}

// decodeSeedFile 解析种子文件，容忍注释行与空白。
func decodeSeedFile(raw []byte) ([]byte, error) {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		seed, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("futurecast: 种子不是合法 base64: %w", err)
		}
		if len(seed) != crypto.SeedSize {
			return nil, fmt.Errorf("futurecast: 种子长度应为 %d，实为 %d", crypto.SeedSize, len(seed))
		}
		return seed, nil
	}
	return nil, fmt.Errorf("futurecast: 种子文件中没有可用的密钥行")
}

// DecodeSeedString 解析十六进制或 base64 种子字符串。
func DecodeSeedString(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		if b, err := hexDecode(s); err == nil {
			return b, nil
		}
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("futurecast: 无法解析种子: %w", err)
	}
	if len(b) != crypto.SeedSize {
		return nil, fmt.Errorf("futurecast: 种子长度应为 %d，实为 %d", crypto.SeedSize, len(b))
	}
	return b, nil
}
