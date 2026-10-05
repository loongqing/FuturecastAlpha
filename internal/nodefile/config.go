// Package nodefile 负责 CLI 的配置文件读写。
//
// 使用 JSON 而非 YAML：本环境虽有 goproxy.cn 镜像，但少一个依赖就少一类问题，
// 同时 JSON 配置天然可被脚本与其他工具解析。
package nodefile

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/node"
)

// Config 是节点配置文件的内容。
type Config struct {
	// NodeKeyPath 是节点身份密钥文件，默认 ~/.futurecast/node.key。
	NodeKeyPath string `json:"node_key_path"`
	// Listen 是监听地址；留空 = 不监听（sealed/signed 超管）。
	Listen string `json:"listen"`
	// Network 为 "quic"（默认）或 "tcp"。
	Network string `json:"network"`
	// Seeds 是种子节点地址，只写 1~3 个即可自动扩张。
	Seeds []string `json:"seeds"`
	// MinPeers / MaxPeers 控制连接数自适应区间。
	MinPeers int `json:"min_peers"`
	MaxPeers int `json:"max_peers"`
	// AdminMode 为 public / signed / sealed。
	AdminMode string `json:"admin_mode"`
	// VerifyLevel 为 strict / standard / open。
	VerifyLevel string `json:"verify_level"`
	// Topics 是本地订阅主题。
	Topics []string `json:"topics"`
	// TopicSecret 是主题共享口令（sealed 内容保密层）。
	TopicSecret string `json:"topic_secret"`
	// AdminSetPath 是创世（或当前）AdminSet 的 JSON 文件。
	AdminSetPath string `json:"admin_set_path"`
	// AdminKeyPaths 是管理员私钥文件（仅超管节点需要）。
	AdminKeyPaths []string `json:"admin_key_paths"`
	// RelayConfig 控制封存中继与信箱。
	Relay RelayConfig `json:"relay"`
}

// RelayConfig 是封存中继配置。
type RelayConfig struct {
	Enabled         bool `json:"enabled"`
	MailboxCapacity int  `json:"mailbox_capacity"`
	Relays          int  `json:"relays"`
	EpochHours      int  `json:"epoch_hours"`
	JitterMinMS     int  `json:"jitter_min_ms"`
	JitterMaxMS     int  `json:"jitter_max_ms"`
}

// Default 返回一份带默认值的配置。
func Default() Config {
	d := node.DefaultConfig()
	return Config{
		NodeKeyPath: "~/.futurecast/node.key",
		Listen:      "0.0.0.0:7777",
		Network:     d.Network,
		MinPeers:    d.MinPeers,
		MaxPeers:    d.MaxPeers,
		AdminMode:   string(d.AdminMode),
		VerifyLevel: string(d.VerifyLevel),
		Relay: RelayConfig{
			Enabled:         true,
			MailboxCapacity: d.Relay.MailboxCapacity,
			Relays:          d.Relay.Relays,
			EpochHours:      int(d.Relay.EpochDuration / time.Hour),
			JitterMinMS:     int(d.Relay.SealedJitterMin / time.Millisecond),
			JitterMaxMS:     int(d.Relay.SealedJitterMax / time.Millisecond),
		},
	}
}

// Load 读取配置文件。
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("futurecast: 读取配置 %s 失败: %w", path, err)
	}
	cfg := Default()
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("futurecast: 解析配置 %s 失败: %w", path, err)
	}
	return cfg, nil
}

// Save 写出配置文件（0600）。
func Save(path string, cfg Config) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// ToNodeConfig 转换为 node.Config。
func (c Config) ToNodeConfig() (node.Config, error) {
	out := node.DefaultConfig()
	out.NodeKeyPath = c.NodeKeyPath
	out.Listen = c.Listen
	if c.Network != "" {
		out.Network = c.Network
	}
	out.Seeds = c.Seeds
	if c.MinPeers > 0 {
		out.MinPeers = c.MinPeers
	}
	if c.MaxPeers > 0 {
		out.MaxPeers = c.MaxPeers
	}
	out.AdminMode = node.AdminMode(c.AdminMode)
	out.VerifyLevel = node.VerifyLevel(c.VerifyLevel)
	out.Topics = c.Topics
	out.TopicSecret = c.TopicSecret
	if c.Relay.MailboxCapacity > 0 {
		out.Relay.MailboxCapacity = c.Relay.MailboxCapacity
	}
	out.Relay.Enabled = c.Relay.Enabled
	if c.Relay.Relays > 0 {
		out.Relay.Relays = c.Relay.Relays
	}
	if c.Relay.EpochHours > 0 {
		out.Relay.EpochDuration = time.Duration(c.Relay.EpochHours) * time.Hour
	}
	if c.Relay.JitterMinMS > 0 {
		out.Relay.SealedJitterMin = time.Duration(c.Relay.JitterMinMS) * time.Millisecond
	}
	if c.Relay.JitterMaxMS > 0 {
		out.Relay.SealedJitterMax = time.Duration(c.Relay.JitterMaxMS) * time.Millisecond
	}
	if !out.AdminMode.Valid() {
		return out, fmt.Errorf("futurecast: 配置里的 admin_mode=%q 非法（应为 public/signed/sealed）", c.AdminMode)
	}
	return out, nil
}
