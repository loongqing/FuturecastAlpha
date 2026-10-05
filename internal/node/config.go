package node

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// AdminMode 是超级管理员的 IP 可见性模式（对应设计文档 §5.1）。
type AdminMode string

const (
	// AdminModePublic：公布自身地址、可被连接，门限签名明文可见，任何节点可验证。
	AdminModePublic AdminMode = "public"
	// AdminModeSigned：不监听、只出站，但由中继带上门限签名转发，公众仍可验证。
	AdminModeSigned AdminMode = "signed"
	// AdminModeSealed：不监听、只出站，门限签名被封存，仅持主题密钥者可验证。
	AdminModeSealed AdminMode = "sealed"
)

// Valid 校验模式取值。
func (m AdminMode) Valid() bool {
	switch m {
	case AdminModePublic, AdminModeSigned, AdminModeSealed:
		return true
	default:
		return false
	}
}

// HidesAddress 表示该模式不向网络公布自身地址。
func (m AdminMode) HidesAddress() bool { return m != AdminModePublic }

// Config 是节点运行配置。
type Config struct {
	// NodeKeyPath 是节点身份密钥文件路径。
	NodeKeyPath string
	// Listen 是监听地址；空字符串表示不监听（sealed/signed 超管）。
	Listen string
	// Network 是 "quic"（默认）或 "tcp"。
	Network string
	// Seeds 是种子节点地址列表，可只给 1~3 个。
	Seeds []string
	// MinPeers / MaxPeers 控制连接数自适应区间。
	MinPeers int
	MaxPeers int
	// AdminMode 是超管 IP 可见性模式；普通节点填 AdminModePublic 亦可。
	AdminMode AdminMode
	// VerifyLevel 是本地验证级别。
	VerifyLevel VerifyLevel
	// Topics 是本地订阅的主题白名单。
	Topics []string
	// Relay 是封存中继配置。
	Relay RelayConfig
	// AdminKeyPaths 是超级管理员私钥文件路径（仅超管节点需要）。
	AdminKeyPaths []string
	// PublishPublic 决定节点动态里是否包含自身地址。
	PublishPublic bool
	// TopicSecret 是主题共享口令（仅 sealed 模式的内容保密层需要）。
	// 非空时：内层管理员正文在发布前用派生的主题密钥加密，
	// 没有口令的观察者与中继只能看到密文。
	// 为空时：sealed 退化为"只隐藏提交者、不隐藏内容"，节点启动时告警。
	TopicSecret string
}

// VerifyLevel 是本地验证级别（对应设计文档 §9）。
type VerifyLevel string

const (
	// VerifyStrict：所有消息都必须带管理员门限签名。
	VerifyStrict VerifyLevel = "strict"
	// VerifyStandard：管理员主题必须门限签名，普通主题允许节点自签。
	VerifyStandard VerifyLevel = "standard"
	// VerifyOpen：任何消息都转发，仅在展示层标注来源。
	VerifyOpen VerifyLevel = "open"
)

// RelayConfig 是封存中继与信箱配置。
type RelayConfig struct {
	// Enabled 开启封存中继能力。
	Enabled bool
	// MailboxCapacity 是本节点为信箱保留的最大条目数。
	MailboxCapacity int
	// MailboxTTL 是信箱条目的存活时间。
	MailboxTTL time.Duration
	// SealedJitterMin / Max 是发布封存副本的抖动区间。
	SealedJitterMin time.Duration
	SealedJitterMax time.Duration
	// Relays 是每代选定的中继数量 k。
	Relays int
	// EpochDuration 是信箱与中继轮换周期。
	EpochDuration time.Duration
}

// DefaultConfig 返回带默认值的配置。
func DefaultConfig() Config {
	return Config{
		Network:       "quic",
		MinPeers:      housekitchen.DefaultMinPeers,
		MaxPeers:      housekitchen.DefaultMaxPeers,
		AdminMode:     AdminModePublic,
		VerifyLevel:   VerifyStandard,
		PublishPublic: true,
		Relay: RelayConfig{
			Enabled:         true,
			MailboxCapacity: 128,
			MailboxTTL:      7 * 24 * time.Hour,
			SealedJitterMin: 200 * time.Millisecond,
			SealedJitterMax: 2500 * time.Millisecond,
			Relays:          4,
			EpochDuration:   24 * time.Hour,
		},
	}
}

// normalize 填充默认值并做基本校验。
func (c *Config) normalize() error {
	d := DefaultConfig()
	if c.Network == "" {
		c.Network = d.Network
	}
	if c.Network != "quic" && c.Network != "tcp" {
		return fmt.Errorf("futurecast: 不支持的传输类型 %q", c.Network)
	}
	if c.MinPeers <= 0 {
		c.MinPeers = d.MinPeers
	}
	if c.MaxPeers <= 0 {
		c.MaxPeers = d.MaxPeers
	}
	if c.MinPeers > c.MaxPeers {
		return fmt.Errorf("futurecast: min_peers(%d) 不得大于 max_peers(%d)", c.MinPeers, c.MaxPeers)
	}
	if c.AdminMode == "" {
		c.AdminMode = d.AdminMode
	}
	if !c.AdminMode.Valid() {
		return fmt.Errorf("futurecast: 未知的超管模式 %q", c.AdminMode)
	}
	if c.VerifyLevel == "" {
		c.VerifyLevel = d.VerifyLevel
	}
	switch c.VerifyLevel {
	case VerifyStrict, VerifyStandard, VerifyOpen:
	default:
		return fmt.Errorf("futurecast: 未知的验证级别 %q", c.VerifyLevel)
	}
	if c.Relay.MailboxCapacity <= 0 {
		c.Relay.MailboxCapacity = d.Relay.MailboxCapacity
	}
	if c.Relay.MailboxTTL <= 0 {
		c.Relay.MailboxTTL = d.Relay.MailboxTTL
	}
	if c.Relay.SealedJitterMax <= 0 {
		c.Relay.SealedJitterMax = d.Relay.SealedJitterMax
	}
	if c.Relay.SealedJitterMin <= 0 {
		c.Relay.SealedJitterMin = d.Relay.SealedJitterMin
	}
	if c.Relay.Relays <= 0 {
		c.Relay.Relays = d.Relay.Relays
	}
	if c.Relay.EpochDuration <= 0 {
		c.Relay.EpochDuration = d.Relay.EpochDuration
	}
	if c.AdminMode.HidesAddress() {
		// sealed/signed 超管绝不能监听：这是"不做种子、不可被扫描"的实现保证。
		c.Listen = ""
		c.PublishPublic = false
	}
	return nil
}

// Options 是 New 的入参。
type Options struct {
	Config Config
	// Identity 为 nil 时按 Config.NodeKeyPath 加载或创建。
	Identity *identity.NodeIdentity
	// Genesis 是创世 AdminSet，必填。
	Genesis *pb.AdminSet
	// AdminKeys 是超管私钥（仅超管节点需要）。
	AdminKeys []*identity.AdminKey
	// Now 覆盖时间源，便于测试。
	Now func() time.Time
	// Logf 是可选的日志函数。
	Logf func(format string, args ...any)
	// RandomSeed 为测试固定随机源；0 表示使用系统随机。
	RandomSeed int64
}

// localPub 是辅助函数：从节点身份取 ed25519 公钥。
func localPub(id *identity.NodeIdentity) ed25519.PublicKey { return id.Pub }
