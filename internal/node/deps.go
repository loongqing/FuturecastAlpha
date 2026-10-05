package node

import (
	"time"

	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// 说明：以下接口按 docs/CONTRACTS.md 第 6 节的前置声明。
//
// 之所以在 node 包内声明接口而不是直接依赖具体类型，是为了：
//  1. 让 node 包可以独立编译与测试，不被并行开发中的包阻塞；
//  2. 允许测试注入内存实现。
//
// Go 的结构化类型系统保证 internal/store.Store 与 internal/peer.Table
// 自动满足这些接口 —— 无需任何适配代码。

// MessageStore 是内容寻址存储与去重表（由 internal/store 实现）。
type MessageStore interface {
	// Seen 首次见到 msgID 返回 true。
	Seen(msgID housekitchen.Hash, at time.Time) bool
	// Put 保存信封；重复 msgID 返回 ErrDuplicate。
	Put(env *pb.Envelope, at time.Time) error
	// Get 按 msgID 取信封（契约签名，与 internal/store 逐字一致）。
	Get(msgID housekitchen.Hash) (*pb.Envelope, bool)
	// List 按 topic 与时间窗列举，first_seen 升序。
	List(topic string, since time.Time, limit int) []*pb.Envelope
	// Topics 返回存储中出现过的全部主题。
	Topics() []string
	// Len 返回条目数。
	Len() int
	// GC 清理过期条目，返回清除数量。
	GC(now time.Time) int

	// PutChunk 保存内容分片。
	PutChunk(contentID housekitchen.Hash, index uint32, data []byte) error
	// GetChunk 读取内容分片。
	GetChunk(contentID housekitchen.Hash, index uint32) ([]byte, bool)
	// HasContent 判断是否已完整持有内容。
	HasContent(contentID housekitchen.Hash, count uint32) bool
	// MissingChunks 返回缺失的分片下标。
	MissingChunks(contentID housekitchen.Hash, count uint32) []uint32
	// CommitManifest 逐片校验并确认内容。
	CommitManifest(m *pb.ContentManifest) error
}

// PeerRecord 是共享节点记录类型的别名。
type PeerRecord = housekitchen.NodeRecord

// PeerTable 是 Kademlia 路由表与评分系统（由 internal/peer 实现）。
type PeerTable interface {
	Upsert(rec PeerRecord) error
	Remove(id housekitchen.NodeID)
	Get(id housekitchen.NodeID) (PeerRecord, bool)
	Touch(id housekitchen.NodeID, rtt time.Duration, at time.Time)
	MarkFailure(id housekitchen.NodeID, at time.Time) bool
	Len() int
	NeedMorePeers() bool
	Closest(target housekitchen.NodeID, k int) []PeerRecord
	// All 返回表中全部记录（用于枚举已知节点与采集收件人公钥）。
	All() []PeerRecord
	Bucket(target housekitchen.NodeID) int
	Expire(now time.Time) []housekitchen.NodeID
	Reward(id housekitchen.NodeID, delta int)
	Penalize(id housekitchen.NodeID, delta int, reason string) bool
	IsBanned(nodeID housekitchen.NodeID, at time.Time) bool
}

// Limiter 是每连接令牌桶（由 internal/peer 实现）。
type Limiter interface {
	Allow(n int, at time.Time) bool
}
