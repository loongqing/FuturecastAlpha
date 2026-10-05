package store

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
)

var t0 = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

func hashOf(b byte) housekitchen.Hash {
	var h housekitchen.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

func mkBody(t *testing.T, seed byte, topic string, created time.Time) *pb.SignedBody {
	t.Helper()
	body := &pb.SignedBody{
		ProtoVersion:       housekitchen.ProtoVersion,
		Kind:               pb.MessageKind_MESSAGE_KIND_ADMIN_BROADCAST,
		Topic:              topic,
		CreatedAtUnixNanos: created.UnixNano(),
		ExpiresAtUnixNanos: created.Add(72 * time.Hour).UnixNano(),
		Nonce:              bytes.Repeat([]byte{seed}, housekitchen.NonceSize),
		AdminSetGeneration: 1,
		MaxHops:            housekitchen.DefaultMaxHops,
	}
	id, err := housekitchen.MsgID(body)
	if err != nil {
		t.Fatalf("MsgID: %v", err)
	}
	body.MsgId = housekitchen.PBHash(id)
	return body
}

func mkEnv(t *testing.T, seed byte, topic string, created time.Time) *pb.Envelope {
	t.Helper()
	body := mkBody(t, seed, topic, created)
	return &pb.Envelope{
		MsgId:              body.MsgId,
		MaxHops:            uint32(body.MaxHops),
		FirstSeenUnixNanos: created.UnixNano(),
		Body:               body,
	}
}

func envID(t *testing.T, env *pb.Envelope) housekitchen.Hash {
	t.Helper()
	return housekitchen.GetHash(env.GetMsgId())
}

// ---------- 去重 ----------

func TestSeenDuplicate(t *testing.T) {
	s := New(16, time.Hour)
	a, b := hashOf(0x11), hashOf(0x22)

	if !s.Seen(a, t0) {
		t.Fatal("首次 Seen 应为 true")
	}
	if s.Seen(a, t0.Add(time.Minute)) {
		t.Fatal("窗口内重复 Seen 应为 false")
	}
	if !s.Seen(b, t0.Add(time.Minute)) {
		t.Fatal("不同 msgID 首次 Seen 应为 true")
	}
	if !s.Repeated(a, t0.Add(time.Minute)) {
		t.Fatal("Repeated 应报告在窗口内")
	}
	if s.Repeated(hashOf(0x33), t0) {
		t.Fatal("未知 msgID 的 Repeated 应为 false")
	}
}

func TestSeenSlidingWindowExpiry(t *testing.T) {
	s := New(16, time.Hour)
	id := hashOf(0x44)

	if !s.Seen(id, t0) {
		t.Fatal("首次 Seen 应为 true")
	}
	// 窗口内重复出现会刷新滑动窗口。
	if s.Seen(id, t0.Add(59*time.Minute)) {
		t.Fatal("窗口内重复 Seen 应为 false")
	}
	// 距最后一次出现 59 分钟，仍在窗口内。
	if s.Seen(id, t0.Add(118*time.Minute)) {
		t.Fatal("距最后出现 59min 仍应在窗口内")
	}
	// 距最后一次出现 61 分钟，超出窗口 → 重新算首次。
	if !s.Seen(id, t0.Add(179*time.Minute)) {
		t.Fatal("超出滑动窗口后应重新算首次出现")
	}
}

func TestSeenLRUCapacityEviction(t *testing.T) {
	s := New(2, time.Hour)
	a, b, c := hashOf(0xA1), hashOf(0xB2), hashOf(0xC3)

	if !s.Seen(a, t0) || !s.Seen(b, t0.Add(time.Second)) || !s.Seen(c, t0.Add(2*time.Second)) {
		t.Fatal("三个不同 msgID 首次均应为 true")
	}
	if s.SeenLen() != 2 {
		t.Fatalf("容量 2 应只保留 2 条，实为 %d", s.SeenLen())
	}
	// a 最久未见，应已被淘汰。
	if !s.Seen(a, t0.Add(3*time.Second)) {
		t.Fatal("被 LRU 淘汰的 msgID 再次出现应为 true")
	}
	// c 最近出现且仍未被淘汰。
	if s.Seen(c, t0.Add(4*time.Second)) {
		t.Fatal("仍在窗口内的 msgID 应为 false")
	}
}

func TestGCExpiresDedupEntries(t *testing.T) {
	s := New(16, time.Hour)
	id := hashOf(0x55)
	if !s.Seen(id, t0) {
		t.Fatal("首次 Seen 应为 true")
	}
	if n := s.GC(t0.Add(30 * time.Minute)); n != 0 {
		t.Fatalf("未过期时 GC 应清 0 条，实为 %d", n)
	}
	if n := s.GC(t0.Add(2 * time.Hour)); n != 1 {
		t.Fatalf("过期后 GC 应清 1 条，实为 %d", n)
	}
	if s.SeenLen() != 0 {
		t.Fatalf("GC 后去重表应为空，实为 %d", s.SeenLen())
	}
	if !s.Seen(id, t0.Add(2*time.Hour)) {
		t.Fatal("GC 后同一 msgID 应重新算首次")
	}
}

// ---------- 消息表 ----------

func TestPutGetRoundTripAndDuplicate(t *testing.T) {
	s := New(64, time.Hour)
	env := mkEnv(t, 0x01, "news", t0)
	id := envID(t, env)

	if err := s.Put(env, t0); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := s.Get(id)
	if !ok {
		t.Fatal("Get 未命中")
	}
	if !proto.Equal(got, env) {
		t.Fatalf("Put/Get 往返不一致:\n got=%v\nwant=%v", got, env)
	}
	// 返回的是深拷贝：修改返回值不得影响存储。
	got.Body.Topic = "hacked"
	again, _ := s.Get(id)
	if again.GetBody().GetTopic() != "news" {
		t.Fatalf("Get 返回的应是深拷贝，实为 %q", again.GetBody().GetTopic())
	}
	// 存储的也是深拷贝：修改入参不得影响存储。
	env.Body.Topic = "mutated"
	third, _ := s.Get(id)
	if third.GetBody().GetTopic() != "news" {
		t.Fatalf("Put 应存深拷贝，实为 %q", third.GetBody().GetTopic())
	}

	err := s.Put(env, t0)
	if !errors.Is(err, housekitchen.ErrDuplicate) {
		t.Fatalf("重复 Put 应包装 ErrDuplicate，实为 %v", err)
	}
	if s.Len() != 1 {
		t.Fatalf("重复 Put 后 Len 应为 1，实为 %d", s.Len())
	}
}

func TestPutNilAndMissingID(t *testing.T) {
	s := New(4, time.Hour)
	if err := s.Put(nil, t0); err == nil {
		t.Fatal("Put(nil) 应报错")
	}
	if err := s.Put(&pb.Envelope{}, t0); err == nil {
		t.Fatal("缺少 msg_id 的 Envelope 应报错")
	}
	// 只有 body.msg_id 也要能识别。
	body := mkBody(t, 0x09, "x", t0)
	env := &pb.Envelope{Body: body}
	if err := s.Put(env, t0); err != nil {
		t.Fatalf("仅有 body.msg_id 的 Envelope 应可存入: %v", err)
	}
	if _, ok := s.Get(housekitchen.GetHash(body.MsgId)); !ok {
		t.Fatal("按 body.msg_id 应能取回")
	}
}

func TestPutCapacityEvictsOldest(t *testing.T) {
	s := New(2, 72*time.Hour)
	e1 := mkEnv(t, 0x01, "t", t0)
	e2 := mkEnv(t, 0x02, "t", t0.Add(time.Minute))
	e3 := mkEnv(t, 0x03, "t", t0.Add(2*time.Minute))
	for _, e := range []*pb.Envelope{e1, e2, e3} {
		if err := s.Put(e, housekitchen.FromUnixNanos(e.GetFirstSeenUnixNanos())); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if s.Len() != 2 {
		t.Fatalf("容量 2 应只保留 2 条，实为 %d", s.Len())
	}
	if _, ok := s.Get(envID(t, e1)); ok {
		t.Fatal("最旧的 e1 应被淘汰")
	}
	if _, ok := s.Get(envID(t, e3)); !ok {
		t.Fatal("e3 应在表中")
	}
}

func TestGCExpiresMessages(t *testing.T) {
	s := New(16, time.Hour)
	env := mkEnv(t, 0x07, "news", t0)
	if err := s.Put(env, t0); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if n := s.GC(t0.Add(30 * time.Minute)); n != 0 {
		t.Fatalf("未过期时 GC 应清 0 条，实为 %d", n)
	}
	if s.Len() != 1 {
		t.Fatalf("未过期时 Len 应为 1，实为 %d", s.Len())
	}
	if n := s.GC(t0.Add(2 * time.Hour)); n != 1 {
		t.Fatalf("过期后 GC 应清 1 条，实为 %d", n)
	}
	if s.Len() != 0 {
		t.Fatalf("GC 后消息表应为空，实为 %d", s.Len())
	}
}

func TestGCExpiresByEnvelopeExpiresAt(t *testing.T) {
	// ttl 很长，但信封自述 expires_at 已过 → 也应被 GC 清掉。
	s := New(16, 30*24*time.Hour)
	body := mkBody(t, 0x08, "news", t0)
	body.ExpiresAtUnixNanos = t0.Add(10 * time.Minute).UnixNano()
	env := &pb.Envelope{MsgId: body.MsgId, Body: body}
	if err := s.Put(env, t0); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if n := s.GC(t0.Add(11 * time.Minute)); n != 1 {
		t.Fatalf("expires_at 已过应被清除，实为 %d", n)
	}
	if s.Len() != 0 {
		t.Fatalf("Len 应为 0，实为 %d", s.Len())
	}
}

func TestListOrderFilterLimit(t *testing.T) {
	s := New(16, 72*time.Hour)
	ea := mkEnv(t, 0x0A, "alpha", t0.Add(2*time.Minute))
	eb := mkEnv(t, 0x0B, "beta", t0.Add(1*time.Minute))
	ec := mkEnv(t, 0x0C, "alpha", t0.Add(3*time.Minute))
	// 乱序写入，验证 List 仍按 first_seen 升序。
	for _, e := range []*pb.Envelope{ec, ea, eb} {
		if err := s.Put(e, housekitchen.FromUnixNanos(e.GetFirstSeenUnixNanos())); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	all := s.List("", time.Time{}, 0)
	if len(all) != 3 {
		t.Fatalf("不限条件应返回 3 条，实为 %d", len(all))
	}
	want := []string{"beta", "alpha", "alpha"}
	for i, e := range all {
		if e.GetBody().GetTopic() != want[i] {
			t.Fatalf("第 %d 条应为 %s，实为 %s", i, want[i], e.GetBody().GetTopic())
		}
	}
	if all[0].GetFirstSeenUnixNanos() > all[1].GetFirstSeenUnixNanos() {
		t.Fatal("first_seen 应升序")
	}

	alpha := s.List("alpha", time.Time{}, 0)
	if len(alpha) != 2 {
		t.Fatalf("主题 alpha 应为 2 条，实为 %d", len(alpha))
	}
	since := s.List("", t0.Add(90*time.Second), 0)
	if len(since) != 2 {
		t.Fatalf("since=t0+90s 应为 2 条，实为 %d", len(since))
	}
	limited := s.List("", time.Time{}, 1)
	if len(limited) != 1 || limited[0].GetBody().GetTopic() != "beta" {
		t.Fatalf("limit=1 应返回最早的 beta，实为 %v", limited)
	}
	if got := s.List("nope", time.Time{}, 0); len(got) != 0 {
		t.Fatalf("未知主题应返回 0 条，实为 %d", len(got))
	}
}

// ---------- 分片与清单 ----------

func TestChunksAndCommitManifest(t *testing.T) {
	s := New(16, time.Hour)
	cid := hashOf(0x71)
	chunks := [][]byte{[]byte("hello "), []byte("world")}
	var total uint64
	for _, c := range chunks {
		total += uint64(len(c))
	}
	m := &pb.ContentManifest{
		ContentId:  housekitchen.PBHash(cid),
		TotalSize:  total,
		ChunkSize:  6,
		ChunkCount: 2,
		MerkleRoot: MerkleRoot(chunks),
	}

	if s.HasContent(cid, 2) {
		t.Fatal("尚未写分片时 HasContent 应为 false")
	}
	if miss := s.MissingChunks(cid, 2); len(miss) != 2 || miss[0] != 0 || miss[1] != 1 {
		t.Fatalf("缺失分片应为 [0 1]，实为 %v", miss)
	}
	err := s.CommitManifest(m)
	if err == nil {
		t.Fatal("分片不全时 CommitManifest 应报错")
	}
	if errors.Is(err, housekitchen.ErrInvalidSignature) {
		t.Fatalf("分片缺失不应报 ErrInvalidSignature（那是数据不符），实为 %v", err)
	}

	for i, c := range chunks {
		if err := s.PutChunk(cid, uint32(i), c); err != nil {
			t.Fatalf("PutChunk(%d): %v", i, err)
		}
	}
	if !s.HasContent(cid, 2) {
		t.Fatal("分片齐全后 HasContent 应为 true")
	}
	got, ok := s.GetChunk(cid, 1)
	if !ok || !bytes.Equal(got, chunks[1]) {
		t.Fatalf("GetChunk 往返不一致: %q ok=%v", got, ok)
	}
	got[0] = 'X' // 深拷贝语义
	again, _ := s.GetChunk(cid, 1)
	if again[0] != 'w' {
		t.Fatal("GetChunk 应返回深拷贝")
	}
	if err := s.CommitManifest(m); err != nil {
		t.Fatalf("分片正确时 CommitManifest 应成功: %v", err)
	}
	if _, ok := s.Manifest(cid); !ok {
		t.Fatal("CommitManifest 成功后应能取回清单")
	}
	if s.ChunkCount(cid) != 2 {
		t.Fatalf("ChunkCount 应为 2，实为 %d", s.ChunkCount(cid))
	}
}

func TestCommitManifestRejectsTamperedChunk(t *testing.T) {
	s := New(16, time.Hour)
	cid := hashOf(0x72)
	chunks := [][]byte{[]byte("alpha"), []byte("bravo")}
	m := &pb.ContentManifest{
		ContentId:  housekitchen.PBHash(cid),
		TotalSize:  10,
		ChunkSize:  5,
		ChunkCount: 2,
		MerkleRoot: MerkleRoot(chunks),
	}
	for i, c := range chunks {
		if err := s.PutChunk(cid, uint32(i), c); err != nil {
			t.Fatalf("PutChunk: %v", err)
		}
	}
	if err := s.CommitManifest(m); err != nil {
		t.Fatalf("初次提交应成功: %v", err)
	}
	// 篡改一个分片（长度不变，只有 Merkle 根能发现）。
	if err := s.PutChunk(cid, 1, []byte("BRAVO")); err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	err := s.CommitManifest(m)
	if !errors.Is(err, housekitchen.ErrInvalidSignature) {
		t.Fatalf("篡改分片应包装 ErrInvalidSignature，实为 %v", err)
	}
	// 总长不符（清单声明 10 字节，实际 12 字节）也应被判为内容与清单不符。
	bad := proto.Clone(m).(*pb.ContentManifest)
	if err := s.PutChunk(cid, 1, []byte("bravoxx")); err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	if err := s.CommitManifest(bad); !errors.Is(err, housekitchen.ErrInvalidSignature) {
		t.Fatalf("总长不符应包装 ErrInvalidSignature，实为 %v", err)
	}
}

func TestCommitManifestStructuralValidation(t *testing.T) {
	s := New(16, time.Hour)
	cid := hashOf(0x73)

	cases := []struct {
		name string
		m    *pb.ContentManifest
	}{
		{"nil", nil},
		{"零 content_id", &pb.ContentManifest{ChunkSize: 4, ChunkCount: 1}},
		{"零 chunk_size", &pb.ContentManifest{ContentId: housekitchen.PBHash(cid), ChunkCount: 1}},
		{"空清单", &pb.ContentManifest{ContentId: housekitchen.PBHash(cid), ChunkSize: 4}},
		{"count 与 total_size 不符", &pb.ContentManifest{
			ContentId: housekitchen.PBHash(cid), TotalSize: 12, ChunkSize: 4, ChunkCount: 2}},
		{"merkle_root 长度非法", &pb.ContentManifest{
			ContentId: housekitchen.PBHash(cid), TotalSize: 4, ChunkSize: 4, ChunkCount: 1,
			MerkleRoot: []byte{1, 2, 3}}},
	}
	for _, tc := range cases {
		if err := s.CommitManifest(tc.m); err == nil {
			t.Fatalf("%s: 应报错", tc.name)
		}
	}
	// 长度非法的 merkle_root 在分片齐全时也必须报 ErrInvalidSignature。
	if err := s.PutChunk(cid, 0, []byte("abcd")); err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	err := s.CommitManifest(&pb.ContentManifest{
		ContentId: housekitchen.PBHash(cid), TotalSize: 4, ChunkSize: 4, ChunkCount: 1,
		MerkleRoot: []byte{1, 2, 3},
	})
	if !errors.Is(err, housekitchen.ErrInvalidSignature) {
		t.Fatalf("merkle_root 长度非法应包装 ErrInvalidSignature，实为 %v", err)
	}
}

func TestChunkInputValidation(t *testing.T) {
	s := New(4, time.Hour)
	if err := s.PutChunk(housekitchen.Hash{}, 0, []byte("x")); err == nil {
		t.Fatal("零 content_id 应报错")
	}
	if _, ok := s.GetChunk(hashOf(1), 9); ok {
		t.Fatal("不存在的分片不应命中")
	}
	if !s.HasContent(hashOf(1), 0) {
		t.Fatal("count=0 应视为空内容完整")
	}
}

// ---------- 并发 ----------

func TestConcurrentPutSameMsgIDOnlyOneWins(t *testing.T) {
	s := New(128, time.Hour)
	env := mkEnv(t, 0x31, "concurrent", t0)

	const n = 32
	var wg sync.WaitGroup
	results := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = s.Put(env, t0)
		}(i)
	}
	close(start)
	wg.Wait()

	okCount, dupCount := 0, 0
	for i, err := range results {
		switch {
		case err == nil:
			okCount++
		case errors.Is(err, housekitchen.ErrDuplicate):
			dupCount++
		default:
			t.Fatalf("goroutine %d 意外错误: %v", i, err)
		}
	}
	if okCount != 1 {
		t.Fatalf("同一 msgID 并发 Put 应只有 1 次成功，实为 %d", okCount)
	}
	if dupCount != n-1 {
		t.Fatalf("其余应全部 ErrDuplicate，实为 %d", dupCount)
	}
	if s.Len() != 1 {
		t.Fatalf("Len 应为 1，实为 %d", s.Len())
	}
}

func TestConcurrentSeenSameMsgIDOnlyOneWins(t *testing.T) {
	s := New(128, time.Hour)
	id := hashOf(0x99)

	const n = 32
	var wg sync.WaitGroup
	seen := make([]bool, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			seen[i] = s.Seen(id, t0)
		}(i)
	}
	close(start)
	wg.Wait()

	trueCount := 0
	for _, v := range seen {
		if v {
			trueCount++
		}
	}
	if trueCount != 1 {
		t.Fatalf("同一 msgID 并发 Seen 应只有 1 次 true，实为 %d", trueCount)
	}
}

func TestConcurrentMixedOperations(t *testing.T) {
	s := New(64, time.Hour)
	cid := hashOf(0x81)
	chunks := [][]byte{[]byte("aaaaaaaa"), []byte("bbbbbbbb")}
	m := &pb.ContentManifest{
		ContentId:  housekitchen.PBHash(cid),
		TotalSize:  16,
		ChunkSize:  8,
		ChunkCount: 2,
		MerkleRoot: MerkleRoot(chunks),
	}
	for i, c := range chunks {
		if err := s.PutChunk(cid, uint32(i), c); err != nil {
			t.Fatalf("PutChunk: %v", err)
		}
	}

	const workers = 8
	const iters = 200
	// 测试辅助函数不得在子 goroutine 中调用 t.Fatal，因此先在主 goroutine 里备好数据。
	envs := make([]*pb.Envelope, workers)
	ids := make([]housekitchen.Hash, workers)
	for w := 0; w < workers; w++ {
		envs[w] = mkEnv(t, byte(w+1), fmt.Sprintf("topic-%d", w%3), t0)
		ids[w] = envID(t, envs[w])
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < iters; i++ {
				s.Seen(hashOf(byte(w+1)), t0.Add(time.Duration(i)*time.Millisecond))
				_ = s.Put(envs[w], t0)
				if got, ok := s.Get(ids[w]); ok {
					_ = got.GetBody().GetTopic()
				}
				_ = s.List("topic-1", t0, 4)
				_ = s.Len()
				_ = s.MissingChunks(cid, 2)
				_, _ = s.GetChunk(cid, uint32(i%2))
				if i%50 == 0 {
					_ = s.CommitManifest(m)
					s.GC(t0.Add(time.Duration(i) * time.Second))
				}
			}
		}(w)
	}
	close(start)
	wg.Wait()
}
