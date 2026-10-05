package peer

import (
	"sync"
	"testing"
	"time"
)

func TestLimiterTokenBucketBoundary(t *testing.T) {
	l := NewLimiter(10, 3) // 10 token/s，桶容量 3
	base := time.Now()

	for i := 0; i < 3; i++ {
		if !l.Allow(1, base) {
			t.Fatalf("burst 内的第 %d 个令牌应放行", i+1)
		}
	}
	if l.Allow(1, base) {
		t.Fatal("burst 用尽后同一时刻应拒绝")
	}

	// 推进 100ms，按 10/s 应补充 1 个令牌。
	at := base.Add(100 * time.Millisecond)
	if !l.Allow(1, at) {
		t.Fatal("补充 1 个令牌后应放行")
	}
	if l.Allow(1, at) {
		t.Fatal("仅剩 0 个令牌时应拒绝")
	}

	// 推进 1s，按 10/s 补 10 个但被 burst=3 截断。
	at = base.Add(1100 * time.Millisecond)
	if !l.Allow(3, at) {
		t.Fatal("补充到满桶后应允许一次性取 3 个")
	}
	if l.Allow(1, at) {
		t.Fatal("满桶取空后应拒绝")
	}

	// 再推进 200ms → 2 个令牌。
	at = base.Add(1300 * time.Millisecond)
	if !l.Allow(2, at) {
		t.Fatal("补充 2 个令牌后应允许取 2")
	}
	if l.Allow(1, at) {
		t.Fatal("取完 2 个后应拒绝")
	}
}

func TestLimiterNoRefillWhenRateZero(t *testing.T) {
	l := NewLimiter(0, 2)
	base := time.Now()
	if !l.Allow(1, base) || !l.Allow(1, base) {
		t.Fatal("初始应放行 burst 个")
	}
	if l.Allow(1, base.Add(time.Hour)) {
		t.Fatal("rate=0 时任何时间推进都不应恢复令牌")
	}
}

func TestLimiterZeroAndNegativeRequests(t *testing.T) {
	l := NewLimiter(1, 1)
	base := time.Now()
	if !l.Allow(0, base) {
		t.Fatal("n=0 应直接放行")
	}
	if !l.Allow(-5, base) {
		t.Fatal("n<0 应直接放行")
	}
	if !l.Allow(1, base) {
		t.Fatal("n=0 不应消耗令牌")
	}
	if l.Allow(1, base) {
		t.Fatal("令牌已耗尽")
	}
}

func TestLimiterZeroBurstTreatedAsOne(t *testing.T) {
	l := NewLimiter(1, 0)
	base := time.Now()
	if !l.Allow(1, base) {
		t.Fatal("burst<=0 视为 1，应放行 1 个")
	}
	if l.Allow(1, base) {
		t.Fatal("burst 用尽后应拒绝")
	}
}

func TestLimiterClockGoingBackwardsDoesNotRefill(t *testing.T) {
	l := NewLimiter(10, 2)
	base := time.Now()
	if !l.Allow(2, base) {
		t.Fatal("初始应放行 2 个")
	}
	if l.Allow(1, base.Add(-time.Hour)) {
		t.Fatal("时间回退不应补充令牌")
	}
}

func TestLimiterTokens(t *testing.T) {
	l := NewLimiter(10, 3)
	base := time.Now()
	if got := l.Tokens(base); got != 3 {
		t.Fatalf("初始令牌应为 3，实为 %v", got)
	}
	l.Allow(2, base)
	if got := l.Tokens(base); got != 1 {
		t.Fatalf("取 2 后令牌应为 1，实为 %v", got)
	}
	if got := l.Tokens(base.Add(500 * time.Millisecond)); got != 3 {
		t.Fatalf("补满后应为 3，实为 %v", got)
	}
}

func TestLimiterConcurrent(t *testing.T) {
	l := NewLimiter(100, 10)
	base := time.Now()
	const workers = 8
	const iters = 500
	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < iters; i++ {
				l.Allow(1, base.Add(time.Duration(w*iters+i)*time.Millisecond))
				_ = l.Tokens(base.Add(time.Duration(w*iters+i) * time.Millisecond))
			}
		}(w)
	}
	close(start)
	wg.Wait()
}
