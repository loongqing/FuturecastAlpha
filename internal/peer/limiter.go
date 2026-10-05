package peer

import (
	"sync"
	"time"
)

// Limiter 是每连接一个的令牌桶。
//
// 语义：桶容量为 burst，初始装满；按 ratePerSec 连续补充，上限 burst；
// Allow(n, at) 在桶内令牌足够时扣除 n 并返回 true。时间回退（at 早于上次调用）不补充令牌。
// ratePerSec <= 0 表示只出不进；n <= 0 视为零成本，直接放行。
type Limiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

// NewLimiter 构造令牌桶。burst <= 0 时按 1 处理（即没有余量）。
func NewLimiter(ratePerSec float64, burst int) *Limiter {
	b := float64(burst)
	if b <= 0 {
		b = 1
	}
	return &Limiter{
		rate:   ratePerSec,
		burst:  b,
		tokens: b,
	}
}

// Allow 尝试为 n 个令牌放行。
func (l *Limiter) Allow(n int, at time.Time) bool {
	if n <= 0 {
		return true
	}
	if at.IsZero() {
		at = time.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.refillLocked(at)
	want := float64(n)
	if l.tokens+1e-9 >= want {
		l.tokens -= want
		return true
	}
	return false
}

// Tokens 返回当前可用令牌数（补充后），便于观测与测试。
func (l *Limiter) Tokens(at time.Time) float64 {
	if at.IsZero() {
		at = time.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillLocked(at)
	return l.tokens
}

func (l *Limiter) refillLocked(at time.Time) {
	if l.last.IsZero() {
		l.last = at
		return
	}
	if !at.After(l.last) {
		return
	}
	if l.rate > 0 {
		l.tokens += at.Sub(l.last).Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
	}
	l.last = at
}
