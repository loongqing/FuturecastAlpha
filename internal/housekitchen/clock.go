package housekitchen

import "time"

// Clock 抽象时间源，便于测试注入。
type Clock interface {
	Now() time.Time
}

// RealClock 使用系统时间。
type RealClock struct{}

// Now 返回当前时间。
func (RealClock) Now() time.Time { return time.Now() }

// UnixNanos 返回当前时间的 Unix 纳秒。
func UnixNanos(t time.Time) int64 { return t.UnixNano() }

// FromUnixNanos 把 Unix 纳秒转为 time.Time。
func FromUnixNanos(n int64) time.Time { return time.Unix(0, n) }
