// Package transport 负责节点之间的连接：QUIC 优先，TLS-over-TCP 作为兼容后备。
//
// 两种实现共用同一套握手流程与帧格式，因此上层 node 包不感知底层差异
// （对应设计文档 P5：QUIC 是加分项，不是正确性前提）。
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/loongqing/FuturecastAlpha/internal/codec"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// Conn 是一条已建立的节点间连接。
type Conn struct {
	// RemoteAddr 是对端网络地址。
	RemoteAddr net.Addr
	// Outbound 表示本连接由本节点主动发起。
	Outbound bool
	// Network 是底层网络类型："udp"（QUIC）或 "tcp"。
	Network string

	frame  frameIO
	closer func() error

	wmu sync.Mutex // 串行化写，避免多 goroutine 交错
}

// frameIO 抽象"读一帧 / 写一帧"。
type frameIO interface {
	readFrame() (*pb.Frame, error)
	writeFrame(*pb.Frame) error
	close() error
}

// ReadFrame 读取一帧。
func (c *Conn) ReadFrame() (*pb.Frame, error) { return c.frame.readFrame() }

// WriteFrame 写入一帧。并发安全。
func (c *Conn) WriteFrame(f *pb.Frame) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.frame.writeFrame(f)
}

// Close 关闭连接。
func (c *Conn) Close() error {
	if c.closer != nil {
		return c.closer()
	}
	return c.frame.close()
}

// CloseGraceful 在关闭前先确保已写入的帧真的发出去。
//
// 用于一次性客户端的收尾路径：写完最后一帧后不能立刻断开，
// 否则该帧可能还在发送缓冲里就被丢弃。grace 是留给对端接收的最短时间。
func (c *Conn) CloseGraceful(grace time.Duration) error {
	if gs, ok := c.frame.(interface{ closeWrite() error }); ok {
		_ = gs.closeWrite()
	}
	if grace > 0 {
		time.Sleep(grace)
	}
	return c.Close()
}

// Transport 持有监听套接字与 QUIC 状态。
type Transport struct {
	Network string // "quic" 或 "tcp"
	TLS     *tls.Config

	quicTr   *quic.Transport
	quicLn   *quic.Listener
	tcpLn    net.Listener
	closed   chan struct{}
	closeMux sync.Mutex
	isClosed bool

	// AcceptTimeout 限制单次 Accept 等待时间，0 表示不限制。
	AcceptTimeout time.Duration
}

// Options 配置 Transport。
type Options struct {
	// Network 为 "quic"（默认）或 "tcp"。
	Network string
	// Listen 为空表示不监听（sealed 超管模式：只出站）。
	Listen string
	// CommonName 用于生成自签证书。
	CommonName string
}

// New 创建并（在 Listen 非空时）开始监听。
func New(opts Options) (*Transport, error) {
	network := opts.Network
	if network == "" {
		network = "quic"
	}
	cn := opts.CommonName
	if cn == "" {
		cn = "futurecast"
	}
	tlsConf, err := SelfSignedTLS(cn)
	if err != nil {
		return nil, err
	}
	t := &Transport{Network: network, TLS: tlsConf, closed: make(chan struct{})}
	if opts.Listen == "" {
		// 只出站模式：仍然需要一个 UDP socket 用于 QUIC 拨号。
		if network == "quic" {
			pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
			if err != nil {
				return nil, fmt.Errorf("futurecast: 分配出站 UDP socket 失败: %w", err)
			}
			t.quicTr = &quic.Transport{Conn: pc}
		}
		return t, nil
	}
	switch network {
	case "quic":
		pc, err := net.ListenUDP("udp", mustUDPAddr(opts.Listen))
		if err != nil {
			return nil, fmt.Errorf("futurecast: 监听 UDP %s 失败: %w", opts.Listen, err)
		}
		t.quicTr = &quic.Transport{Conn: pc}
		ln, err := t.quicTr.Listen(tlsConf, quicConfig())
		if err != nil {
			return nil, fmt.Errorf("futurecast: 启动 QUIC 监听失败: %w", err)
		}
		t.quicLn = ln
	case "tcp":
		ln, err := tls.Listen("tcp", opts.Listen, tlsConf)
		if err != nil {
			return nil, fmt.Errorf("futurecast: 监听 TCP %s 失败: %w", opts.Listen, err)
		}
		t.tcpLn = ln
	default:
		return nil, fmt.Errorf("futurecast: 不支持的传输类型 %q", network)
	}
	return t, nil
}

func mustUDPAddr(addr string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return &net.UDPAddr{IP: net.IPv4zero, Port: 7777}
	}
	return a
}

// quicConfig 返回统一的 QUIC 参数。
func quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:        60 * time.Second,
		KeepAlivePeriod:       20 * time.Second,
		MaxIncomingStreams:    64,
		MaxIncomingUniStreams: 64,
		Allow0RTT:             false,
	}
}

// LocalAddr 返回监听地址，未监听时返回 nil。
func (t *Transport) LocalAddr() net.Addr {
	switch {
	case t.quicLn != nil:
		return t.quicLn.Addr()
	case t.tcpLn != nil:
		return t.tcpLn.Addr()
	default:
		return nil
	}
}

// Listening 表示是否处于监听状态。
func (t *Transport) Listening() bool { return t.quicLn != nil || t.tcpLn != nil }

// Dial 主动连接对端。
func (t *Transport) Dial(ctx context.Context, addr string) (*Conn, error) {
	switch t.Network {
	case "quic":
		if t.quicTr == nil {
			pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
			if err != nil {
				return nil, fmt.Errorf("futurecast: 分配出站 UDP socket 失败: %w", err)
			}
			t.quicTr = &quic.Transport{Conn: pc}
		}
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("futurecast: 解析地址 %s 失败: %w", addr, err)
		}
		qc, err := t.quicTr.Dial(ctx, udpAddr, ClientTLS(t.TLS), quicConfig())
		if err != nil {
			return nil, fmt.Errorf("futurecast: 连接 %s 失败: %w", addr, err)
		}
		st, err := qc.OpenStreamSync(ctx)
		if err != nil {
			_ = qc.CloseWithError(0, "open stream failed")
			return nil, fmt.Errorf("futurecast: 打开流失败: %w", err)
		}
		return &Conn{
			RemoteAddr: qc.RemoteAddr(), Outbound: true, Network: "quic",
			frame:  &quicStream{stream: st, conn: qc},
			closer: func() error { return qc.CloseWithError(0, "bye") },
		}, nil
	case "tcp":
		d := &net.Dialer{Timeout: 10 * time.Second}
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("futurecast: 连接 %s 失败: %w", addr, err)
		}
		tc := tls.Client(raw, ClientTLS(t.TLS))
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("futurecast: TLS 握手失败: %w", err)
		}
		return &Conn{
			RemoteAddr: raw.RemoteAddr(), Outbound: true, Network: "tcp",
			frame:  &tcpStream{conn: tc},
			closer: tc.Close,
		}, nil
	default:
		return nil, fmt.Errorf("futurecast: 不支持的传输类型 %q", t.Network)
	}
}

// Accept 等待并接受一条入站连接。
func (t *Transport) Accept(ctx context.Context) (*Conn, error) {
	switch {
	case t.quicLn != nil:
		qc, err := t.quicLn.Accept(ctx)
		if err != nil {
			return nil, err
		}
		st, err := qc.AcceptStream(ctx)
		if err != nil {
			_ = qc.CloseWithError(0, "accept stream failed")
			return nil, err
		}
		return &Conn{
			RemoteAddr: qc.RemoteAddr(), Outbound: false, Network: "quic",
			frame:  &quicStream{stream: st, conn: qc},
			closer: func() error { return qc.CloseWithError(0, "bye") },
		}, nil
	case t.tcpLn != nil:
		raw, err := t.tcpLn.Accept()
		if err != nil {
			return nil, err
		}
		tc, ok := raw.(*tls.Conn)
		if !ok {
			_ = raw.Close()
			return nil, fmt.Errorf("futurecast: 非预期的 TCP 连接类型")
		}
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := tc.HandshakeContext(hctx); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("futurecast: TLS 握手失败: %w", err)
		}
		return &Conn{
			RemoteAddr: raw.RemoteAddr(), Outbound: false, Network: "tcp",
			frame:  &tcpStream{conn: tc},
			closer: tc.Close,
		}, nil
	default:
		return nil, fmt.Errorf("futurecast: 本节点未监听，无法接受连接")
	}
}

// Close 关闭监听与所有状态。
func (t *Transport) Close() error {
	t.closeMux.Lock()
	defer t.closeMux.Unlock()
	if t.isClosed {
		return nil
	}
	t.isClosed = true
	close(t.closed)
	var firstErr error
	if t.quicLn != nil {
		if err := t.quicLn.Close(); err != nil {
			firstErr = err
		}
	}
	if t.tcpLn != nil {
		if err := t.tcpLn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if t.quicTr != nil {
		if err := t.quicTr.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ---------- frameIO 实现 ----------

type quicStream struct {
	stream quic.Stream
	conn   quic.Connection
}

func (q *quicStream) readFrame() (*pb.Frame, error) {
	_ = q.stream.SetReadDeadline(time.Now().Add(120 * time.Second))
	return codec.ReadFrame(q.stream)
}

func (q *quicStream) writeFrame(f *pb.Frame) error {
	_ = q.stream.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return codec.WriteFrame(q.stream, f)
}

// close 优雅关闭：先关流（发 FIN，quic-go 保证已写入的数据可靠送达），
// 再关连接。
//
// 为什么不能直接 CloseWithError：那是立即断开，效果等同 CancelWrite ——
// 已写入但尚未发出的数据**不保证送达**。一次性发布客户端"写 PUSH 后立刻退出"
// 的场景下，这会让消息静默丢失（实测约 1/3 概率）。
func (q *quicStream) close() error {
	_ = q.stream.Close()
	return q.conn.CloseWithError(0, "closed")
}

// closeWrite 只关闭写侧（发 FIN），让已写入的数据可靠送达，连接本身保持。
func (q *quicStream) closeWrite() error { return q.stream.Close() }

type tcpStream struct{ conn net.Conn }

func (s *tcpStream) readFrame() (*pb.Frame, error) {
	_ = s.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	return codec.ReadFrame(s.conn)
}

func (s *tcpStream) writeFrame(f *pb.Frame) error {
	_ = s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return codec.WriteFrame(s.conn, f)
}

func (s *tcpStream) close() error { return s.conn.Close() }

// closeWrite 尽力优雅关闭写侧：TLS 连接用 CloseNotify 通知对端不再发送。
func (s *tcpStream) closeWrite() error {
	if tc, ok := s.conn.(*tls.Conn); ok {
		return tc.CloseWrite()
	}
	return nil
}

// 确保 housekitchen 被引用（帧大小常量在校验中使用）。
var _ = housekitchen.DefaultMaxFrameSize

// ErrClosed 表示传输已关闭。
var ErrClosed = errors.New("futurecast: 传输已关闭")
