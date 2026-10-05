// Package codec 负责传输帧的编解码。
//
// 线格式：4 字节大端长度前缀 + protobuf(Frame)，长度上限为 housekitchen.DefaultMaxFrameSize。
// 超过上限一律拒绝并返回 ErrFrameTooLarge —— 这是防止内存放大型攻击的第一道闸门。
package codec

import (
	"encoding/binary"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
)

// MaxFrameSize 是单帧最大字节数。
const MaxFrameSize = housekitchen.DefaultMaxFrameSize

// EncodeFrame 把 Frame 序列化为带长度前缀的字节。
func EncodeFrame(f *pb.Frame) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("futurecast: Frame 为空")
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("futurecast: Frame 序列化失败: %w", err)
	}
	if len(body) > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d 字节 > 上限 %d", housekitchen.ErrFrameTooLarge, len(body), MaxFrameSize)
	}
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(len(body)))
	copy(out[4:], body)
	return out, nil
}

// DecodeFrame 从字节解析 Frame。
func DecodeFrame(b []byte) (*pb.Frame, error) {
	f := &pb.Frame{}
	if err := proto.Unmarshal(b, f); err != nil {
		return nil, fmt.Errorf("futurecast: Frame 反序列化失败: %w", err)
	}
	return f, nil
}

// ReadFrame 从 r 读取一帧。长度前缀非法或超限时返回错误。
func ReadFrame(r io.Reader) (*pb.Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, fmt.Errorf("futurecast: 零长度帧")
	}
	if n > MaxFrameSize {
		return nil, fmt.Errorf("%w: 声明 %d 字节 > 上限 %d", housekitchen.ErrFrameTooLarge, n, MaxFrameSize)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("futurecast: 读取帧内容失败: %w", err)
	}
	return DecodeFrame(buf)
}

// WriteFrame 把 Frame 写入 w。
func WriteFrame(w io.Writer, f *pb.Frame) error {
	b, err := EncodeFrame(f)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// ---------- 常用 Frame 构造器 ----------

// NewHello 包装握手消息。
func NewHello(h *pb.Hello) *pb.Frame { return &pb.Frame{Body: &pb.Frame_Hello{Hello: h}} }

// NewPing 包装探测消息。
func NewPing(nonce uint64, atNanos int64) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_Ping{Ping: &pb.Ping{Nonce: nonce, IssuedAtUnixNanos: atNanos}}}
}

// NewPong 包装探测应答。
func NewPong(nonce uint64, atNanos int64) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_Pong{Pong: &pb.Pong{Nonce: nonce, IssuedAtUnixNanos: atNanos}}}
}

// NewFindNode 包装节点查找请求。
func NewFindNode(target housekitchen.NodeID, want uint32) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_FindNode{FindNode: &pb.FindNode{
		Target: housekitchen.PBNodeID(target), Want: want,
	}}}
}

// NewNodes 包装节点查找应答。
func NewNodes(target housekitchen.NodeID, nodes []*pb.NodeInfo) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_Nodes{Nodes: &pb.Nodes{
		Target: housekitchen.PBNodeID(target), Nodes: nodes,
	}}}
}

// NewPeerExchange 包装邻居互推。
func NewPeerExchange(pe *pb.PeerExchange) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_PeerExchange{PeerExchange: pe}}
}

// NewPush 包装一条新消息推送。
func NewPush(env *pb.Envelope) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_Push{Push: &pb.Push{Envelope: env}}}
}

// NewInv 包装消息清单。
func NewInv(topic string, ids []housekitchen.Hash, sinceNanos int64) *pb.Frame {
	hs := make([]*pb.Hash, 0, len(ids))
	for _, id := range ids {
		hs = append(hs, housekitchen.PBHash(id))
	}
	return &pb.Frame{Body: &pb.Frame_Inv{Inv: &pb.Inv{Topic: topic, MsgIds: hs, SinceUnixNanos: sinceNanos}}}
}

// NewGet 包装缺失消息请求。
func NewGet(ids []housekitchen.Hash) *pb.Frame {
	hs := make([]*pb.Hash, 0, len(ids))
	for _, id := range ids {
		hs = append(hs, housekitchen.PBHash(id))
	}
	return &pb.Frame{Body: &pb.Frame_Get{Get: &pb.Get{MsgIds: hs}}}
}

// NewMsg 包装消息应答。
func NewMsg(envs []*pb.Envelope) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_Msg{Msg: &pb.Msg{Envelopes: envs}}}
}

// NewSealedSubmit 包装封存投递。
func NewSealedSubmit(s *pb.SealedSubmit) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_SealedSubmit{SealedSubmit: s}}
}

// NewSealedReceipt 包装封存回执。
func NewSealedReceipt(r *pb.SealedReceipt) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_SealedReceipt{SealedReceipt: r}}
}

// NewMailboxStore 包装信箱写入。
func NewMailboxStore(m *pb.MailboxStore) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_MailboxStore{MailboxStore: m}}
}

// NewMailboxGet 包装信箱拉取请求。
func NewMailboxGet(m *pb.MailboxGet) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_MailboxGet{MailboxGet: m}}
}

// NewMailboxData 包装信箱数据应答。
func NewMailboxData(m *pb.MailboxData) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_MailboxData{MailboxData: m}}
}

// NewGetContent 包装内容分片请求。
func NewGetContent(id housekitchen.Hash, from, count uint32) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_GetContent{GetContent: &pb.GetContent{
		ContentId: housekitchen.PBHash(id), FromIndex: from, Count: count,
	}}}
}

// NewContentChunk 包装内容分片应答。
func NewContentChunk(c *pb.ContentChunk) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_ContentChunk{ContentChunk: c}}
}

// NewBye 包装断开通知。
func NewBye(reason string) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_Bye{Bye: &pb.Bye{Reason: reason}}}
}

// NewError 包装错误应答。
func NewError(code uint32, msg string, retryable bool) *pb.Frame {
	return &pb.Frame{Body: &pb.Frame_Error{Error: &pb.Error{Code: code, Message: msg, Retryable: retryable}}}
}

// KindName 返回 Frame 的类型名，用于日志。
func KindName(f *pb.Frame) string {
	if f == nil || f.Body == nil {
		return "empty"
	}
	switch f.Body.(type) {
	case *pb.Frame_Hello:
		return "HELLO"
	case *pb.Frame_Ping:
		return "PING"
	case *pb.Frame_Pong:
		return "PONG"
	case *pb.Frame_FindNode:
		return "FIND_NODE"
	case *pb.Frame_Nodes:
		return "NODES"
	case *pb.Frame_PeerExchange:
		return "PEER_EXCHANGE"
	case *pb.Frame_Push:
		return "PUSH"
	case *pb.Frame_Inv:
		return "INV"
	case *pb.Frame_Get:
		return "GET"
	case *pb.Frame_Msg:
		return "MSG"
	case *pb.Frame_GetContent:
		return "GET_CONTENT"
	case *pb.Frame_ContentChunk:
		return "CHUNK"
	case *pb.Frame_SealedSubmit:
		return "SEALED_SUBMIT"
	case *pb.Frame_SealedReceipt:
		return "SEALED_RECEIPT"
	case *pb.Frame_MailboxStore:
		return "MAILBOX_STORE"
	case *pb.Frame_MailboxGet:
		return "MAILBOX_GET"
	case *pb.Frame_MailboxData:
		return "MAILBOX_DATA"
	case *pb.Frame_Bye:
		return "BYE"
	case *pb.Frame_Error:
		return "ERROR"
	default:
		return "unknown"
	}
}
