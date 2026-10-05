package conformance_test

import (
	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
)

// encFixed64Field 编码 proto fixed64 字段（little-endian），零值省略。
func encFixed64Field(field int, v uint64) []byte {
	if v == 0 {
		return nil
	}
	out := append(tag(field, 1), make([]byte, 8)...)
	for i := 0; i < 8; i++ {
		out[len(out)-8+i] = byte(v >> (8 * uint(i)))
	}
	return out
}

// encNodeAnnounce 手工编码 NodeAnnounce（self_signature field 7 清空）。
func encNodeAnnounce(a *pb.NodeAnnounce) []byte {
	var out []byte
	if n := housekitchen.GetNodeID(a.GetNodeId()); !n.IsZero() {
		out = append(out, encMsgField(1, encHashLike(n.Bytes()))...)
	}
	for _, addr := range a.GetAddrs() {
		out = append(out, encStringField(2, addr)...)
	}
	if a.GetAddressPublic() {
		out = append(out, append(tag(3, 0), 1)...)
	}
	if h := housekitchen.GetHash(a.GetRendezvousHint()); !h.IsZero() {
		out = append(out, encMsgField(4, encHashLike(h.Bytes()))...)
	}
	out = append(out, encVarintField(5, uint64(a.GetSeq()))...)
	out = append(out, encVarintField(6, uint64(a.GetIssuedAtUnixNanos()))...)
	return out
}

// encSealedPayload 手工编码 SealedPayload。
func encSealedPayload(s *pb.SealedPayload) []byte {
	var out []byte
	if h := housekitchen.GetHash(s.GetInboxRendezvousId()); !h.IsZero() {
		out = append(out, encMsgField(1, encHashLike(h.Bytes()))...)
	}
	out = append(out, encFixed64Field(2, s.GetEpoch())...)
	out = append(out, encBytesField(3, s.GetEphemeralX25519())...)
	out = append(out, encBytesField(4, s.GetCiphertext())...)
	out = append(out, encFixed64Field(5, s.GetJitterHintMs())...)
	out = append(out, encBytesField(6, s.GetInnerBody())...)
	return out
}
