package sealed

import (
	"google.golang.org/protobuf/proto"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

// marshalProto 使用确定性序列化，保证封存明文可复现。
func marshalProto(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

// unmarshalProto 解析 protobuf。
func unmarshalProto(b []byte, m proto.Message) error { return proto.Unmarshal(b, m) }

var _ = (*pb.SignedBody)(nil)
