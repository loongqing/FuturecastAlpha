package directed_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/loongqing/FuturecastAlpha/internal/directed"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/identity"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

const testTopic = "alerts"

type fixture struct {
	set  *pb.AdminSet
	keys []*identity.AdminKey
	now  time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	kr := identity.NewKeyring()
	var keys []*identity.AdminKey
	for _, l := range []string{"a", "b", "c"} {
		k, err := identity.NewAdminKey(l, pb.AdminRole_ADMIN_ROLE_ROOT)
		if err != nil {
			t.Fatal(err)
		}
		kr.Add(k)
		keys = append(keys, k)
	}
	set, err := kr.BuildAdminSet(1, 2, 3, "genesis")
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{set: set, keys: keys, now: time.Unix(1700000000, 0)}
}

// signDirected 完整走一遍签发流程。
func (f *fixture) signDirected(t *testing.T, recipients []directed.Recipient, text string, n int) *pb.DirectedBody {
	t.Helper()
	body, err := directed.NewDirectedBody(f.set, recipients, testTopic, "text/plain", text, f.now, time.Hour)
	if err != nil {
		t.Fatalf("组装失败: %v", err)
	}
	canonical, err := directed.CanonicalForSigning(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := directed.Finalize(body, canonical, f.keys[:n], n, f.now); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	return body
}

func recipientOf(t *testing.T, n *identity.NodeIdentity) directed.Recipient {
	t.Helper()
	return directed.Recipient{NodeID: n.ID, Ed25519Pub: n.Pub}
}

// T1 — 被点名的收件人必须能解出正文，且能验证超管门限签名。
func TestRecipientsCanDecrypt(t *testing.T) {
	f := newFixture(t)
	alice, _ := identity.NewNodeIdentity()
	bob, _ := identity.NewNodeIdentity()
	carol, _ := identity.NewNodeIdentity()

	body := f.signDirected(t, []directed.Recipient{
		recipientOf(t, alice), recipientOf(t, bob), recipientOf(t, carol),
	}, "只有你们三个能看到", 2)

	if _, err := directed.VerifyBody(body, f.set, f.now); err != nil {
		t.Fatalf("外层校验应通过: %v", err)
	}
	for _, n := range []*identity.NodeIdentity{alice, bob, carol} {
		res, err := directed.Open(n.KeySeed, n.ID, body)
		if err != nil {
			t.Fatalf("收件人 %s 应能解密: %v", n.ID.Short(), err)
		}
		if got := res.Kernel.GetBody(); got != "只有你们三个能看到" {
			t.Fatalf("正文不一致: %q", got)
		}
		if res.Kernel.GetTopic() != testTopic {
			t.Fatalf("topic 不一致: %q", res.Kernel.GetTopic())
		}
	}
}

// T2 — 没被点名的节点必须解不开，并且得到 ErrNotAuthorized（而非"解密失败"这类模糊错误）。
func TestNonRecipientCannotDecrypt(t *testing.T) {
	f := newFixture(t)
	alice, _ := identity.NewNodeIdentity()
	bob, _ := identity.NewNodeIdentity()
	outsider, _ := identity.NewNodeIdentity()

	body := f.signDirected(t, []directed.Recipient{recipientOf(t, alice)}, "机密", 2)

	if _, err := directed.Open(bob.KeySeed, bob.ID, body); !errors.Is(err, housekitchen.ErrNotAuthorized) {
		t.Fatalf("非收件人应得到 ErrNotAuthorized，实为: %v", err)
	}
	if _, err := directed.Open(outsider.KeySeed, outsider.ID, body); !errors.Is(err, housekitchen.ErrNotAuthorized) {
		t.Fatalf("陌生节点应得到 ErrNotAuthorized，实为: %v", err)
	}
}

// T3 — 消息里绝不能出现收件人的 node_id 或公钥明文（名单隐私的定义）。
func TestRecipientListNotInPlaintext(t *testing.T) {
	f := newFixture(t)
	alice, _ := identity.NewNodeIdentity()
	bob, _ := identity.NewNodeIdentity()

	body := f.signDirected(t, []directed.Recipient{recipientOf(t, alice), recipientOf(t, bob)}, "机密", 2)
	blob, err := protoMarshal(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []housekitchen.NodeID{alice.ID, bob.ID} {
		if strings.Contains(string(blob), string(id.Bytes())) {
			t.Fatalf("序列化结果中出现了收件人 node_id 明文: %s", id.Short())
		}
	}
	// 也不得出现收件人公钥明文。
	for _, pub := range [][]byte{alice.Pub, bob.Pub} {
		if strings.Contains(string(blob), string(pub)) {
			t.Fatal("序列化结果中出现了收件人公钥明文")
		}
	}
	// 但正文也不该在明文里。
	if strings.Contains(string(blob), "机密") {
		t.Fatal("正文出现在明文序列化中")
	}
}

// T4 — 门限不足必须被拒（外层验签即失败，中继无需解密）。
func TestDirectedRequiresAdminThreshold(t *testing.T) {
	f := newFixture(t)
	alice, _ := identity.NewNodeIdentity()
	body := f.signDirected(t, []directed.Recipient{recipientOf(t, alice)}, "机密", 1)

	_, err := directed.VerifyBody(body, f.set, f.now)
	if !errors.Is(err, housekitchen.ErrThresholdNotMet) {
		t.Fatalf("1/3 签名应被拒且报门限错误，实为: %v", err)
	}
}

// T5 — 篡改外层任一字段必须被拒（msg_id 内容寻址）。
func TestDirectedTamperRejected(t *testing.T) {
	f := newFixture(t)
	alice, _ := identity.NewNodeIdentity()
	body := f.signDirected(t, []directed.Recipient{recipientOf(t, alice)}, "机密", 2)

	body.CreatedAtUnixNanos++ // 改时间戳
	if _, err := directed.VerifyBody(body, f.set, f.now); !errors.Is(err, housekitchen.ErrMsgIDMismatch) {
		t.Fatalf("篡改 created_at 应以 ErrMsgIDMismatch 被拒，实为: %v", err)
	}
}

// T6 — 同一条内容发给不同集合，产生的槽位 tag 必须不同（跨消息不可关联）。
func TestTagsAreUnlinkableAcrossMessages(t *testing.T) {
	f := newFixture(t)
	alice, _ := identity.NewNodeIdentity()
	r := []directed.Recipient{recipientOf(t, alice)}

	b1 := f.signDirected(t, r, "第一条", 2)
	b2 := f.signDirected(t, r, "第二条", 2)

	t1 := b1.GetRecipients()[0].GetRecipientTag()
	t2 := b2.GetRecipients()[0].GetRecipientTag()
	if housekitchen.ConstantTimeEqual(t1, t2) {
		t.Fatal("同一收件人在两条消息里的 tag 相同 —— 观察者可以跨消息关联出名单")
	}
	// eph_pub 也必须每消息不同，否则同样可关联。
	if housekitchen.ConstantTimeEqual(b1.GetRecipients()[0].GetEphPub(), b2.GetRecipients()[0].GetEphPub()) {
		t.Fatal("两条消息的 eph_pub 相同，可被关联")
	}
}

// T7 — 中继/任何节点都能验证"这确实来自超管"，但看不到正文。
func TestAnyoneCanVerifyButNotRead(t *testing.T) {
	f := newFixture(t)
	alice, _ := identity.NewNodeIdentity()
	body := f.signDirected(t, []directed.Recipient{recipientOf(t, alice)}, "只给 alice", 2)

	// 一个完全没有私钥的观察者：能验签。
	res, err := directed.VerifyBody(body, f.set, f.now)
	if err != nil {
		t.Fatalf("观察者应能验证门限签名: %v", err)
	}
	if len(res.Signers) != 2 {
		t.Fatalf("应看到 2 个有效签名者，实为 %d", len(res.Signers))
	}
	// 但读不到正文。
	outsider, _ := identity.NewNodeIdentity()
	if _, err := directed.Open(outsider.KeySeed, outsider.ID, body); err == nil {
		t.Fatal("非收件人不应能解密")
	}
}

// T8 — 过期必须被拒。
func TestDirectedExpiredRejected(t *testing.T) {
	f := newFixture(t)
	alice, _ := identity.NewNodeIdentity()
	body := f.signDirected(t, []directed.Recipient{recipientOf(t, alice)}, "机密", 2)

	_, err := directed.VerifyBody(body, f.set, f.now.Add(2*time.Hour))
	if !errors.Is(err, housekitchen.ErrExpired) {
		t.Fatalf("过期应以 ErrExpired 被拒，实为: %v", err)
	}
}

// T9 — 代数/集合不符必须被拒。
func TestDirectedWrongAdminSetRejected(t *testing.T) {
	f := newFixture(t)
	kr2 := identity.NewKeyring()
	for _, l := range []string{"x", "y", "z"} {
		k, _ := identity.NewAdminKey(l, pb.AdminRole_ADMIN_ROLE_ROOT)
		kr2.Add(k)
	}
	other, _ := kr2.BuildAdminSet(1, 2, 3, "other")

	alice, _ := identity.NewNodeIdentity()
	body := f.signDirected(t, []directed.Recipient{recipientOf(t, alice)}, "机密", 2)

	if _, err := directed.VerifyBody(body, other, f.now); !errors.Is(err, housekitchen.ErrSignerSetMismatch) {
		t.Fatalf("另一个集合应报 ErrSignerSetMismatch，实为: %v", err)
	}
}

// T10 — recipient_count 被篡改必须被拒（防"少报人数"混淆）。
func TestDirectedRecipientCountMismatch(t *testing.T) {
	f := newFixture(t)
	alice, _ := identity.NewNodeIdentity()
	bob, _ := identity.NewNodeIdentity()
	body := f.signDirected(t, []directed.Recipient{recipientOf(t, alice), recipientOf(t, bob)}, "机密", 2)

	body.RecipientCount = 1
	if _, err := directed.VerifyBody(body, f.set, f.now); err == nil {
		t.Fatal("recipient_count 与槽位数不符应被拒")
	}
}

func protoMarshal(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}
