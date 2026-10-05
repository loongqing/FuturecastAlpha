package sealed_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"
	"github.com/loongqing/FuturecastAlpha/internal/housekitchen"
	"github.com/loongqing/FuturecastAlpha/internal/sealed"

	pb "github.com/loongqing/FuturecastAlpha/gen/futurecastv1"
)

func TestSealOpenRoundTrip(t *testing.T) {
	// 中继身份
	relaySeed, err := crypto.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	// admin 身份
	adminSeed, _ := crypto.GenerateSeed()

	xPub, err := crypto.Ed25519SeedToX25519Public(relaySeed) // == Ed25519ToX25519(relayEdPub)
	if err != nil {
		t.Fatal(err)
	}

	rendezvous, err := sealed.RendezvousFor(adminSeed, 42)
	if err != nil {
		t.Fatal(err)
	}
	body := &pb.SignedBody{
		ProtoVersion:       1,
		Kind:               pb.MessageKind_MESSAGE_KIND_ADMIN_BROADCAST,
		Topic:              "alerts",
		CreatedAtUnixNanos: 1700000000,
		Nonce:              housekitchen.RandomNonce(),
		AdminSetGeneration: 1,
		MaxHops:            32,
	}

	sp, err := sealed.Seal(xPub, body, rendezvous, 42, 1000)
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	t.Logf("recipient x25519 pub = %x", xPub)
	t.Logf("ephemeral x25519 pub = %x", sp.GetEphemeralX25519())
	t.Logf("rendezvous = %s epoch = %d", rendezvous.Short(), sp.GetEpoch())

	scalar, err := crypto.Ed25519SeedToX25519Scalar(relaySeed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sealed.Open(scalar, sp)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	if got.GetTopic() != body.GetTopic() {
		t.Fatalf("主题不一致: %q", got.GetTopic())
	}
	if got.GetNonce()[0] != body.GetNonce()[0] {
		t.Fatal("nonce 不一致")
	}
}

// 用真实的 ed25519 密钥对走一遍：确认 Ed25519ToX25519（公钥）与
// Ed25519SeedToX25519Scalar（私钥标量）确实配对可用。
func TestSealOpenWithEd25519DerivedKeys(t *testing.T) {
	relaySeed, _ := crypto.GenerateSeed()
	relayPriv, _ := crypto.KeyFromSeed(relaySeed)
	relayEdPub := relayPriv.Public().(ed25519.PublicKey)

	xPubFromEd, err := crypto.Ed25519ToX25519(relayEdPub)
	if err != nil {
		t.Fatal(err)
	}
	xPubFromSeed, err := crypto.Ed25519SeedToX25519Public(relaySeed)
	if err != nil {
		t.Fatal(err)
	}
	if !housekitchen.ConstantTimeEqual(xPubFromEd, xPubFromSeed) {
		t.Fatalf("派生不一致: ed=%x seed=%x", xPubFromEd, xPubFromSeed)
	}

	adminSeed, _ := crypto.GenerateSeed()
	rendezvous, _ := sealed.RendezvousFor(adminSeed, 7)
	body := &pb.SignedBody{ProtoVersion: 1, Topic: "t", Nonce: housekitchen.RandomNonce()}
	_ = body

	sp, err := sealed.Seal(xPubFromEd, body, rendezvous, 7, 0)
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	ephPriv, _ := crypto.GenerateX25519()
	_ = ephPriv
	scalar, err := crypto.Ed25519SeedToX25519Scalar(relaySeed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sealed.Open(scalar, sp)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	if got.GetTopic() != "t" {
		t.Fatalf("主题不一致: %q", got.GetTopic())
	}
}
