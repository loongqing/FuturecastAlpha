package crypto_test

import (
	"testing"

	"github.com/loongqing/FuturecastAlpha/internal/crypto"
)

func TestX25519SharedSymmetric(t *testing.T) {
	a, err := crypto.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	b, err := crypto.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	s1, err := crypto.X25519Shared(a.Private, b.Public)
	if err != nil {
		t.Fatalf("a→b: %v", err)
	}
	s2, err := crypto.X25519Shared(b.Private, a.Public)
	if err != nil {
		t.Fatalf("b→a: %v", err)
	}
	t.Logf("s1=%x", s1)
	t.Logf("s2=%x", s2)
	if string(s1) != string(s2) {
		t.Fatal("ECDH 不对称")
	}
}

func TestHKDFDeterministic(t *testing.T) {
	secret := []byte("shared-secret-32-bytes-long-xxxx")
	k1, err := crypto.HKDF(secret, nil, "info", 32)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := crypto.HKDF(secret, nil, "info", 32)
	if err != nil {
		t.Fatal(err)
	}
	if string(k1) != string(k2) {
		t.Fatal("HKDF 不确定")
	}
	t.Logf("key=%x", k1)
}

func TestSealOpenFromSenderRoundTrip(t *testing.T) {
	recipient, _ := crypto.GenerateX25519()
	eph, _ := crypto.GenerateX25519()

	ad := []byte("associated-data")
	plain := []byte("hello sealed world")

	ephPub, sealed, err := crypto.SealForRecipient(eph.Private, recipient.Public, plain, ad, "info")
	if err != nil {
		t.Fatalf("SealForRecipient: %v", err)
	}
	t.Logf("ephPub(computed)=%x", ephPub)
	t.Logf("eph.Public      =%x", eph.Public)

	got, err := crypto.OpenFromSender(recipient.Private, ephPub, sealed, ad, "info")
	if err != nil {
		t.Fatalf("OpenFromSender: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("往返内容不一致: %q", got)
	}
}
