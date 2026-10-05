package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// ALPN 是本协议的 ALPN 标识。
const ALPN = "futurecast/1"

// SelfSignedTLS 生成一个自签证书的 TLS 配置。
//
// 证书本身不承担身份认证职责 —— 端点身份由应用层 HELLO 消息中的
// ed25519 自签证明保证（见 identity.VerifyHello）。因此客户端跳过证书校验，
// 但 TLS 仍然提供链路机密性与完整性。
func SelfSignedTLS(commonName string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("futurecast: 生成 TLS 私钥失败: %w", err)
	}
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, fmt.Errorf("futurecast: 生成证书序列号失败: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"futurecast"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("futurecast: 自签证书失败: %w", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{ALPN},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLS 由服务端配置派生客户端配置：复用证书、跳过校验。
func ClientTLS(server *tls.Config) *tls.Config {
	c := server.Clone()
	c.InsecureSkipVerify = true
	c.ServerName = "futurecast"
	c.NextProtos = []string{ALPN}
	return c
}
