package identity

import "encoding/hex"

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }

// HexEncode 编码为十六进制。
func HexEncode(b []byte) string { return hex.EncodeToString(b) }
