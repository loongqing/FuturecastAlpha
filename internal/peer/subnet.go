package peer

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// SubnetKey 把地址映射到子网分组键：IPv4 取 /24、IPv6 取 /48；主机名则按小写主机名分组。
//
// 支持的输入形式：
//
//	"203.0.113.7:7777"  -> "v4:203.0.113"
//	"203.0.113.7"       -> "v4:203.0.113"
//	"[2001:db8:1:2::1]:7777" -> "v6:20010db80102"
//	"2001:db8:1:2::1"   -> "v6:20010db80102"
//	"seed.example.org:7777" / "seed.example.org" -> "name:seed.example.org"
//
// 空地址（或无法解析的地址）返回空串，调用方应跳过空串（不计入配额）。
func SubnetKey(addr string) string {
	s := strings.TrimSpace(addr)
	if s == "" {
		return ""
	}
	host := s
	if h, _, err := net.SplitHostPort(s); err == nil {
		host = h
	} else {
		// 无端口（含裸 IPv6）或带方括号但不带端口的形式。
		host = strings.TrimSpace(s)
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "name:" + strings.ToLower(host)
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("v4:%d.%d.%d", b[0], b[1], b[2])
	}
	b := ip.As16()
	return fmt.Sprintf("v6:%02x%02x:%02x%02x:%02x%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// normalizeAddrs 规整地址列表：去空、规整 IP 表示、去重，保持原顺序。
func normalizeAddrs(addrs []string) []string {
	if len(addrs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(addrs))
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		key := canonicalAddr(a)
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func canonicalAddr(addr string) string {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		if ip, err := netip.ParseAddr(strings.TrimSpace(h)); err == nil {
			return net.JoinHostPort(ip.Unmap().WithZone("").String(), p)
		}
		return net.JoinHostPort(strings.ToLower(strings.TrimSpace(h)), p)
	}
	host := addr
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(host)); err == nil {
		return ip.Unmap().WithZone("").String()
	}
	return strings.ToLower(host)
}
