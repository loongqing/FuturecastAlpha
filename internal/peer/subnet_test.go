package peer

import "testing"

func TestSubnetKey(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"203.0.113.7:7777", "v4:203.0.113"},
		{"203.0.113.7", "v4:203.0.113"},
		{"203.0.113.200:1", "v4:203.0.113"},
		{"203.0.114.7:7777", "v4:203.0.114"},
		{"10.0.0.1:1", "v4:10.0.0"},
		{"10.0.0.200:1", "v4:10.0.0"},
		{"[2001:db8:1:2::1]:7777", "v6:2001:0db8:0001"},
		{"2001:db8:1:2::1", "v6:2001:0db8:0001"},
		{"[2001:db8:1:2::1]", "v6:2001:0db8:0001"},
		{"2001:db8:1:ffff::9", "v6:2001:0db8:0001"},
		{"2001:db8:2::1", "v6:2001:0db8:0002"},
		{"[::1]:7777", "v6:0000:0000:0000"},
		{"::1", "v6:0000:0000:0000"},
		{"[::ffff:203.0.113.9]:80", "v4:203.0.113"},
		{"seed.example.org:7777", "name:seed.example.org"},
		{"seed.example.org", "name:seed.example.org"},
		{"SEED.Example.ORG:1", "name:seed.example.org"},
		{"", ""},
		{"   ", ""},
	}
	for _, tc := range cases {
		if got := SubnetKey(tc.in); got != tc.want {
			t.Errorf("SubnetKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSubnetKeyGroupsSameSlash24AndSlash48(t *testing.T) {
	if SubnetKey("192.168.1.1:1") != SubnetKey("192.168.1.254:65535") {
		t.Fatal("同 /24 的不同地址应同组")
	}
	if SubnetKey("192.168.1.1:1") == SubnetKey("192.168.2.1:1") {
		t.Fatal("相邻 /24 不应同组")
	}
	if SubnetKey("2001:db8:aa:0:1::1") != SubnetKey("[2001:db8:aa:ffff::2]:9") {
		t.Fatal("同 /48 的不同 IPv6 地址应同组")
	}
	if SubnetKey("2001:db8:aa::1") == SubnetKey("2001:db8:ab::1") {
		t.Fatal("相邻 /48 不应同组")
	}
}

func TestNormalizeAddrs(t *testing.T) {
	got := normalizeAddrs([]string{
		" 203.0.113.7:7777 ",
		"203.0.113.7:7777",
		"",
		"SEED.Example.ORG:1",
		"seed.example.org:1",
		"[2001:DB8::1]:2",
	})
	want := []string{"203.0.113.7:7777", "seed.example.org:1", "[2001:db8::1]:2"}
	if len(got) != len(want) {
		t.Fatalf("normalizeAddrs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalizeAddrs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if normalizeAddrs(nil) != nil || normalizeAddrs([]string{"", "  "}) != nil {
		t.Fatal("空列表应归为 nil")
	}
}
