package controller

import (
	"net/netip"
	"testing"
)

func TestParsePorts(t *testing.T) {
	ranges, err := ParsePorts("443,8000-8002,8002-8004")
	if err != nil {
		t.Fatal(err)
	}
	if got := FormatPorts(ranges); got != "443,8000-8004" {
		t.Fatalf("FormatPorts() = %q", got)
	}
	for _, input := range []string{"0", "2-1", "1-2-3", "65536"} {
		if _, err := ParsePorts(input); err == nil {
			t.Errorf("ParsePorts(%q) accepted invalid input", input)
		}
	}
}

func TestCanonicalPrefix(t *testing.T) {
	tests := map[string]string{
		"203.0.113.5":        "203.0.113.5/32",
		"203.0.113.5/24":     "203.0.113.0/24",
		"2001:db8::1":        "2001:db8::1/128",
		"2001:db8::1/64":     "2001:db8::/64",
		"::ffff:203.0.113.1": "203.0.113.1/32",
	}
	for input, want := range tests {
		got, err := CanonicalPrefix(input)
		if err != nil || got != want {
			t.Errorf("CanonicalPrefix(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := CanonicalPrefix("2001:db8::1%eth0"); err == nil {
		t.Error("scoped address accepted")
	}
}

func TestPolicyMatches(t *testing.T) {
	policy := Policy{Ports: []PortRange{{Start: 443, End: 443}}, Match: "either"}
	c := Connection{Local: netip.MustParseAddrPort("192.0.2.1:50000"), Remote: netip.MustParseAddrPort("203.0.113.1:443")}
	if !policy.Matches(c) {
		t.Error("either policy did not match remote port")
	}
}
