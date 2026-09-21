package controller

import (
	"strings"
	"testing"
)

func TestParseLiveRules(t *testing.T) {
	rules, err := parseLiveRules(strings.NewReader("dst=203.0.113.5/32 rate=12500000 gain=20 lock=1 id=3 members=2 sent=50000000\n"))
	if err != nil {
		t.Fatal(err)
	}
	rule, ok := rules["203.0.113.5/32"]
	if !ok || rule.Rate != 12500000 || rule.Gain != 20 || !rule.Locked || rule.Members != 2 {
		t.Fatalf("unexpected parsed rule: %#v", rules)
	}
}

func TestSnapshotMatches(t *testing.T) {
	rule := Rule{Prefix: "203.0.113.5/32", Settings: Settings{RateMbps: 100, Gain: 20}}
	snapshot := Snapshot{Rules: map[string]LiveRule{
		rule.Prefix: {Prefix: rule.Prefix, Rate: rule.BytesPerSecond(), Gain: 20, Locked: true},
	}, Routes: map[string]bool{}}
	if snapshot.Matches(rule) {
		t.Error("route-missing rule unexpectedly matched")
	}
	rule.NoRoute = true
	if !snapshot.Matches(rule) {
		t.Error("no-route rule did not match")
	}
}
