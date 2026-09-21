package controller

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

type fakeBackend struct {
	snapshot Snapshot
	puts     []Rule
	deletes  []Rule
}

func (b *fakeBackend) Snapshot(context.Context) (Snapshot, error) { return b.snapshot, nil }
func (b *fakeBackend) Put(_ context.Context, rule Rule) error {
	b.puts = append(b.puts, rule)
	return nil
}
func (b *fakeBackend) Delete(_ context.Context, rule Rule) error {
	b.deletes = append(b.deletes, rule)
	return nil
}

func TestDiscoverChoosesMatchingPolicy(t *testing.T) {
	state := NewState()
	state.Policies = []Policy{
		{ID: 1, Ports: []PortRange{{Start: 443, End: 443}}, Match: "remote", Settings: Settings{RateMbps: 100, Gain: 20}},
		{ID: 2, Ports: []PortRange{{Start: 443, End: 443}}, Match: "remote", Settings: Settings{RateMbps: 50, Gain: 20}},
	}
	connection := Connection{Local: netip.MustParseAddrPort("192.0.2.1:50000"), Remote: netip.MustParseAddrPort("203.0.113.1:443")}
	discover(state, []Connection{connection}, Snapshot{Rules: map[string]LiveRule{}, Routes: map[string]bool{}}, connectionTime())
	rule, ok := state.Rules["203.0.113.1/32"]
	if !ok || rule.PolicyID != 2 || rule.RateMbps != 50 {
		t.Fatalf("unexpected discovered rule: %#v", state.Rules)
	}
}

func connectionTime() (t time.Time) { return time.Unix(0, 0).UTC() }
