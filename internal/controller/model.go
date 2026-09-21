package controller

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

const DefaultConfig = "/etc/tcpbrutal/state.json"

type PortRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

func ParsePorts(s string) ([]PortRange, error) {
	var ranges []PortRange
	for _, part := range strings.Split(s, ",") {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		start, err := strconv.ParseUint(strings.TrimSpace(bounds[0]), 10, 16)
		if err != nil || start == 0 {
			return nil, fmt.Errorf("invalid port %q: expected 1-65535", bounds[0])
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.ParseUint(strings.TrimSpace(bounds[1]), 10, 16)
			if err != nil || end < start {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		ranges = append(ranges, PortRange{uint16(start), uint16(end)})
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].Start < ranges[j].Start })
	merged := make([]PortRange, 0, len(ranges))
	for _, r := range ranges {
		if len(merged) > 0 && int(r.Start) <= int(merged[len(merged)-1].End)+1 {
			if r.End > merged[len(merged)-1].End {
				merged[len(merged)-1].End = r.End
			}
		} else {
			merged = append(merged, r)
		}
	}
	return merged, nil
}

func FormatPorts(ranges []PortRange) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		s := strconv.Itoa(int(r.Start))
		if r.Start != r.End {
			s += "-" + strconv.Itoa(int(r.End))
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ",")
}

type Settings struct {
	RateMbps float64 `json:"rate_mbps"`
	Gain     uint32  `json:"gain"`
	NoLock   bool    `json:"no_lock,omitempty"`
	NoRoute  bool    `json:"no_route,omitempty"`
}

func (s Settings) Validate() error {
	if math.IsNaN(s.RateMbps) || math.IsInf(s.RateMbps, 0) || s.RateMbps < 0.5 || s.RateMbps > 1000000 {
		return fmt.Errorf("rate must be 0.5-1000000 Mbps (TCP Brutal v2 limits)")
	}
	if s.Gain < 5 || s.Gain > 80 {
		return fmt.Errorf("gain must be 5-80 (20 means 2.0x)")
	}
	return nil
}

func (s Settings) BytesPerSecond() uint64 {
	return uint64(math.Round(s.RateMbps * 125000))
}

type Policy struct {
	ID    int         `json:"id"`
	Ports []PortRange `json:"ports"`
	Match string      `json:"match"`
	Settings
}

func (p Policy) Matches(c Connection) bool {
	for _, r := range p.Ports {
		local := c.Local.Port() >= r.Start && c.Local.Port() <= r.End
		remote := c.Remote.Port() >= r.Start && c.Remote.Port() <= r.End
		if (p.Match == "local" && local) || (p.Match == "remote" && remote) || (p.Match == "either" && (local || remote)) {
			return true
		}
	}
	return false
}

type Rule struct {
	Prefix   string    `json:"prefix"`
	PolicyID int       `json:"policy_id,omitempty"`
	LastSeen time.Time `json:"last_seen,omitempty"`
	Settings
}

type State struct {
	Version        int             `json:"version"`
	NextID         int             `json:"next_id"`
	Policies       []Policy        `json:"policies"`
	Rules          map[string]Rule `json:"rules"`
	PendingDeletes map[string]Rule `json:"pending_deletes"`
	Excluded       []string        `json:"excluded"`
}

func NewState() *State {
	return &State{Version: 1, NextID: 1, Policies: []Policy{}, Rules: map[string]Rule{}, PendingDeletes: map[string]Rule{}, Excluded: []string{}}
}

func CanonicalPrefix(s string) (string, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		addr = addr.Unmap()
		if addr.Zone() != "" {
			return "", fmt.Errorf("scoped addresses are not supported: %s", s)
		}
		return netip.PrefixFrom(addr, addr.BitLen()).String(), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return "", fmt.Errorf("invalid IP or CIDR %q", s)
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return "", fmt.Errorf("IPv4-mapped CIDR must have at least 96 prefix bits")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked().String(), nil
}

func (s *State) Validate() error {
	if s.Version != 1 || s.NextID < 1 {
		return fmt.Errorf("unsupported or invalid state version/next_id")
	}
	ids := map[int]bool{}
	for _, p := range s.Policies {
		if p.ID <= 0 || p.ID >= s.NextID || ids[p.ID] {
			return fmt.Errorf("invalid or duplicate policy ID %d", p.ID)
		}
		ids[p.ID] = true
		if p.Match != "local" && p.Match != "remote" && p.Match != "either" {
			return fmt.Errorf("policy %d: match must be local, remote or either", p.ID)
		}
		if len(p.Ports) == 0 {
			return fmt.Errorf("policy %d has no ports", p.ID)
		}
		for _, r := range p.Ports {
			if r.Start == 0 || r.End < r.Start {
				return fmt.Errorf("policy %d has invalid ports", p.ID)
			}
		}
		if err := p.Settings.Validate(); err != nil {
			return fmt.Errorf("policy %d: %w", p.ID, err)
		}
	}
	for key, rule := range s.Rules {
		if err := validateRule(key, rule); err != nil {
			return err
		}
		if rule.PolicyID != 0 && !ids[rule.PolicyID] {
			return fmt.Errorf("rule %s refers to missing policy %d", key, rule.PolicyID)
		}
		if _, ok := s.PendingDeletes[key]; ok {
			return fmt.Errorf("rule %s is also pending deletion", key)
		}
	}
	for key, rule := range s.PendingDeletes {
		if err := validateRule(key, rule); err != nil {
			return err
		}
	}
	for _, prefix := range s.Excluded {
		canonical, err := CanonicalPrefix(prefix)
		if err != nil || canonical != prefix {
			return fmt.Errorf("invalid exclusion %q", prefix)
		}
	}
	if s.Rules == nil {
		s.Rules = map[string]Rule{}
	}
	if s.PendingDeletes == nil {
		s.PendingDeletes = map[string]Rule{}
	}
	return nil
}

func validateRule(key string, rule Rule) error {
	canonical, err := CanonicalPrefix(key)
	if err != nil || canonical != key || rule.Prefix != key || rule.PolicyID < 0 {
		return fmt.Errorf("invalid stored rule %q", key)
	}
	return rule.Settings.Validate()
}

func (s *State) IsExcluded(addr netip.Addr) bool {
	for _, raw := range s.Excluded {
		p, _ := netip.ParsePrefix(raw)
		if p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
