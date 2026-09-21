package controller

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type Manager struct {
	Store   Store
	Backend Backend
	Scan    func() ([]Connection, error)
	Log     func(string, ...interface{})
}

func (m *Manager) log(format string, args ...interface{}) {
	if m.Log != nil {
		m.Log(format, args...)
	}
}

func (m *Manager) AddPolicy(ctx context.Context, policy Policy) (int, error) {
	var id int
	err := m.Store.Update(ctx, func(s *State) error {
		id = s.NextID
		s.NextID++
		policy.ID = id
		s.Policies = append(s.Policies, policy)
		return nil
	})
	return id, err
}

func (m *Manager) DeletePolicy(ctx context.Context, id int) error {
	return m.Store.Update(ctx, func(s *State) error {
		found := false
		for i, policy := range s.Policies {
			if policy.ID == id {
				s.Policies = append(s.Policies[:i], s.Policies[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("watch policy %d not found", id)
		}
		for key, rule := range s.Rules {
			if rule.PolicyID == id {
				s.PendingDeletes[key] = rule
				delete(s.Rules, key)
			}
		}
		return nil
	})
}

func (m *Manager) AddRule(ctx context.Context, rule Rule) error {
	prefix, err := CanonicalPrefix(rule.Prefix)
	if err != nil {
		return err
	}
	rule.Prefix = prefix
	rule.PolicyID = 0
	return m.Store.Update(ctx, func(s *State) error {
		s.Rules[prefix] = rule
		delete(s.PendingDeletes, prefix)
		removeExclusion(s, prefix)
		return nil
	})
}

func (m *Manager) DeleteRule(ctx context.Context, raw string) error {
	prefix, err := CanonicalPrefix(raw)
	if err != nil {
		return err
	}
	return m.Store.Update(ctx, func(s *State) error {
		rule, ok := s.Rules[prefix]
		if !ok {
			if _, pending := s.PendingDeletes[prefix]; !pending {
				return fmt.Errorf("%s is not managed by this controller", prefix)
			}
		} else {
			s.PendingDeletes[prefix] = rule
			delete(s.Rules, prefix)
		}
		addExclusion(s, prefix)
		return nil
	})
}

func addExclusion(s *State, prefix string) {
	for _, current := range s.Excluded {
		if current == prefix {
			return
		}
	}
	s.Excluded = append(s.Excluded, prefix)
	sort.Strings(s.Excluded)
}

func removeExclusion(s *State, prefix string) bool {
	for i, current := range s.Excluded {
		if current == prefix {
			s.Excluded = append(s.Excluded[:i], s.Excluded[i+1:]...)
			return true
		}
	}
	return false
}

func (m *Manager) Exclude(ctx context.Context, raw string, remove bool) error {
	prefix, err := CanonicalPrefix(raw)
	if err != nil {
		return err
	}
	return m.Store.Update(ctx, func(s *State) error {
		if remove {
			if !removeExclusion(s, prefix) {
				return fmt.Errorf("exclusion %s not found", prefix)
			}
			return nil
		}
		addExclusion(s, prefix)
		p, _ := netip.ParsePrefix(prefix)
		for key, rule := range s.Rules {
			ip, _ := netip.ParsePrefix(key)
			if rule.PolicyID != 0 && p.Contains(ip.Addr()) {
				s.PendingDeletes[key] = rule
				delete(s.Rules, key)
			}
		}
		return nil
	})
}

func discover(s *State, connections []Connection, live Snapshot, now time.Time) {
	candidates := map[string]Policy{}
	for _, c := range connections {
		ip := c.Remote.Addr().Unmap()
		if !ip.IsGlobalUnicast() || s.IsExcluded(ip) {
			continue
		}
		prefix := netip.PrefixFrom(ip, ip.BitLen()).String()
		if _, pending := s.PendingDeletes[prefix]; pending {
			continue
		}
		covered := false
		for key, rule := range s.Rules {
			p, _ := netip.ParsePrefix(key)
			if rule.PolicyID == 0 && p.Contains(ip) {
				covered = true
				break
			}
		}
		for key := range live.Rules {
			p, _ := netip.ParsePrefix(key)
			if _, owned := s.Rules[key]; !owned && p.Contains(ip) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		for _, policy := range s.Policies {
			if !policy.Matches(c) {
				continue
			}
			current, ok := candidates[prefix]
			if !ok || policy.RateMbps < current.RateMbps || (policy.RateMbps == current.RateMbps && policy.ID < current.ID) {
				candidates[prefix] = policy
			}
		}
	}
	for prefix, policy := range candidates {
		s.Rules[prefix] = Rule{Prefix: prefix, PolicyID: policy.ID, LastSeen: now, Settings: policy.Settings}
	}
}

func (m *Manager) Sync(ctx context.Context, scan bool) error {
	lock, err := m.Store.Lock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	s, err := m.Store.Load()
	if err != nil {
		return err
	}
	live, err := m.Backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	if scan && len(s.Policies) > 0 {
		connections, err := m.Scan()
		if err != nil {
			return err
		}
		discover(s, connections, live, time.Now().UTC())
		// Persist ownership before any kernel mutation, including partially failed adds.
		if err := m.Store.Save(s); err != nil {
			return err
		}
	}
	var failures []string
	for _, prefix := range sortedKeys(s.PendingDeletes) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.Backend.Delete(ctx, s.PendingDeletes[prefix]); err != nil {
			failures = append(failures, fmt.Sprintf("delete %s: %v", prefix, err))
			continue
		}
		delete(s.PendingDeletes, prefix)
		if err := m.Store.Save(s); err != nil {
			return err
		}
		m.log("deleted %s", prefix)
	}
	for _, prefix := range sortedKeys(s.Rules) {
		if err := ctx.Err(); err != nil {
			return err
		}
		rule := s.Rules[prefix]
		if live.Matches(rule) {
			continue
		}
		if err := m.Backend.Put(ctx, rule); err != nil {
			failures = append(failures, fmt.Sprintf("apply %s: %v", prefix, err))
			continue
		}
		m.log("applied %s at %g Mbps", prefix, rule.RateMbps)
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s (saved state will be retried on the next sync)", strings.Join(failures, "; "))
	}
	return nil
}

func (m *Manager) Watch(ctx context.Context, interval time.Duration, once bool) error {
	if interval < 100*time.Millisecond {
		return fmt.Errorf("interval must be at least 100ms")
	}
	lock, err := acquireLock(ctx, m.Store.Path+".daemon.lock", false)
	if err != nil {
		return err
	}
	defer lock.Close()
	if once {
		return m.Sync(ctx, true)
	}
	m.log("watching every %s; config=%s", interval, m.Store.Path)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := m.Sync(ctx, true); err != nil && ctx.Err() == nil {
			m.log("sync failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
