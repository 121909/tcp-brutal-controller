package controller

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const RulesPath = "/proc/net/tcp_brutal/rules"

type LiveRule struct {
	Prefix  string
	Rate    uint64
	Gain    uint32
	Locked  bool
	ID      uint64
	Members uint64
	Sent    uint64
}

type Snapshot struct {
	Rules  map[string]LiveRule
	Routes map[string]bool
}

func (s Snapshot) Matches(rule Rule) bool {
	live, ok := s.Rules[rule.Prefix]
	return ok && live.Rate == rule.BytesPerSecond() && live.Gain == rule.Gain && live.Locked == !rule.NoLock && s.Routes[rule.Prefix] == !rule.NoRoute
}

type Backend interface {
	Snapshot(context.Context) (Snapshot, error)
	Put(context.Context, Rule) error
	Delete(context.Context, Rule) error
}

type CommandRunner func(context.Context, string, ...string) ([]byte, error)

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	data, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(data)))
	}
	return data, nil
}

type KernelBackend struct {
	Path string
	Run  CommandRunner
}

func NewKernelBackend() *KernelBackend {
	return &KernelBackend{Path: RulesPath, Run: runCommand}
}

func parseLiveRules(r io.Reader) (map[string]LiveRule, error) {
	rules := map[string]LiveRule{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := map[string]string{}
		for _, field := range strings.Fields(line) {
			kv := strings.SplitN(field, "=", 2)
			if len(kv) != 2 {
				return nil, fmt.Errorf("invalid kernel rule field %q", field)
			}
			fields[kv[0]] = kv[1]
		}
		prefix, err := CanonicalPrefix(fields["dst"])
		if err != nil {
			return nil, err
		}
		values := map[string]uint64{}
		for _, name := range []string{"rate", "gain", "lock", "id", "members", "sent"} {
			value, err := strconv.ParseUint(fields[name], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("kernel rule %s: invalid %s", prefix, name)
			}
			values[name] = value
		}
		if values["gain"] > 80 || values["gain"] < 5 || values["lock"] > 1 {
			return nil, fmt.Errorf("kernel rule %s: invalid gain or lock", prefix)
		}
		rules[prefix] = LiveRule{Prefix: prefix, Rate: values["rate"], Gain: uint32(values["gain"]), Locked: values["lock"] == 1, ID: values["id"], Members: values["members"], Sent: values["sent"]}
	}
	return rules, scanner.Err()
}

func (b *KernelBackend) readRules() (map[string]LiveRule, error) {
	f, err := os.Open(b.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("TCP Brutal v2 is not loaded (%s missing); run 'tcpbrutal install' or 'modprobe brutal'", b.Path)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseLiveRules(f)
}

type routeEntry struct {
	Destination string          `json:"dst"`
	Gateway     string          `json:"gateway"`
	Device      string          `json:"dev"`
	Source      string          `json:"prefsrc"`
	Protocol    json.RawMessage `json:"protocol"`
	Table       json.RawMessage `json:"table"`
	Type        string          `json:"type"`
	Metric      uint64          `json:"metric"`
}

func scalar(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

func (b *KernelBackend) routes(ctx context.Context, family string, args ...string) ([]routeEntry, error) {
	// JSON keeps gateways, devices, metrics and protocol IDs unambiguous. The
	// controller never shells out through a command interpreter.
	argv := append([]string{"-j", family, "route"}, args...)
	data, err := b.Run(ctx, "ip", argv...)
	if err != nil {
		return nil, err
	}
	var entries []routeEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode iproute2 JSON: %w", err)
	}
	return entries, nil
}

func familyFor(prefix string) string {
	if strings.Contains(prefix, ":") {
		return "-6"
	}
	return "-4"
}

func (b *KernelBackend) Snapshot(ctx context.Context) (Snapshot, error) {
	rules, err := b.readRules()
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{Rules: rules, Routes: map[string]bool{}}
	for _, family := range []string{"-4", "-6"} {
		entries, err := b.routes(ctx, family, "show", "table", "main", "proto", "233")
		if err != nil {
			return Snapshot{}, err
		}
		for _, route := range entries {
			dst := route.Destination
			if dst == "default" {
				dst = "0.0.0.0/0"
				if family == "-6" {
					dst = "::/0"
				}
			}
			prefix, err := CanonicalPrefix(dst)
			if err != nil {
				return Snapshot{}, err
			}
			snapshot.Routes[prefix] = true
		}
	}
	return snapshot, nil
}

func (b *KernelBackend) write(command string) error {
	f, err := os.OpenFile(b.Path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	data := []byte(command + "\n")
	// The proc interface requires one complete command per write syscall.
	n, err := f.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func (b *KernelBackend) prepareRoute(ctx context.Context, rule Rule) ([]string, error) {
	family := familyFor(rule.Prefix)
	existing, err := b.routes(ctx, family, "show", "table", "main", "exact", rule.Prefix)
	if err != nil {
		return nil, err
	}
	operation := "add"
	for _, entry := range existing {
		if scalar(entry.Protocol) != "233" {
			return nil, fmt.Errorf("%s has an existing route not owned by Brutal; manage routing yourself and use --no-route", rule.Prefix)
		}
		operation = "replace"
	}
	prefix, _ := netip.ParsePrefix(rule.Prefix)
	nextHops, err := b.routes(ctx, family, "get", prefix.Addr().String())
	if err != nil {
		return nil, err
	}
	if len(nextHops) != 1 || nextHops[0].Device == "" {
		return nil, fmt.Errorf("no unambiguous route to %s", rule.Prefix)
	}
	hop := nextHops[0]
	if hop.Type != "" && hop.Type != "unicast" {
		return nil, fmt.Errorf("%s has route type %s; only unicast destinations are supported", rule.Prefix, hop.Type)
	}
	if table := scalar(hop.Table); table != "" && table != "254" && table != "main" {
		return nil, fmt.Errorf("%s uses policy routing table %s; manage routing yourself and use --no-route", rule.Prefix, table)
	}
	args := []string{family, "route", operation, rule.Prefix, "table", "main"}
	if hop.Gateway != "" {
		args = append(args, "via", hop.Gateway)
	}
	args = append(args, "dev", hop.Device)
	if hop.Source != "" {
		args = append(args, "src", hop.Source)
	}
	if len(existing) == 1 && existing[0].Metric != 0 {
		args = append(args, "metric", strconv.FormatUint(existing[0].Metric, 10))
	}
	args = append(args, "congctl")
	if !rule.NoLock {
		args = append(args, "lock")
	}
	return append(args, "brutal", "proto", "233"), nil
}

func (b *KernelBackend) deleteRoute(ctx context.Context, prefix string) error {
	family := familyFor(prefix)
	entries, err := b.routes(ctx, family, "show", "table", "main", "proto", "233", "exact", prefix)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		args := []string{family, "route", "del", prefix, "table", "main", "proto", "233"}
		if entry.Metric != 0 {
			args = append(args, "metric", strconv.FormatUint(entry.Metric, 10))
		}
		if _, err := b.Run(ctx, "ip", args...); err != nil {
			return err
		}
	}
	return nil
}

func (b *KernelBackend) Put(ctx context.Context, rule Rule) error {
	if err := validateRule(rule.Prefix, rule); err != nil {
		return err
	}
	var routeArgs []string
	if !rule.NoRoute {
		var err error
		routeArgs, err = b.prepareRoute(ctx, rule)
		if err != nil {
			return err
		}
	} else if err := b.deleteRoute(ctx, rule.Prefix); err != nil {
		return err
	}
	command := fmt.Sprintf("add %s rate=%d gain=%d", rule.Prefix, rule.BytesPerSecond(), rule.Gain)
	if rule.NoLock {
		command += " nolock"
	}
	if err := b.write(command); err != nil {
		return err
	}
	if len(routeArgs) > 0 {
		if _, err := b.Run(ctx, "ip", routeArgs...); err != nil {
			return fmt.Errorf("kernel rule saved, route still pending: %w", err)
		}
	}
	return nil
}

func (b *KernelBackend) Delete(ctx context.Context, rule Rule) error {
	if err := validateRule(rule.Prefix, rule); err != nil {
		return err
	}
	// Remove routing first so new connections cannot fall back to Brutal's 1 Mbps default.
	if err := b.deleteRoute(ctx, rule.Prefix); err != nil {
		return err
	}
	if err := b.write("del " + rule.Prefix); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
