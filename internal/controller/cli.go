package controller

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

var Version = "dev"

const help = `tcpbrutal - TCP Brutal v2 controller

Usage: tcpbrutal [--config PATH] COMMAND

  install [--version v2.0.0]                 Install the official DKMS module
  status                                    Show module and controller status
  watch add --ports 443,8000-8100 --rate 100  Add a port watch policy
  watch list [--json]                        List port watch policies
  watch delete ID                           Delete a policy and its learned rules
  rules add --rate 100 IP[/PREFIX]           Add or update a persistent manual rule
  rules list [--json]                        List saved and live rules
  rules delete IP[/PREFIX]                   Delete a rule and exclude rediscovery
  exclude add IP[/PREFIX]                    Exclude peers from discovery
  exclude delete IP[/PREFIX]                 Allow discovery again
  exclude list [--json]                      List exclusions
  run [--interval 2s] [--once]               Discover peers and reconcile rules
  service install [--interval 2s]            Install, enable and start systemd service
  service start|stop|restart|status|uninstall Manage the systemd service

Watch and manual rule options: --rate Mbps --gain 20 --no-lock --no-route
Watch matching: --match local (default), remote, or either.
Put global flags before COMMAND and command flags before positional arguments.
Rules cover all TCP ports of the peer; only newly established connections join.
`

type settingsFlags struct {
	rate    *float64
	gain    *uint
	noLock  *bool
	noRoute *bool
}

func bindSettings(fs *flag.FlagSet) settingsFlags {
	return settingsFlags{
		rate:    fs.Float64("rate", 0, "shared rate per destination IP in Mbps (required)"),
		gain:    fs.Uint("gain", 20, "congestion window gain in tenths (5-80)"),
		noLock:  fs.Bool("no-lock", false, "allow applications to override Brutal parameters"),
		noRoute: fs.Bool("no-route", false, "manage congestion-control routes yourself"),
	}
}

func (f settingsFlags) settings() (Settings, error) {
	if *f.gain < 5 || *f.gain > 80 {
		return Settings{}, fmt.Errorf("gain must be 5-80")
	}
	s := Settings{RateMbps: *f.rate, Gain: uint32(*f.gain), NoLock: *f.noLock, NoRoute: *f.noRoute}
	return s, s.Validate()
}

func flags(name string, errOut io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	return fs
}

func parse(fs *flag.FlagSet, args []string, positional int) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != positional {
		return fmt.Errorf("%s expects %d positional argument(s); put options before them (see --help)", fs.Name(), positional)
	}
	return nil
}

func RunCLI(ctx context.Context, args []string, out, errOut io.Writer) error {
	err := runCLI(ctx, args, out, errOut)
	if errors.Is(err, flag.ErrHelp) || (errors.Is(err, context.Canceled) && ctx.Err() != nil) {
		return nil
	}
	return err
}

func runCLI(ctx context.Context, args []string, out, errOut io.Writer) error {
	global := flags("tcpbrutal", errOut)
	config := global.String("config", DefaultConfig, "persistent controller state file")
	version := global.Bool("version", false, "print controller version")
	global.Usage = func() { fmt.Fprint(out, help) }
	if err := global.Parse(args); err != nil {
		return err
	}
	if *version {
		fmt.Fprintln(out, "tcpbrutal", Version)
		return nil
	}
	args = global.Args()
	if len(args) == 0 || args[0] == "help" {
		fmt.Fprint(out, help)
		return nil
	}
	if strings.TrimSpace(*config) == "" {
		return fmt.Errorf("config path must not be empty")
	}
	path, err := filepath.Abs(*config)
	if err != nil {
		return err
	}
	m := &Manager{
		Store: Store{Path: path}, Backend: NewKernelBackend(),
		Scan: func() ([]Connection, error) { return ScanConnections("/proc/net") },
		Log:  func(format string, a ...interface{}) { fmt.Fprintf(errOut, format+"\n", a...) },
	}
	switch args[0] {
	case "install":
		fs := flags("install", errOut)
		version := fs.String("version", "", "module release, e.g. v2.0.0 (default: latest)")
		if err := parse(fs, args[1:], 0); err != nil {
			return err
		}
		return Install(ctx, *version, out, errOut)
	case "status":
		if err := parse(flags("status", errOut), args[1:], 0); err != nil {
			return err
		}
		return showStatus(ctx, m, out)
	case "watch":
		return watchCLI(ctx, m, args[1:], out, errOut)
	case "rules":
		return rulesCLI(ctx, m, args[1:], out, errOut)
	case "exclude":
		return excludeCLI(ctx, m, args[1:], out, errOut)
	case "run":
		fs := flags("run", errOut)
		interval := fs.Duration("interval", 2*time.Second, "polling interval (minimum 100ms)")
		once := fs.Bool("once", false, "scan and reconcile once, then exit")
		if err := parse(fs, args[1:], 0); err != nil {
			return err
		}
		if err := requireRoot(); err != nil {
			return err
		}
		return m.Watch(ctx, *interval, *once)
	case "service":
		if len(args) < 2 {
			return fmt.Errorf("usage: service install|start|stop|restart|status|uninstall")
		}
		fs := flags("service "+args[1], errOut)
		if args[1] == "install" {
			interval := fs.Duration("interval", 2*time.Second, "polling interval")
			if err := parse(fs, args[2:], 0); err != nil {
				return err
			}
			return InstallService(ctx, m.Store, *interval, out, errOut)
		}
		if err := parse(fs, args[2:], 0); err != nil {
			return err
		}
		return ServiceAction(ctx, args[1], out, errOut)
	default:
		return fmt.Errorf("unknown command %q; run 'tcpbrutal --help'", args[0])
	}
}

func watchCLI(ctx context.Context, m *Manager, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: watch add|list|delete")
	}
	fs := flags("watch "+args[0], errOut)
	switch args[0] {
	case "add":
		ports := fs.String("ports", "", "ports or ranges, e.g. 443,8000-8100")
		match := fs.String("match", "local", "port to match: local, remote or either")
		settings := bindSettings(fs)
		if err := parse(fs, args[1:], 0); err != nil {
			return err
		}
		ranges, err := ParsePorts(*ports)
		if err != nil {
			return err
		}
		s, err := settings.settings()
		if err != nil {
			return err
		}
		id, err := m.AddPolicy(ctx, Policy{Ports: ranges, Match: *match, Settings: s})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Watch %d saved: %s ports %s, %g Mbps per peer.\n", id, *match, FormatPorts(ranges), s.RateMbps)
		return nil
	case "list":
		asJSON := fs.Bool("json", false, "output JSON")
		if err := parse(fs, args[1:], 0); err != nil {
			return err
		}
		s, err := m.Store.Load()
		if err != nil {
			return err
		}
		if *asJSON {
			return writeJSON(out, s.Policies)
		}
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tMATCH\tPORTS\tRATE(Mbps)\tGAIN\tLOCK\tAUTO-ROUTE")
		for _, p := range s.Policies {
			fmt.Fprintf(w, "%d\t%s\t%s\t%g\t%d\t%t\t%t\n", p.ID, p.Match, FormatPorts(p.Ports), p.RateMbps, p.Gain, !p.NoLock, !p.NoRoute)
		}
		return w.Flush()
	case "delete":
		if err := parse(fs, args[1:], 1); err != nil {
			return err
		}
		id, err := strconv.Atoi(fs.Arg(0))
		if err != nil || id < 1 {
			return fmt.Errorf("watch ID must be a positive integer")
		}
		if err := requireRoot(); err != nil {
			return err
		}
		if err := m.DeletePolicy(ctx, id); err != nil {
			return err
		}
		fmt.Fprintf(out, "Watch %d removed from saved state.\n", id)
		return syncSaved(ctx, m)
	default:
		return fmt.Errorf("unknown watch action %q", args[0])
	}
}

func rulesCLI(ctx context.Context, m *Manager, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: rules add|list|delete")
	}
	fs := flags("rules "+args[0], errOut)
	switch args[0] {
	case "list":
		asJSON := fs.Bool("json", false, "output JSON")
		if err := parse(fs, args[1:], 0); err != nil {
			return err
		}
		return showRules(ctx, m, *asJSON, out, errOut)
	case "add":
		settings := bindSettings(fs)
		if err := parse(fs, args[1:], 1); err != nil {
			return err
		}
		s, err := settings.settings()
		if err != nil {
			return err
		}
		if err := requireRoot(); err != nil {
			return err
		}
		if err := m.AddRule(ctx, Rule{Prefix: fs.Arg(0), Settings: s}); err != nil {
			return err
		}
		fmt.Fprintln(out, "Manual rule saved.")
		return syncSaved(ctx, m)
	case "delete":
		if err := parse(fs, args[1:], 1); err != nil {
			return err
		}
		if err := requireRoot(); err != nil {
			return err
		}
		if err := m.DeleteRule(ctx, fs.Arg(0)); err != nil {
			return err
		}
		fmt.Fprintln(out, "Deletion saved; automatic rediscovery is excluded for this prefix.")
		return syncSaved(ctx, m)
	default:
		return fmt.Errorf("unknown rules action %q", args[0])
	}
}

func excludeCLI(ctx context.Context, m *Manager, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: exclude add|delete|list")
	}
	fs := flags("exclude "+args[0], errOut)
	if args[0] == "list" {
		asJSON := fs.Bool("json", false, "output JSON")
		if err := parse(fs, args[1:], 0); err != nil {
			return err
		}
		s, err := m.Store.Load()
		if err != nil {
			return err
		}
		if *asJSON {
			return writeJSON(out, s.Excluded)
		}
		for _, prefix := range s.Excluded {
			fmt.Fprintln(out, prefix)
		}
		return nil
	}
	if args[0] != "add" && args[0] != "delete" {
		return fmt.Errorf("unknown exclude action %q", args[0])
	}
	if err := parse(fs, args[1:], 1); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if err := m.Exclude(ctx, fs.Arg(0), args[0] == "delete"); err != nil {
		return err
	}
	fmt.Fprintln(out, "Exclusions saved.")
	if args[0] == "add" {
		return syncSaved(ctx, m)
	}
	return nil
}

func syncSaved(ctx context.Context, m *Manager) error {
	if err := m.Sync(ctx, false); err != nil {
		return fmt.Errorf("configuration saved; kernel synchronization incomplete: %w", err)
	}
	return nil
}

func writeJSON(out io.Writer, value interface{}) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

type ruleView struct {
	Rule
	Source   string    `json:"source"`
	Status   string    `json:"status"`
	Route    bool      `json:"route"`
	LiveRate float64   `json:"live_rate_mbps"`
	Members  uint64    `json:"members"`
	Sent     uint64    `json:"sent_bytes"`
	Live     *LiveRule `json:"live,omitempty"`
}

func showRules(ctx context.Context, m *Manager, asJSON bool, out, errOut io.Writer) error {
	s, err := m.Store.Load()
	if err != nil {
		return err
	}
	live, liveErr := m.Backend.Snapshot(ctx)
	report := struct {
		Rules       []ruleView `json:"rules"`
		Excluded    []string   `json:"excluded"`
		KernelError string     `json:"kernel_error,omitempty"`
	}{Rules: []ruleView{}, Excluded: s.Excluded}
	if liveErr != nil {
		report.KernelError = liveErr.Error()
		fmt.Fprintln(errOut, "Kernel state unavailable:", liveErr)
	}
	all := map[string]Rule{}
	for key, rule := range s.Rules {
		all[key] = rule
	}
	for key, rule := range s.PendingDeletes {
		all[key] = rule
	}
	for key, rule := range live.Rules {
		if _, ok := all[key]; !ok {
			all[key] = Rule{Prefix: key, Settings: Settings{RateMbps: float64(rule.Rate) / 125000, Gain: rule.Gain, NoLock: !rule.Locked}}
		}
	}
	for _, key := range sortedKeys(all) {
		rule := all[key]
		view := ruleView{Rule: rule, Source: "manual", Status: "pending", Route: live.Routes[key]}
		if rule.PolicyID != 0 {
			view.Source = fmt.Sprintf("watch:%d", rule.PolicyID)
		}
		if current, ok := live.Rules[key]; ok {
			view.LiveRate, view.Members, view.Sent = float64(current.Rate)/125000, current.Members, current.Sent
			view.Live = &current
		}
		if _, managed := s.Rules[key]; !managed {
			view.Source, view.Status = "external", "external"
		}
		if liveErr != nil {
			view.Status = "unverified"
		} else if live.Matches(rule) {
			if _, managed := s.Rules[key]; managed {
				view.Status = "active"
				if rule.NoRoute {
					view.Status = "manual-route"
				}
			}
		}
		if _, pending := s.PendingDeletes[key]; pending {
			view.Source, view.Status = "deletion", "pending-delete"
		}
		report.Rules = append(report.Rules, view)
	}
	if asJSON {
		return writeJSON(out, report)
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "DESTINATION\tRATE(Mbps)\tLIVE(Mbps)\tSOURCE\tSTATUS\tROUTE\tMEMBERS\tSENT(MB)")
	for _, r := range report.Rules {
		fmt.Fprintf(w, "%s\t%g\t%g\t%s\t%s\t%t\t%d\t%.2f\n", r.Prefix, r.RateMbps, r.LiveRate, r.Source, r.Status, r.Route, r.Members, float64(r.Sent)/1e6)
	}
	return w.Flush()
}

func showStatus(ctx context.Context, m *Manager, out io.Writer) error {
	s, err := m.Store.Load()
	if err != nil {
		return err
	}
	version := "not loaded"
	if data, err := os.ReadFile("/sys/module/brutal/version"); err == nil {
		version = strings.TrimSpace(string(data))
	}
	fmt.Fprintf(out, "Module: %s\nConfig: %s\nWatch policies: %d\nManaged rules: %d\nPending deletions: %d\nExclusions: %d\n", version, m.Store.Path, len(s.Policies), len(s.Rules), len(s.PendingDeletes), len(s.Excluded))
	snapshot, err := m.Backend.Snapshot(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Kernel rules: %d\nBrutal routes: %d\n", len(snapshot.Rules), len(snapshot.Routes))
	return nil
}
