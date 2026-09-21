package controller

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const serviceName = "tcpbrutal.service"
const servicePath = "/etc/systemd/system/" + serviceName
const serviceBinary = "/usr/local/bin/tcpbrutal"
const serviceMarker = "# Managed by tcpbrutal-controller\n"

func systemdQuote(value string) (string, error) {
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("systemd paths must not contain NUL or newlines")
	}
	escaped := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "%", "%%", "$", "$$").Replace(value)
	return "\"" + escaped + "\"", nil
}

func serviceUnit(config string, interval time.Duration) (string, error) {
	quoted, err := systemdQuote(config)
	if err != nil {
		return "", err
	}
	return serviceMarker + fmt.Sprintf(`[Unit]
Description=TCP Brutal port watcher
Wants=network-online.target
After=network-online.target systemd-modules-load.service

[Service]
Type=simple
User=root
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=%s --config %s run --interval %s
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`, serviceBinary, quoted, interval), nil
}

func InstallService(ctx context.Context, store Store, interval time.Duration, out, errOut io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if interval < 100*time.Millisecond {
		return fmt.Errorf("interval must be at least 100ms")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemd is required for service commands: %w", err)
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return fmt.Errorf("systemd is not running; use 'tcpbrutal run' under your service supervisor")
	}
	if _, err := NewKernelBackend().Snapshot(ctx); err != nil {
		return err
	}
	if data, err := os.ReadFile(servicePath); err == nil {
		if !strings.HasPrefix(string(data), serviceMarker) {
			return fmt.Errorf("%s already exists and was not created by this controller", servicePath)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	config, err := filepath.Abs(store.Path)
	if err != nil {
		return err
	}
	unit, err := serviceUnit(config, interval)
	if err != nil {
		return err
	}
	if err := store.Update(ctx, func(*State) error { return nil }); err != nil {
		return err
	}
	source, err := os.Executable()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(serviceBinary), 0755); err != nil {
		return err
	}
	if err := atomicWrite(serviceBinary, data, 0755); err != nil {
		return err
	}
	if err := atomicWrite(servicePath, []byte(unit), 0644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", serviceName}, {"restart", serviceName}} {
		if err := streamCommand(ctx, out, errOut, "systemctl", args...); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "Installed and started", serviceName)
	return nil
}

func ServiceAction(ctx context.Context, action string, out, errOut io.Writer) error {
	if action != "status" {
		if err := requireRoot(); err != nil {
			return err
		}
	}
	switch action {
	case "status":
		return streamCommand(ctx, out, errOut, "systemctl", "--no-pager", "--full", "status", serviceName)
	case "start", "stop", "restart":
		return streamCommand(ctx, out, errOut, "systemctl", action, serviceName)
	case "uninstall":
		data, err := os.ReadFile(servicePath)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(string(data), serviceMarker) {
			return fmt.Errorf("%s is not managed by this controller", servicePath)
		}
		if err := streamCommand(ctx, out, errOut, "systemctl", "disable", "--now", serviceName); err != nil {
			return err
		}
		if err := os.Remove(servicePath); err != nil {
			return err
		}
		if err := streamCommand(ctx, out, errOut, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		fmt.Fprintln(out, "Service removed. Saved rules, kernel rules and the binary are retained.")
		return nil
	default:
		return fmt.Errorf("unknown service action %q", action)
	}
}
