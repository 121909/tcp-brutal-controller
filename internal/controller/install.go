package controller

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const installerURL = "https://tcp.hy2.sh/"
const maxInstallerSize = 2 * 1024 * 1024

func requireRoot() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("TCP Brutal requires Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root; run it with sudo")
	}
	return nil
}

func checkKernel(release string) error {
	parts := strings.SplitN(strings.TrimSpace(release), ".", 3)
	if len(parts) < 2 {
		return fmt.Errorf("unrecognized kernel version %q", release)
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || major < 5 || (major == 5 && minor < 10) {
		return fmt.Errorf("TCP Brutal v2 requires Linux 5.10 or later (running %s)", strings.TrimSpace(release))
	}
	return nil
}

func normalizeVersion(version string) (string, error) {
	if version == "" {
		return "", nil
	}
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("version must be vMAJOR.MINOR.PATCH, for example v2.0.0")
	}
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil || (i == 0 && n < 2) {
			return "", fmt.Errorf("version must be a stable TCP Brutal release >= v2.0.0")
		}
	}
	return "v" + strings.Join(parts, "."), nil
}

func downloadInstaller(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tcpbrutal-controller/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download official installer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download official installer: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxInstallerSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxInstallerSize {
		return nil, fmt.Errorf("installer exceeds %d bytes", maxInstallerSize)
	}
	if !bytes.HasPrefix(data, []byte("#!")) {
		return nil, fmt.Errorf("official installer response is not a shell script")
	}
	return data, nil
}

func streamCommand(ctx context.Context, out, errOut io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, out, errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func ensureIPRoute(ctx context.Context, out, errOut io.Writer) error {
	if _, err := exec.LookPath("ip"); err == nil {
		return nil
	}
	packages := []struct {
		manager string
		args    []string
	}{
		{"apt-get", []string{"install", "-y", "--no-install-recommends", "iproute2"}},
		{"dnf", []string{"install", "-y", "iproute"}},
		{"yum", []string{"install", "-y", "iproute"}},
		{"pacman", []string{"-S", "--needed", "--noconfirm", "iproute2"}},
		{"zypper", []string{"--non-interactive", "install", "iproute2"}},
	}
	for _, pkg := range packages {
		if _, err := exec.LookPath(pkg.manager); err != nil {
			continue
		}
		fmt.Fprintln(out, "Installing iproute2...")
		if pkg.manager == "apt-get" {
			if err := streamCommand(ctx, out, errOut, "apt-get", "update"); err != nil {
				return err
			}
		}
		return streamCommand(ctx, out, errOut, pkg.manager, pkg.args...)
	}
	return fmt.Errorf("iproute2 is required; install the 'ip' command with your package manager")
}

func Install(ctx context.Context, version string, out, errOut io.Writer) error {
	if err := requireRoot(); err != nil {
		return err
	}
	version, err := normalizeVersion(version)
	if err != nil {
		return err
	}
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return err
	}
	if err := checkKernel(string(release)); err != nil {
		return err
	}
	if _, err := exec.LookPath("bash"); err != nil {
		return fmt.Errorf("bash is required to run the official installer: %w", err)
	}
	client := &http.Client{
		Timeout: 90 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || len(via) >= 5 {
				return fmt.Errorf("refusing insecure or excessive installer redirects")
			}
			return nil
		},
	}
	fmt.Fprintln(out, "Downloading official TCP Brutal installer from", installerURL)
	data, err := downloadInstaller(ctx, client, installerURL)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "tcpbrutal-install-*.sh")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ensureIPRoute(ctx, out, errOut); err != nil {
		return err
	}
	args := []string{f.Name(), "install"}
	if version != "" {
		args = append(args, "--version", version)
	}
	if err := streamCommand(ctx, out, errOut, "bash", args...); err != nil {
		return err
	}
	if _, err := NewKernelBackend().Snapshot(ctx); err != nil {
		return fmt.Errorf("installer finished, but v2 readiness check failed: %w", err)
	}
	fmt.Fprintln(out, "TCP Brutal v2 rule interface and iproute2 are ready.")
	return nil
}
