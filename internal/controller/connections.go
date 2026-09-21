package controller

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type Connection struct {
	Local  netip.AddrPort
	Remote netip.AddrPort
}

func nativeEndian() binary.ByteOrder {
	switch runtime.GOARCH {
	case "mips", "mips64", "ppc64", "s390x":
		return binary.BigEndian
	default:
		return binary.LittleEndian
	}
}

func parseEndpoint(raw string, order binary.ByteOrder) (netip.AddrPort, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 || (len(parts[0]) != 8 && len(parts[0]) != 32) || len(parts[1]) != 4 {
		return netip.AddrPort{}, fmt.Errorf("invalid proc TCP endpoint %q", raw)
	}
	addr := make([]byte, len(parts[0])/2)
	// procfs formats each address word in host byte order, including IPv6 words.
	for i := 0; i < len(addr); i += 4 {
		word, err := strconv.ParseUint(parts[0][i*2:i*2+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, err
		}
		order.PutUint32(addr[i:i+4], uint32(word))
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ip, _ := netip.AddrFromSlice(addr)
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
}

func parseConnections(r io.Reader, order binary.ByteOrder) ([]Connection, error) {
	scanner := bufio.NewScanner(r)
	var connections []Connection
	line := 0
	for scanner.Scan() {
		line++
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] == "sl" {
			continue
		}
		if len(fields) < 4 {
			return nil, fmt.Errorf("malformed proc TCP entry at line %d", line)
		}
		if fields[3] != "01" { // TCP_ESTABLISHED
			continue
		}
		local, err := parseEndpoint(fields[1], order)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		remote, err := parseEndpoint(fields[2], order)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		connections = append(connections, Connection{Local: local, Remote: remote})
	}
	return connections, scanner.Err()
}

func ScanConnections(procNet string) ([]Connection, error) {
	localAddresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("read local addresses: %w", err)
	}
	local := map[netip.Addr]bool{}
	for _, addr := range localAddresses {
		if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
			local[prefix.Addr().Unmap()] = true
		}
	}
	var result []Connection
	for _, name := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(procNet, name))
		if name == "tcp6" && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		connections, err := parseConnections(f, nativeEndian())
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for _, c := range connections {
			ip := c.Remote.Addr()
			if !ip.IsGlobalUnicast() || local[ip] || c.Remote.Port() == 0 {
				continue
			}
			result = append(result, c)
		}
	}
	return result, nil
}
