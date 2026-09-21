package controller

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseConnections(t *testing.T) {
	data := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   1: 0100007F:1F90 010000CB:01BB 01 00000000:00000000 00:00000000 00000000   100        0 1 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1F90 010000CB:01BB 0A 00000000:00000000 00:00000000 00000000   100        0 2 1 0000000000000000 100 0 0 10 0
`
	connections, err := parseConnections(strings.NewReader(data), binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	if len(connections) != 1 || connections[0].Local.String() != "127.0.0.1:8080" || connections[0].Remote.String() != "203.0.0.1:443" {
		t.Fatalf("unexpected connections: %#v", connections)
	}
}

func TestParseIPv6Endpoint(t *testing.T) {
	endpoint, err := parseEndpoint("00000000000000000000000001000020:01BB", binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Port() != 443 || !endpoint.Addr().Is6() {
		t.Fatalf("unexpected IPv6 endpoint %s", endpoint)
	}
}
