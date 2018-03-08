package cli

import (
	"net"
	"strings"
	"time"
)

// dialer is a custom gRPC Dialer that understands "unix:/path/to/sock"
// as well as TCP addresses
func dialer(addr string, timeout time.Duration) (net.Conn, error) {
	var network, address string

	parts := strings.Split(addr, ":")
	if len(parts) > 1 && parts[0] == "unix" {
		network = "unix"
		address = parts[1]
	} else {
		network = "tcp"
		address = addr
	}

	return net.DialTimeout(network, address, timeout)
}
