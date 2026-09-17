package common

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseBindAddress validates a configured listener address. An empty value
// means all interfaces; any other value must be a literal IP address so a
// typo or hostname can never silently change the exposure.
func ParseBindAddress(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if address := net.ParseIP(trimmed); address == nil {
		return "", fmt.Errorf("gateway bind address %q is not a literal IP", raw)
	}
	return trimmed, nil
}

// ParseLoopbackBindAddress validates a listener address that must stay on
// loopback, such as the management and static listeners.
func ParseLoopbackBindAddress(raw string) (string, error) {
	address, err := ParseBindAddress(raw)
	if err != nil {
		return "", err
	}
	parsed := net.ParseIP(address)
	if parsed == nil || !parsed.IsLoopback() {
		return "", fmt.Errorf("gateway bind address %q is not loopback", raw)
	}
	return address, nil
}

// ParseListenerBinds validates the three configured listener addresses
// before any socket opens. The management and static listeners must stay on
// loopback; the gateway bind may be empty (all interfaces) or a literal IP.
func ParseListenerBinds(getter interface{ GetString(string) string }) (management, static, gateway string, err error) {
	if getter == nil {
		return "", "", "", fmt.Errorf("gateway bind configuration is unavailable")
	}
	if management, err = ParseLoopbackBindAddress(getter.GetString(ConfigKeyManagementBindAddress)); err != nil {
		return "", "", "", err
	}
	if static, err = ParseLoopbackBindAddress(getter.GetString(ConfigKeyStaticBindAddress)); err != nil {
		return "", "", "", err
	}
	if gateway, err = ParseBindAddress(getter.GetString(ConfigKeyGatewayBindAddress)); err != nil {
		return "", "", "", err
	}
	return management, static, gateway, nil
}

// ParsePort validates a configured listener port and returns its canonical
// decimal form.
func ParsePort(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	port, err := strconv.Atoi(trimmed)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("gateway port %q is not an integer from 1 through 65535", raw)
	}
	return strconv.Itoa(port), nil
}

// ParsePort validates a configured listener port and returns its canonical
// decimal form.
