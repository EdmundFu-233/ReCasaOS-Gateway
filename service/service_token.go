package service

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ServiceTokenFilename is the local service credential the gateway publishes
// for in-stack component clients. It is written owner-only (0600) into the
// runtime directory on every start, so only the owning service identity can
// read it. The root service reads the same file to authenticate route and
// port management calls without accepting unauthenticated loopback requests.
const ServiceTokenFilename = "gateway.token"

// ServiceOwner is the route owner identity granted to the local service
// credential. It is deliberately distinct from user JWT owners and from the
// gateway's own self routes, and uses only the owner-name character set the
// route policy accepts.
const ServiceOwner = "service-recasaos-root"

// GenerateServiceToken writes a fresh 256-bit credential to the runtime
// directory and returns it. The destination is replaced atomically so a
// concurrent reader never observes a partial token.
func GenerateServiceToken(runtimePath string) (string, error) {
	if strings.TrimSpace(runtimePath) == "" {
		return "", fmt.Errorf("gateway service token runtime path is empty")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate gateway service token: %w", err)
	}
	token := hex.EncodeToString(raw)
	if err := os.MkdirAll(runtimePath, 0o755); err != nil {
		return "", err
	}
	destination := filepath.Join(runtimePath, ServiceTokenFilename)
	temporary := destination + ".tmp"
	if err := os.WriteFile(temporary, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, destination); err != nil {
		_ = os.Remove(temporary)
		return "", err
	}
	return token, nil
}

// ServiceTokenMatches compares a presented credential with the active token
// in constant time. Empty values and length mismatches never match.
func ServiceTokenMatches(presented, active string) bool {
	presented = strings.TrimSpace(presented)
	active = strings.TrimSpace(active)
	if presented == "" || active == "" || len(presented) != len(active) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(active)) == 1
}
