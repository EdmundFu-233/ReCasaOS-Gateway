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

// WriteFileAtomic0600 writes data to path atomically through a random,
// exclusively created 0600 temporary file in the same directory, followed
// by a directory sync. A symlinked temporary name cannot be followed and a
// reader never observes a partial file.
func WriteFileAtomic0600(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Errorf("generate temporary file name: %w", err)
	}
	temporary := path + ".tmp-" + hex.EncodeToString(suffix)
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return err
	}
	return nil
}
func GenerateServiceToken(runtimePath string) (string, error) {
	if strings.TrimSpace(runtimePath) == "" {
		return "", fmt.Errorf("gateway service token runtime path is empty")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate gateway service token: %w", err)
	}
	token := hex.EncodeToString(raw)
	destination := filepath.Join(runtimePath, ServiceTokenFilename)
	if err := WriteFileAtomic0600(destination, []byte(token+"\n")); err != nil {
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
