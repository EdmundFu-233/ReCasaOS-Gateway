package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gotest.tools/assert"
)

func TestGenerateServiceTokenIsOwnerOnlyAndAtomic(t *testing.T) {
	runtimePath := t.TempDir()

	token, err := GenerateServiceToken(runtimePath)
	assert.NilError(t, err)
	assert.Equal(t, 64, len(token))

	tokenPath := filepath.Join(runtimePath, ServiceTokenFilename)
	info, err := os.Stat(tokenPath)
	assert.NilError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	content, err := os.ReadFile(tokenPath)
	assert.NilError(t, err)
	assert.Equal(t, token, strings.TrimSpace(string(content)))

	if _, err := os.Stat(tokenPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary service token file was not replaced")
	}

	second, err := GenerateServiceToken(runtimePath)
	assert.NilError(t, err)
	assert.Assert(t, second != token)
}

func TestGenerateServiceTokenRequiresRuntimePath(t *testing.T) {
	if _, err := GenerateServiceToken(""); err == nil {
		t.Fatal("empty runtime path was accepted")
	}
}

func TestServiceTokenMatchesIsStrict(t *testing.T) {
	token := "a" + strings.Repeat("b", 63)

	assert.Assert(t, ServiceTokenMatches(token, token))
	assert.Assert(t, ServiceTokenMatches(token+"\n", token))
	assert.Assert(t, !ServiceTokenMatches("", token))
	assert.Assert(t, !ServiceTokenMatches(token, ""))
	assert.Assert(t, !ServiceTokenMatches(token[:63], token))
	assert.Assert(t, !ServiceTokenMatches(strings.Repeat("c", 64), token))
	assert.Assert(t, !ServiceTokenMatches(token, strings.Repeat("c", 64)))
}
