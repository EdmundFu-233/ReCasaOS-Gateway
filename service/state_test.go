package service

import (
	"testing"

	"gotest.tools/assert"
)

func TestSetGatewayPortValidation(t *testing.T) {
	state := NewState()
	notified := ""
	state.OnGatewayPortChange(func(port string) error {
		notified = port
		return nil
	})

	assert.NilError(t, state.SetGatewayPort("8080"))
	assert.Equal(t, "8080", state.GetGatewayPort())
	assert.Equal(t, "8080", notified)

	assert.NilError(t, state.SetGatewayPort(" 8081 "))
	assert.Equal(t, "8081", state.GetGatewayPort())

	assert.NilError(t, state.SetGatewayPort(""))
	assert.Equal(t, "", state.GetGatewayPort())

	for _, port := range []string{"0", "65536", "-1", "http", "127.0.0.1:8080", "abc"} {
		if err := state.SetGatewayPort(port); err == nil {
			t.Fatalf("SetGatewayPort(%q) unexpectedly accepted", port)
		}
	}
	// A rejected value must not change the stored port.
	assert.Equal(t, "", state.GetGatewayPort())
}
