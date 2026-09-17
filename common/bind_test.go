package common

import (
	"net"
	"testing"
)

func TestParseBindAddress(t *testing.T) {
	for _, test := range []struct {
		raw   string
		want  string
		fails bool
	}{
		{raw: "", want: ""},
		{raw: "  ", want: ""},
		{raw: "127.0.0.1", want: "127.0.0.1"},
		{raw: "::1", want: "::1"},
		{raw: "0.0.0.0", want: "0.0.0.0"},
		{raw: "192.168.1.10", want: "192.168.1.10"},
		{raw: "localhost", fails: true},
		{raw: "example.com", fails: true},
		{raw: "999.1.1.1", fails: true},
		{raw: "127.0.0.1:8080", fails: true},
	} {
		got, err := ParseBindAddress(test.raw)
		if test.fails {
			if err == nil {
				t.Fatalf("ParseBindAddress(%q) unexpectedly accepted", test.raw)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseBindAddress(%q): %v", test.raw, err)
		}
		if got != test.want {
			t.Fatalf("ParseBindAddress(%q) = %q, want %q", test.raw, got, test.want)
		}
	}
}

func TestParseLoopbackBindAddress(t *testing.T) {
	for _, test := range []struct {
		raw   string
		want  string
		fails bool
	}{
		{raw: "127.0.0.1", want: "127.0.0.1"},
		{raw: "::1", want: "::1"},
		{raw: "127.0.0.2", want: "127.0.0.2"},
		{raw: "", fails: true},
		{raw: "0.0.0.0", fails: true},
		{raw: "::", fails: true},
		{raw: "192.168.1.10", fails: true},
		{raw: "localhost", fails: true},
	} {
		got, err := ParseLoopbackBindAddress(test.raw)
		if test.fails {
			if err == nil {
				t.Fatalf("ParseLoopbackBindAddress(%q) unexpectedly accepted", test.raw)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseLoopbackBindAddress(%q): %v", test.raw, err)
		}
		if got != test.want {
			t.Fatalf("ParseLoopbackBindAddress(%q) = %q, want %q", test.raw, got, test.want)
		}
		if address := net.ParseIP(got); address == nil || !address.IsLoopback() {
			t.Fatalf("ParseLoopbackBindAddress(%q) = %q is not loopback", test.raw, got)
		}
	}
}

func TestParsePort(t *testing.T) {
	for _, test := range []struct {
		raw   string
		want  string
		fails bool
	}{
		{raw: "8080", want: "8080"},
		{raw: " 80 ", want: "80"},
		{raw: "08080", want: "8080"},
		{raw: "", fails: true},
		{raw: "0", fails: true},
		{raw: "65536", fails: true},
		{raw: "-1", fails: true},
		{raw: "http", fails: true},
		{raw: "127.0.0.1:8080", fails: true},
	} {
		got, err := ParsePort(test.raw)
		if test.fails {
			if err == nil {
				t.Fatalf("ParsePort(%q) unexpectedly accepted", test.raw)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParsePort(%q): %v", test.raw, err)
		}
		if got != test.want {
			t.Fatalf("ParsePort(%q) = %q, want %q", test.raw, got, test.want)
		}
	}
}

type mapBindConfig map[string]string

func (config mapBindConfig) GetString(key string) string {
	return config[key]
}

func TestParseListenerBinds(t *testing.T) {
	management, static, gateway, err := ParseListenerBinds(mapBindConfig{
		ConfigKeyManagementBindAddress: "127.0.0.1",
		ConfigKeyStaticBindAddress:     "::1",
		ConfigKeyGatewayBindAddress:    "",
	})
	if err != nil {
		t.Fatalf("ParseListenerBinds: %v", err)
	}
	if management != "127.0.0.1" || static != "::1" || gateway != "" {
		t.Fatalf("binds = %q, %q, %q", management, static, gateway)
	}

	for name, values := range map[string]map[string]string{
		"wildcard management": {
			ConfigKeyManagementBindAddress: "0.0.0.0",
			ConfigKeyStaticBindAddress:     "127.0.0.1",
			ConfigKeyGatewayBindAddress:    "",
		},
		"hostname static": {
			ConfigKeyManagementBindAddress: "127.0.0.1",
			ConfigKeyStaticBindAddress:     "localhost",
			ConfigKeyGatewayBindAddress:    "",
		},
		"hostname gateway": {
			ConfigKeyManagementBindAddress: "127.0.0.1",
			ConfigKeyStaticBindAddress:     "127.0.0.1",
			ConfigKeyGatewayBindAddress:    "example.com",
		},
	} {
		if _, _, _, err := ParseListenerBinds(mapBindConfig(values)); err == nil {
			t.Fatalf("%s unexpectedly accepted", name)
		}
	}

	if _, _, _, err := ParseListenerBinds(nil); err == nil {
		t.Fatal("nil configuration unexpectedly accepted")
	}
}
