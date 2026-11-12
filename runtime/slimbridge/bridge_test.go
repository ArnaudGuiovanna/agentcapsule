package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The worker (internal/slimlink, in the platform's module) writes the same
// contract and owns these examples (internal/slimlink/testdata); both sides
// decode them strictly and write them back unchanged.
func TestTheWorkerContractIsTheSameOnBothSides(t *testing.T) {
	raw, err := os.ReadFile("../../internal/slimlink/testdata/contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]json.RawMessage
	if err = json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	var paths map[string]string
	var codes []string
	var namespace string
	_ = json.Unmarshal(c["paths"], &paths)
	_ = json.Unmarshal(c["codes"], &codes)
	_ = json.Unmarshal(c["platform_namespace"], &namespace)
	if !reflect.DeepEqual(paths, map[string]string{"serve": servePath, "send": sendPath, "health": healthPath, "deliver": deliverPath}) ||
		!reflect.DeepEqual(codes, []string{codeUnreachable, codeRefused, codeFailed, codeInvalid, codeUnavailable}) || namespace != platformNamespace {
		t.Fatal("paths, codes or namespace differ", paths, codes, namespace)
	}
	for name, v := range map[string]any{"serve": &ServeRequest{}, "send": &SendRequest{}, "deliver": &DeliverRequest{}, "receipt": &Receipt{}, "health": &Health{}, "failure": &Failure{}} {
		d := json.NewDecoder(bytes.NewReader(c[name]))
		d.DisallowUnknownFields()
		if err = d.Decode(v); err != nil {
			t.Fatal(name, err)
		}
		again, _ := json.Marshal(v)
		var want, got any
		_ = json.Unmarshal(c[name], &want)
		_ = json.Unmarshal(again, &got)
		if !reflect.DeepEqual(want, got) {
			t.Fatal(name, string(again))
		}
	}
}

// writeConfig writes a configuration and its private files; certificates are
// only checked for being absolute until the bridge connects.
func writeConfig(t *testing.T, dir string, mutate func(*Config)) string {
	t.Helper()
	for name, body := range map[string]string{"key.pem": "key", "secret": strings.Repeat("s", 40) + "\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := Config{Version: 1, Node: "https://127.0.0.1:46357", CA: "/etc/slim/ca.pem", Cert: "/etc/slim/client.crt", Key: filepath.Join(dir, "key.pem"),
		SecretFile: filepath.Join(dir, "secret"), Name: "agentcapsule/platform/host-1", Socket: filepath.Join(dir, "bridge.sock"),
		WorkerSocket: filepath.Join(dir, "worker.sock"), WorkerUID: 0}
	if mutate != nil {
		mutate(&c)
	}
	raw, _ := json.Marshal(c)
	path := filepath.Join(dir, "bridge.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigurationIsCheckedBeforeConnecting(t *testing.T) {
	dir := t.TempDir()
	c, secret, err := LoadConfig(writeConfig(t, dir, nil))
	if err != nil || secret != strings.Repeat("s", 40) || c.Idle().Minutes() != 10 || c.Probe().Seconds() != 5 || c.Call().Minutes() != 5 {
		t.Fatal("defaults", c, err)
	}
	for name, mutate := range map[string]func(*Config){
		"plain node":       func(c *Config) { c.Node = "http://127.0.0.1:46357" },
		"agent's name":     func(c *Config) { c.Name = "agentcapsule/org_1/agt-a" },
		"same socket":      func(c *Config) { c.WorkerSocket = c.Socket },
		"relative ca":      func(c *Config) { c.CA = "ca.pem" },
		"negative worker":  func(c *Config) { c.WorkerUID = -1 },
		"idle too short":   func(c *Config) { c.IdleSeconds = 5 },
		"probe too slow":   func(c *Config) { c.ProbeSeconds = 120 },
		"unreadable key":   func(c *Config) { c.Key = filepath.Join(dir, "absent") },
		"short secret":     func(c *Config) { c.SecretFile = filepath.Join(dir, "short") },
		"version":          func(c *Config) { c.Version = 2 },
		"node with a path": func(c *Config) { c.Node = "https://127.0.0.1:46357/x" },
	} {
		_ = os.WriteFile(filepath.Join(dir, "short"), []byte("too short"), 0o600)
		if _, _, err := LoadConfig(writeConfig(t, dir, mutate)); !errors.Is(err, errConfig) {
			t.Fatal(name, err)
		}
	}
	// The secret and the key are the bridge's alone.
	path := writeConfig(t, dir, nil)
	if err = os.Chmod(filepath.Join(dir, "secret"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err = LoadConfig(path); !errors.Is(err, errConfig) {
		t.Fatal("a secret others can read", err)
	}
	path = writeConfig(t, dir, nil)
	if err = os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err = LoadConfig(path); err == nil {
		t.Fatal("a configuration others can write")
	}
}

func TestNames(t *testing.T) {
	for _, s := range []string{"agentcapsule/org_1/agt-b", "agentcapsule/personal/a.b-c_d"} {
		if !validName(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"agentcapsule/a", "other/a/b", "agentcapsule/a/b/c", "agentcapsule/a/b c", "agentcapsule//b"} {
		if validName(s) {
			t.Fatal(s)
		}
	}
}
