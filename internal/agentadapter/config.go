// Package agentadapter runs an unmodified agent program as a capsule.v1
// harness. The adapter speaks the guest protocol on the agent's behalf: each
// invocation (or request from another agent) runs the agent's command once,
// with the text on its input, and its output becomes the answer. A model
// endpoint on the VM's loopback lets the agent's own OpenAI or Anthropic SDK
// reach the organization's model aliases through the platform, which keeps the
// credentials and the budget.
package agentadapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ConfigPath is where the adapter looks for its configuration when its
// entrypoint names none.
const ConfigPath = "/agentcapsule/adapter.json"

// DefaultModelAddress is the model endpoint's loopback address.
const DefaultModelAddress = "127.0.0.1:8411"

var ErrConfig = errors.New("invalid adapter configuration")

// Config is the adapter's configuration, shipped read-only in the harness image.
type Config struct {
	Version int `json:"version"`
	// Command is the agent program and its arguments; the program is an
	// absolute path inside the harness image. It runs once per job.
	Command []string `json:"command,omitempty"`
	// Server is, instead of Command, an agent that runs as an A2A server for
	// the life of the VM; each job is a message to it.
	Server *ServerConfig `json:"server,omitempty"`
	// Input says how the text reaches the program: "stdin" (default) or
	// "argument", appended as the last argument.
	Input string `json:"input,omitempty"`
	// Env adds to or replaces the default environment, except AGENTCAPSULE_*.
	Env map[string]string `json:"env,omitempty"`
	// Models maps the model names the agent asks for to the organization's
	// aliases. A name absent from it is used as DefaultModel when set,
	// otherwise as an alias of the same name.
	Models       map[string]string `json:"models,omitempty"`
	DefaultModel string            `json:"default_model,omitempty"`
	// ModelAddress is the loopback address of the model endpoint.
	ModelAddress string `json:"model_address,omitempty"`
	// A2AAddress is the loopback address of the A2A endpoint, through which
	// the agent sends requests to other agents of its organization.
	A2AAddress string `json:"a2a_address,omitempty"`
	// TimeoutSeconds bounds one run of the command (default 3600).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// ServerConfig describes an agent that serves A2A (1.0, JSON-RPC binding) on
// the VM's loopback.
type ServerConfig struct {
	// Command starts the server; it runs until the VM stops and is started
	// again if it exits.
	Command []string `json:"command"`
	// URL is the server's A2A endpoint, such as http://127.0.0.1:9000/. The
	// adapter calls it there, whatever the agent's own card says.
	URL string `json:"a2a_url"`
	// ReadySeconds bounds how long a job waits for the server to accept
	// connections after a start (default 120).
	ReadySeconds int `json:"ready_seconds,omitempty"`
}

// Ready is how long a job waits for the server to accept connections.
func (s ServerConfig) Ready() time.Duration { return time.Duration(s.ReadySeconds) * time.Second }

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func validAlias(s string) bool {
	return s != "" && len(s) <= 100 && !strings.ContainsAny(s, " \t\r\n\x00") && utf8.ValidString(s)
}

// LoadConfig reads and checks a configuration file: regular, at most 64 KiB,
// strict JSON with no unknown field.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return Config{}, ErrConfig
	}
	b, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil || len(b) > 64<<10 {
		return Config{}, ErrConfig
	}
	return ParseConfig(b)
}

func ParseConfig(b []byte) (Config, error) {
	var c Config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil || d.More() {
		return Config{}, ErrConfig
	}
	if _, err := d.Token(); err != io.EOF {
		return Config{}, ErrConfig
	}
	if c.Input == "" {
		c.Input = "stdin"
	}
	if c.ModelAddress == "" {
		c.ModelAddress = DefaultModelAddress
	}
	if c.A2AAddress == "" {
		c.A2AAddress = DefaultA2AAddress
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 3600
	}
	program := c.Command
	if c.Server != nil {
		// A server takes its jobs as messages: there is no input to choose.
		if len(c.Command) != 0 || c.Input != "stdin" {
			return Config{}, ErrConfig
		}
		if c.Server.ReadySeconds == 0 {
			c.Server.ReadySeconds = 120
		}
		if c.Server.ReadySeconds < 1 || c.Server.ReadySeconds > 3600 || !loopbackURL(c.Server.URL) {
			return Config{}, ErrConfig
		}
		program = c.Server.Command
	}
	if c.Version != 1 || !validCommand(program) || (c.Input != "stdin" && c.Input != "argument") ||
		c.TimeoutSeconds < 1 || c.TimeoutSeconds > 86400 || len(c.Env) > 64 || len(c.Models) > 64 ||
		(c.DefaultModel != "" && !validAlias(c.DefaultModel)) {
		return Config{}, ErrConfig
	}
	for k, v := range c.Env {
		if !envName.MatchString(k) || strings.HasPrefix(k, "AGENTCAPSULE_") || len(v) > 4096 || strings.ContainsRune(v, 0) {
			return Config{}, ErrConfig
		}
	}
	for name, alias := range c.Models {
		if name == "" || len(name) > 200 || strings.ContainsRune(name, 0) || !validAlias(alias) {
			return Config{}, ErrConfig
		}
	}
	for _, address := range []string{c.ModelAddress, c.A2AAddress} {
		host, port, err := net.SplitHostPort(address)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() || port == "" || port == "0" {
			return Config{}, ErrConfig
		}
	}
	if c.ModelAddress == c.A2AAddress {
		return Config{}, ErrConfig
	}
	if c.Server != nil {
		u, _ := url.Parse(c.Server.URL)
		if u.Host == c.ModelAddress || u.Host == c.A2AAddress {
			return Config{}, ErrConfig
		}
	}
	return c, nil
}

func validCommand(command []string) bool {
	if len(command) == 0 || len(command) > 64 || !filepath.IsAbs(command[0]) || filepath.Clean(command[0]) != command[0] {
		return false
	}
	for _, a := range command {
		if len(a) > 4096 || strings.ContainsRune(a, 0) || !utf8.ValidString(a) {
			return false
		}
	}
	return true
}

// loopbackURL accepts an http URL on a loopback IP and an explicit port, with
// no credentials, query or fragment.
func loopbackURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(s) > 2048 {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback() && u.Port() != "" && u.Port() != "0"
}

// A2AURL is the A2A endpoint's base address, as the agent reaches it.
func (c Config) A2AURL() string { return "http://" + c.A2AAddress }

// Timeout is the bound of one run of the command.
func (c Config) Timeout() time.Duration { return time.Duration(c.TimeoutSeconds) * time.Second }

// Alias is the organization alias a model name stands for.
func (c Config) Alias(model string) (string, bool) {
	if alias, ok := c.Models[model]; ok {
		return alias, true
	}
	if c.DefaultModel != "" {
		return c.DefaultModel, true
	}
	return model, validAlias(model)
}

// Environment is the agent's environment: a conventional PATH, HOME on its
// private data directory, and the model endpoint for the OpenAI and Anthropic
// SDKs, whose keys are placeholders (the platform holds the real ones).
func (c Config) Environment(home string, extra map[string]string) []string {
	base := "http://" + c.ModelAddress
	env := map[string]string{
		"PATH":               "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME":               home,
		"LANG":               "C.UTF-8",
		"TMPDIR":             "/tmp",
		"OPENAI_BASE_URL":    base + "/v1",
		"OPENAI_API_BASE":    base + "/v1",
		"OPENAI_API_KEY":     "agentcapsule",
		"ANTHROPIC_BASE_URL": base,
		"ANTHROPIC_API_KEY":  "agentcapsule",
	}
	for k, v := range c.Env {
		env[k] = v
	}
	env["AGENTCAPSULE_MODEL_URL"] = base
	env["AGENTCAPSULE_A2A_URL"] = c.A2AURL()
	for k, v := range extra {
		env[k] = v
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}
