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
	// absolute path inside the harness image.
	Command []string `json:"command"`
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
	// TimeoutSeconds bounds one run of the command (default 3600).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

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
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 3600
	}
	if c.Version != 1 || len(c.Command) == 0 || len(c.Command) > 64 || !filepath.IsAbs(c.Command[0]) ||
		filepath.Clean(c.Command[0]) != c.Command[0] || (c.Input != "stdin" && c.Input != "argument") ||
		c.TimeoutSeconds < 1 || c.TimeoutSeconds > 86400 || len(c.Env) > 64 || len(c.Models) > 64 ||
		(c.DefaultModel != "" && !validAlias(c.DefaultModel)) {
		return Config{}, ErrConfig
	}
	for _, a := range c.Command {
		if len(a) > 4096 || strings.ContainsRune(a, 0) || !utf8.ValidString(a) {
			return Config{}, ErrConfig
		}
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
	host, port, err := net.SplitHostPort(c.ModelAddress)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() || port == "" || port == "0" {
		return Config{}, ErrConfig
	}
	return c, nil
}

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
	for k, v := range extra {
		env[k] = v
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}
