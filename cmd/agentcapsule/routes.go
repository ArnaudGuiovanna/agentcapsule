package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Commands use the same HTTP contract as an application. Each brace takes
// one positional identifier (left to right), or its named flag.
var commands = map[string]string{
	"pool expand": "POST /pools/{id}/expand", "rollout start": "POST /deployments/{deployment}/rollouts", "rollout members": "GET /rollouts/{id}/members", "rollout show": "GET /rollouts/{id}", "rollout resume": "POST /rollouts/{id}/resume",
	"communication explain": "GET /agents/{agent}/requests/{request}/diagnostics",
	"organization list":     "GET /organizations", "organization create": "POST /organizations", "organization show": "GET /organizations/{id}", "organization disable": "POST /organizations/{id}/disable", "organization current": "GET /organizations/current",
	"quota show": "GET /organizations/{id}/quotas", "quota set": "PUT /organizations/{id}/quotas", "quota current": "GET /organizations/current/quotas",
	"member list": "GET /members", "member create": "POST /members", "member role": "POST /members/{member}/role", "member revoke": "POST /members/{member}/revoke",
	"team list": "GET /teams", "team create": "POST /teams", "team show": "GET /teams/{team}", "team disable": "POST /teams/{team}/disable", "team members": "GET /teams/{team}/members", "team add": "POST /teams/{team}/members", "team remove": "POST /teams/{team}/members/{member}/revoke",
	"service-account list": "GET /service-accounts", "service-account create": "POST /service-accounts", "service-account disable": "POST /service-accounts/{account}/disable", "key list": "GET /service-accounts/{account}/tokens", "key issue": "POST /service-accounts/{account}/tokens", "key revoke": "POST /service-accounts/{account}/tokens/{id}/revoke",
	"agent list": "GET /agents", "agent create": "POST /agents", "agent show": "GET /agents/{agent}", "agent delete": "DELETE /agents/{agent}", "agent wake": "POST /agents/{agent}/wake", "agent sleep": "POST /agents/{agent}/sleep", "agent idle-policy": "POST /agents/{agent}/idle-policy", "agent release": "POST /agents/{agent}/release", "agent invoke": "POST /agents/{agent}/invocations", "agent capabilities": "GET /agents/{agent}/capabilities",
	"assignment list": "GET /agents/{agent}/assignments", "assignment grant": "POST /agents/{agent}/assignments", "assignment revoke": "POST /agents/{agent}/assignments/{id}/revoke", "assignment replace": "POST /agents/{agent}/assignments/{id}/replace", "assignment reassign": "POST /agents/{agent}/assignments/{id}/reassign",
	"registry import": "POST /harness-imports", "registry show": "GET /harness-imports/{id}", "registry list": "GET /harness-releases", "registry deprecate": "POST /harness-releases/{id}/deprecate",
	"invocation show": "GET /invocations/{id}", "invocation result": "GET /invocations/{id}/result", "invocation cancel": "POST /invocations/{id}/cancel", "invocation replay": "POST /invocations/{id}/replay",
	"queue show": "GET /queue", "queue limits": "POST /queue/limits", "audit list": "GET /audit", "audit export": "GET /audit/export", "revocation show": "GET /access-revocations/{id}",
	"provider list": "GET /llm/providers", "provider create": "POST /llm/providers", "provider rotate": "POST /llm/providers/{id}/rotate", "provider disable": "POST /llm/providers/{id}/disable",
	"alias list": "GET /llm/aliases", "alias create": "POST /llm/aliases", "alias access": "POST /llm/aliases/{alias}/access", "alias prices": "POST /llm/aliases/{alias}/prices", "alias disable": "POST /llm/aliases/{alias}/disable", "alias grants": "GET /llm/aliases/{alias}/grants", "alias grant": "POST /llm/aliases/{alias}/grants", "alias revoke": "POST /llm/aliases/{alias}/grants/{id}/revoke",
	"budget list": "GET /llm/budgets", "budget create": "POST /llm/budgets", "budget disable": "POST /llm/budgets/{id}/disable", "llm usage": "GET /llm/usage", "llm unresolved": "GET /llm/calls/unresolved", "llm settle": "POST /llm/calls/{id}/settle", "llm release": "POST /llm/calls/{id}/release",
	"directory show": "GET /agents/{agent}/directory", "directory set": "PUT /agents/{agent}/directory", "communication inbound": "GET /agents/{agent}/inbound", "communication configure": "PUT /agents/{agent}/inbound", "communication held": "GET /agents/{agent}/held-requests", "communication accept": "POST /agents/{agent}/held-requests/{id}/accept", "communication decline": "POST /agents/{agent}/held-requests/{id}/decline",
	"operation show": "GET /operations/{id}", "operation wait": "GET /operations/{id}", "session show": "GET /platform/session", "session revoke": "POST /platform/sessions/{id}/revoke",
	"template publish": "POST /templates", "deployment plan": "POST /deployment-plans", "deployment apply": "POST /deployment-plans/{plan}/apply", "deployment show": "GET /deployments/{id}", "pool create": "POST /pools", "pool show": "GET /pools/{id}", "system-image publish": "POST /system-images", "system-image list": "GET /system-images",
	"app register": "POST /applications", "app list": "GET /applications", "app connection": "GET /applications/{id}", "app show": "GET /applications/{id}", "app rotate": "POST /applications/{id}/rotate", "app revoke": "POST /applications/{id}/revoke",
	"assignment-policy plan": "POST /assignment-policies/plan", "assignment-policy apply": "POST /assignment-policies/{plan}/apply", "access explain": "GET /access/explain",
}

type options map[string]string

func (o options) take(k string) string { v := o[k]; delete(o, k); return v }
func (o options) done() error {
	if len(o) == 0 {
		return nil
	}
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return fmt.Errorf("unexpected option --%s", keys[0])
}
func parse(args []string) ([]string, options, error) {
	o := options{}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			pos = append(pos, a)
			continue
		}
		k, v, equal := strings.Cut(a[2:], "=")
		if k == "" {
			return nil, nil, errors.New("empty option")
		}
		if _, dup := o[k]; dup {
			return nil, nil, fmt.Errorf("duplicate --%s", k)
		}
		switch k {
		case "json", "help", "watch", "non-interactive":
			if equal {
				return nil, nil, fmt.Errorf("--%s takes no value", k)
			}
			v = "true"
		default:
			if !equal {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "--") {
					return nil, nil, fmt.Errorf("--%s requires a value", k)
				}
				v = args[i]
			}
			if v == "" {
				return nil, nil, fmt.Errorf("--%s requires a value", k)
			}
		}
		o[k] = v
	}
	return pos, o, nil
}
func readSource(path string, stdin io.Reader, private bool) ([]byte, error) {
	if path == "-" {
		return readBounded(stdin, maxDocument)
	}
	return readFile(path, private)
}
func document(path string, in io.Reader) (map[string]any, error) {
	m := map[string]any{}
	if path == "" {
		return m, nil
	}
	data, err := readSource(path, in, false)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, errors.New("expected a single JSON or YAML object")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, errors.New("expected one document")
	}
	if path != "-" && hasSecret(m) {
		if _, err = readFile(path, true); err != nil {
			return nil, err
		}
	}
	return m, nil
}
func hasSecret(val any) bool {
	switch x := val.(type) {
	case map[string]any:
		for k, v := range x {
			switch strings.ToLower(k) {
			case "secret", "token", "client_secret", "password", "invitation_token", "private_key", "access_token", "refresh_token", "proof":
				return true
			}
			if hasSecret(v) {
				return true
			}
		}
	case []any:
		for _, v := range x {
			if hasSecret(v) {
				return true
			}
		}
	}
	return false
}

var param = regexp.MustCompile(`\{([a-z_]+)\}`)

type action struct {
	name, method, path string
	body               []byte
}

func buildAction(pos []string, o options, in io.Reader) (action, error) {
	var a action
	if len(pos) < 2 {
		return a, errors.New("expected a command and subcommand (see help)")
	}
	a.name = strings.Join(pos[:2], " ")
	spec, ok := commands[a.name]
	args := pos[2:]
	if a.name == "operation show" || a.name == "operation wait" {
		kind := o.take("type")
		byKind := map[string]string{"": "operations", "operation": "operations", "deployment": "deployments", "rollout": "rollouts", "harness-import": "harness-imports", "invocation": "invocations"}
		if kind == "activation" {
			byKind[kind] = "applications/{app}/activations"
		}
		resource, found := byKind[kind]
		if !found {
			return a, errors.New("unknown operation type")
		}
		spec = "GET /" + resource + "/{id}"
	}
	if pos[0] == "api" && len(pos) == 3 {
		a.method = strings.ToUpper(pos[1])
		a.path = pos[2]
		args = nil
		switch a.method {
		case "GET", "POST", "PUT", "DELETE":
		default:
			return a, errors.New("unsupported HTTP method")
		}
	} else {
		if !ok {
			return a, fmt.Errorf("unknown command %q", a.name)
		}
		a.method, a.path, _ = strings.Cut(spec, " ")
		a.path = "/v1" + a.path
		for _, match := range param.FindAllStringSubmatch(a.path, -1) {
			val := o.take(match[1])
			if val == "" && len(args) > 0 {
				val, args = args[0], args[1:]
			}
			if val == "" || val == "." || val == ".." || strings.ContainsAny(val, "/\\?#\r\n") {
				return a, fmt.Errorf("invalid or missing %s", match[1])
			}
			a.path = strings.Replace(a.path, match[0], url.PathEscape(val), 1)
		}
	}
	if !validRoute(a.path) {
		return a, errors.New("invalid API path")
	}
	if a.method == "GET" {
		u, _ := url.ParseRequestURI(a.path)
		q := u.Query()
		for _, key := range []string{"limit", "after", "period", "from", "to", "member", "agent", "cursor", "status", "action"} {
			if v := o.take(key); v != "" {
				q.Set(key, v)
			}
		}
		u.RawQuery = q.Encode()
		a.path = u.RequestURI()
	} else {
		file := o.take("file")
		config := o.take("config")
		if file != "" && config != "" {
			return a, errors.New("choose one input file")
		}
		if file == "" {
			file = config
		}
		body, err := document(file, in)
		if err != nil {
			return a, err
		}
		if a.name == "organization create" {
			if path := o.take("owner-file"); path != "" {
				if _, exists := body["initial_owner"]; exists {
					return a, errors.New("choose one initial owner")
				}
				data, err := readSource(path, in, false)
				if err != nil {
					return a, err
				}
				var who struct {
					Version int               `json:"version"`
					Data    map[string]string `json:"data"`
				}
				if json.Unmarshal(data, &who) != nil || who.Version != 1 || who.Data["issuer"] == "" {
					return a, errors.New("expected the public output of identity create or show")
				}
				body["initial_owner"] = who.Data
			}
		}
		set := func(k string, v any) error {
			if old, exists := body[k]; exists && old != v {
				return fmt.Errorf("conflicting value for %s", k)
			}
			body[k] = v
			return nil
		}
		if (a.name == "app register" || a.name == "pool create") && len(args) > 0 {
			if err = set("name", args[0]); err != nil {
				return a, err
			}
			args = args[1:]
		}
		for _, k := range []string{"template", "count", "active-count", "max-unavailable", "deployment", "auth-mode", "base-url", "kind", "name", "reference", "alias", "upstream-model", "provider-id"} {
			v := o.take(k)
			if v == "" {
				continue
			}
			field := strings.ReplaceAll(k, "-", "_")
			var value any = v
			if k == "deployment" {
				field = "deployment_id"
			}
			if k == "count" || k == "active-count" || k == "max-unavailable" {
				n, e := strconv.Atoi(v)
				if e != nil || n < 0 {
					return a, fmt.Errorf("invalid --%s", k)
				}
				value = n
			}
			if err = set(field, value); err != nil {
				return a, err
			}
		}
		if sf := o.take("secret-file"); sf != "" {
			if sf == "-" && file == "-" {
				return a, errors.New("stdin can only have one reader")
			}
			secret, e := readSource(sf, in, true)
			if e != nil {
				return a, e
			}
			if err = set("secret", strings.TrimRight(string(secret), "\r\n")); err != nil {
				return a, err
			}
		}
		a.body, err = json.Marshal(body)
		if err != nil {
			return a, errors.New("document is not representable as JSON")
		}
	}
	if len(args) != 0 {
		return a, errors.New("unexpected positional argument")
	}
	return a, o.done()
}
func listCommands(w io.Writer) {
	fmt.Fprintln(w, `agentcapsule [--context NAME] COMMAND [--file FILE|-] [--idempotency-key KEY] [--output-file FILE]
context add NAME --url HTTPS_ORIGIN --kind platform|organization [--organization ID] [--ca FILE]
context use NAME | context list | context show NAME
identity create|show --key-file PATH --display-name NAME
login --enrollment-file FILE|- | login --key-file PATH | login --token-file FILE|- | session renew | logout
status [--watch] | doctor | support export --output-file FILE
install | update check|plan|apply | self update | host operation show|wait | restore
api METHOD /v1/path
--json selects versioned JSON (default). --non-interactive runs without prompts.
For named routes supply identifiers in route order or as named flags.`)
	keys := make([]string, 0, len(commands))
	for k := range commands {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "  %-26s %s\n", k, commands[k])
	}
}

func returnsCredential(a action) bool {
	p := strings.Split(a.path, "?")[0]
	if a.method != "POST" {
		return false
	}
	return p == "/v1/applications" || strings.HasPrefix(p, "/v1/applications/") && (strings.HasSuffix(p, "/rotate") || strings.HasSuffix(p, "/invitations")) || strings.HasSuffix(p, "/tokens")
}
