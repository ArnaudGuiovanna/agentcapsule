package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Commands use the same HTTP contract as an application. Each brace takes
// one positional identifier (left to right), or its named flag.
var commands = map[string]string{
	"access explain": "GET /access/explain",

	"corpus list":               "GET /corpora",
	"corpus create":             "POST /corpora",
	"corpus show":               "GET /corpora/{corpus}",
	"corpus build":              "POST /corpora/{corpus}/builds",
	"corpus versions":           "GET /corpus-releases",
	"corpus-build list":         "GET /corpus-builds",
	"corpus-build show":         "GET /corpus-builds/{id}",
	"corpus-build cancel":       "POST /corpus-builds/{id}/cancel",
	"corpus-build review":       "GET /corpus-builds/{id}/review",
	"corpus-build files":        "GET /corpus-builds/{id}/review-file",
	"corpus-build index":        "GET /corpus-builds/{id}/review-file",
	"corpus-build try":          "POST /corpus-builds/{id}/try",
	"corpus-build publish":      "POST /corpus-builds/{id}/publish",
	"corpus-release list":       "GET /corpus-releases",
	"corpus-release show":       "GET /corpus-releases/{id}",
	"corpus-release deprecate":  "POST /corpus-releases/{id}/deprecate",
	"source-credential list":    "GET /source-credentials",
	"source-credential create":  "POST /source-credentials",
	"source-credential rotate":  "POST /source-credentials/{id}/rotate",
	"source-credential disable": "POST /source-credentials/{id}/disable",
	"agent corpora":             "GET /agents/{id}/corpora",
	"agent set-corpora":         "POST /agents/{id}/corpora",

	"activation show":   "GET /applications/{app}/activations/{id}",
	"activation update": "PUT /applications/{app}/activations/{id}",

	"agent capabilities":     "GET /agents/{agent}/capabilities",
	"agent create":           "POST /agents",
	"agent delete":           "DELETE /agents/{agent}",
	"agent grow":             "POST /agents/{id}/volume-growth",
	"agent idle-policy":      "POST /agents/{agent}/idle-policy",
	"agent invoke":           "POST /agents/{agent}/invocations",
	"agent list":             "GET /agents",
	"agent resize":           "POST /agents/{id}/resize",
	"agent release":          "POST /agents/{agent}/release",
	"agent set-capabilities": "PUT /agents/{agent}/capabilities",
	"agent show":             "GET /agents/{agent}",
	"agent sleep":            "POST /agents/{agent}/sleep",
	"agent wake":             "POST /agents/{agent}/wake",

	"alias access":  "POST /llm/aliases/{alias}/access",
	"alias create":  "POST /llm/aliases",
	"alias disable": "POST /llm/aliases/{alias}/disable",
	"alias grant":   "POST /llm/aliases/{alias}/grants",
	"alias grants":  "GET /llm/aliases/{alias}/grants",
	"alias list":    "GET /llm/aliases",
	"alias prices":  "POST /llm/aliases/{alias}/prices",
	"alias revoke":  "POST /llm/aliases/{alias}/grants/{id}/revoke",

	"app connection": "GET /applications/{id}",
	"app invite":     "POST /applications/{app}/invitations",
	"app list":       "GET /applications",
	"app register":   "POST /applications",
	"app revoke":     "POST /applications/{id}/revoke",
	"app rotate":     "POST /applications/{id}/rotate",
	"app show":       "GET /applications/{id}",
	"app verify":     "GET /applications/{id}",

	"assignment grant":    "POST /agents/{agent}/assignments",
	"assignment list":     "GET /agents/{agent}/assignments",
	"assignment reassign": "POST /agents/{agent}/assignments/{id}/reassign",
	"assignment replace":  "POST /agents/{agent}/assignments/{id}/replace",
	"assignment revoke":   "POST /agents/{agent}/assignments/{id}/revoke",

	"assignment-policy apply": "POST /assignment-policies/{plan}/apply",
	"assignment-policy plan":  "POST /assignment-policies/plan",

	"audit export": "GET /audit/export",
	"audit list":   "GET /audit",

	"budget create":  "POST /llm/budgets",
	"budget disable": "POST /llm/budgets/{id}/disable",
	"budget list":    "GET /llm/budgets",

	"communication accept":    "POST /agents/{agent}/held-requests/{id}/accept",
	"communication configure": "PUT /agents/{agent}/inbound",
	"communication decline":   "POST /agents/{agent}/held-requests/{id}/decline",
	"communication explain":   "GET /agents/{agent}/requests/{request}/diagnostics",
	"communication held":      "GET /agents/{agent}/held-requests",
	"communication inbound":   "GET /agents/{agent}/inbound",

	"deployment apply": "POST /deployment-plans/{plan}/apply",
	"deployment plan":  "POST /deployment-plans",
	"deployment show":  "GET /deployments/{id}",

	"directory set":  "PUT /agents/{agent}/directory",
	"directory show": "GET /agents/{agent}/directory",

	"invocation cancel": "POST /invocations/{id}/cancel",
	"invocation replay": "POST /invocations/{id}/replay",
	"invocation result": "GET /invocations/{id}/result",
	"invocation show":   "GET /invocations/{id}",

	"key issue":  "POST /service-accounts/{account}/tokens",
	"key list":   "GET /service-accounts/{account}/tokens",
	"key revoke": "POST /service-accounts/{account}/tokens/{id}/revoke",

	"llm release":    "POST /llm/calls/{id}/release",
	"llm settle":     "POST /llm/calls/{id}/settle",
	"llm unresolved": "GET /llm/calls/unresolved",
	"llm usage":      "GET /llm/usage",

	"member create": "POST /members",
	"member list":   "GET /members",
	"member revoke": "POST /members/{member}/revoke",
	"member role":   "POST /members/{member}/role",

	"operation show": "GET /operations/{id}",
	"operation wait": "GET /operations/{id}",

	"organization capabilities":     "GET /organizations/current/capabilities",
	"organization create":           "POST /organizations",
	"organization current":          "GET /organizations/current",
	"organization disable":          "POST /organizations/{id}/disable",
	"organization list":             "GET /organizations",
	"organization set-capabilities": "PUT /organizations/current/capabilities",
	"organization show":             "GET /organizations/{id}",

	"pool create": "POST /pools",
	"pool expand": "POST /pools/{id}/expand",
	"pool show":   "GET /pools/{id}",

	"provider create":  "POST /llm/providers",
	"provider disable": "POST /llm/providers/{id}/disable",
	"provider list":    "GET /llm/providers",
	"provider rotate":  "POST /llm/providers/{id}/rotate",

	"queue limits": "POST /queue/limits",
	"queue show":   "GET /queue",

	"quota current": "GET /organizations/current/quotas",
	"quota set":     "PUT /organizations/{id}/quotas",
	"quota show":    "GET /organizations/{id}/quotas",

	"registry deprecate": "POST /harness-releases/{id}/deprecate",
	"registry import":    "POST /harness-imports",
	"registry list":      "GET /harness-releases",
	"registry show":      "GET /harness-imports/{id}",

	"revocation show": "GET /access-revocations/{id}",

	"rollout members": "GET /rollouts/{id}/members",
	"rollout resume":  "POST /rollouts/{id}/resume",
	"rollout show":    "GET /rollouts/{id}",
	"rollout start":   "POST /deployments/{deployment}/rollouts",

	"service-account create":  "POST /service-accounts",
	"service-account disable": "POST /service-accounts/{account}/disable",
	"service-account list":    "GET /service-accounts",

	"session revoke": "POST /platform/sessions/{id}/revoke",
	"session show":   "GET /platform/session",

	"system-image list":    "GET /system-images",
	"system-image publish": "POST /system-images",

	"team add":     "POST /teams/{team}/members",
	"team create":  "POST /teams",
	"team disable": "POST /teams/{team}/disable",
	"team list":    "GET /teams",
	"team members": "GET /teams/{team}/members",
	"team remove":  "POST /teams/{team}/members/{member}/revoke",
	"team show":    "GET /teams/{team}",

	"template publish": "POST /templates",

	"volume-growth show": "GET /volume-growth/{id}",
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
		case "json", "help", "watch", "non-interactive", "include-deprecated":
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
	var f *os.File
	if path != "-" {
		var err error
		f, err = openRegular(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		in = f
	}
	data, err := readBounded(in, maxDocument)
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
	if f != nil && hasSecret(m) {
		if err := verifyPrivateFile(f); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return m, nil
}
func hasSecret(val any) bool {
	switch x := val.(type) {
	case map[string]any:
		for k, v := range x {
			switch strings.ToLower(k) {
			case "secret", "token", "client_secret", "password", "invitation_token", "provisioning_token", "private_key", "access_token", "refresh_token", "proof":
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
	name, method, path                   string
	body                                 []byte
	corpusRef, credentialRef, fileStatus string
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
		byKind := map[string]string{
			"":               "operations",
			"operation":      "operations",
			"deployment":     "deployments",
			"rollout":        "rollouts",
			"harness-import": "harness-imports",
			"invocation":     "invocations",
			"corpus-build":   "corpus-builds",
			"volume-growth":  "volume-growth",
			"activation":     "applications/{app}/activations",
			"revocation":     "access-revocations",
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
			if match[1] == "corpus" {
				a.corpusRef = val
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
		if a.name == "corpus versions" {
			a.corpusRef = o.take("corpus")
			if a.corpusRef == "" && len(args) > 0 {
				a.corpusRef, args = args[0], args[1:]
			}
			if a.corpusRef == "" {
				return a, errors.New("provide a corpus name or ID")
			}
			q.Set("corpus_id", a.corpusRef)
		}
		if a.name == "corpus-build files" {
			a.fileStatus = o.take("status")
			if a.fileStatus != "" && a.fileStatus != "converted" && a.fileStatus != "cached" && a.fileStatus != "skipped" && a.fileStatus != "failed" {
				return a, errors.New("invalid corpus file status")
			}
			q.Set("path", "report.json")
		}
		if a.name == "corpus-build index" {
			q.Set("path", "INDEX.md")
		}
		if a.name == "corpus list" {
			if v := o.take("name"); v != "" {
				q.Set("name", v)
			}
		}
		if a.name == "corpus-build list" {
			if v := o.take("state"); v != "" {
				q.Set("state", v)
			}
		}
		if a.name == "corpus-build list" || a.name == "corpus-release list" {
			if v := o.take("corpus"); v != "" {
				a.corpusRef = v
				q.Set("corpus_id", v)
			}
		}
		if a.name == "corpus versions" || a.name == "corpus-release list" {
			if o.take("include-deprecated") != "" {
				q.Set("include_deprecated", "true")
			}
		}
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
		if (a.name == "app register" || a.name == "pool create" || a.name == "corpus create") && len(args) > 0 {
			if err = set("name", args[0]); err != nil {
				return a, err
			}
			args = args[1:]
		}
		if err = buildCorpusOptions(&a, o, body, set); err != nil {
			return a, err
		}
		for _, k := range []string{"template", "count", "active-count", "max-unavailable", "size-mib", "vcpus", "memory-mib", "deployment", "auth-mode", "base-url", "kind", "name", "reference", "alias", "upstream-model", "provider-id"} {
			v := o.take(k)
			if v == "" {
				continue
			}
			field := strings.ReplaceAll(k, "-", "_")
			var value any = v
			if k == "deployment" {
				field = "deployment_id"
			}
			if k == "count" || k == "active-count" || k == "max-unavailable" || k == "size-mib" || k == "vcpus" || k == "memory-mib" {
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
corpus init DIR [--title TEXT] [--language TAG] | corpus lint DIR (local, no API)
login --enrollment-file FILE|- | login --key-file PATH | login --token-file FILE|- | session renew | logout
status [--watch] | doctor | support export --output-file FILE
operation show|wait ID [--type operation|deployment|rollout|harness-import|invocation|volume-growth|activation|revocation|corpus-build] [--app APP_ID]
install [--ssh USER@HOST] [--plan-only] (see install --help)
update check|plan|apply | self update | host operation show|wait | restore
app verify APP_ID [--issuer-ca PEM_FILE]
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
	if a.method != "POST" {
		return false
	}
	u, err := url.ParseRequestURI(a.path)
	if err != nil {
		return false
	}
	p := u.Path
	return p == "/v1/applications" || strings.HasPrefix(p, "/v1/applications/") && (strings.HasSuffix(p, "/rotate") || strings.HasSuffix(p, "/invitations")) || strings.HasSuffix(p, "/tokens")
}
