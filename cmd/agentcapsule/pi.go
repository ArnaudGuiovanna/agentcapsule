package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry/reference"
)

const piHelp = `Usage: agentcapsule [--context NAME] pi COMMAND

On the Linux host, authorize the GitHub source and get the signed package references:
  agentcapsule host pi enable --corpus-repo OWNER/REPOSITORY > pi-host.json
Use a platform operator context to import both packages and wait for verification:
  agentcapsule --context platform pi import --file pi-host.json

In the organization context, create and review the corpus with "corpus create",
"corpus build", "corpus-build files" and "corpus-build publish". Publish the
agent template, then use "deployment plan" and "deployment apply":
  agentcapsule pi template NAME --release TAG --alias ALIAS --corpus NAME --corpus-version N [--mount NAME] [--a2a]
Each agent receives 1 vCPU, 1024 MiB of RAM, a writable 1024 MiB disk and a
read-only corpus. --a2a requests discovery and delegation. The receiving
agent's directory visibility and consent policy remain under operator control.

Choose model settings for invocations in this workstation context:
  agentcapsule pi profile set ALIAS --provider capsule-openai|capsule-anthropic --context-window N --max-output-tokens N
  agentcapsule pi profile show ALIAS
  agentcapsule agent invoke AGENT --pi-profile ALIAS --file REQUEST --watch --text
  agentcapsule pi status AGENT [--text]
`

// Pi profiles belong to this workstation's organization context. The control
// part travels with a single invocation; it grants no access to model aliases.
type piProfile struct {
	Provider        string `json:"provider"`
	ContextWindow   int    `json:"context_window"`
	MaxOutputTokens int    `json:"max_output_tokens"`
}

func (p piProfile) validate() error {
	if p.Provider != "capsule-openai" && p.Provider != "capsule-anthropic" {
		return errors.New("select --provider capsule-openai or capsule-anthropic")
	}
	if p.ContextWindow < 1024 || p.ContextWindow > 2147483647 ||
		p.MaxOutputTokens < 1 || p.MaxOutputTokens > 1000000 || p.MaxOutputTokens >= p.ContextWindow {
		return errors.New("expected a context window of 1024..2147483647 and an output limit of 1..1000000 below that window")
	}
	return nil
}

func (cli console) piProfileCommand(dir, name string, pos []string, o options) error {
	if len(pos) != 2 || (pos[0] != "set" && pos[0] != "show") || !corpusmeta.ValidAlias(pos[1]) {
		return usageError{errors.New("use pi profile set|show ALIAS")}
	}
	unlock, err := lockConfig(filepath.Join(dir, "lock-"+name))
	if err != nil {
		return err
	}
	defer unlock()
	c, err := loadContext(dir, name)
	if err != nil {
		return err
	}
	if c.Kind != "organization" {
		return usageError{errors.New("a Pi model profile needs an organization context")}
	}
	alias := pos[1]
	var p piProfile
	if pos[0] == "set" {
		p.Provider = o.take("provider")
		p.ContextWindow, err = strconv.Atoi(o.take("context-window"))
		if err != nil {
			return usageError{errors.New("--context-window must be an integer")}
		}
		p.MaxOutputTokens, err = strconv.Atoi(o.take("max-output-tokens"))
		if err != nil {
			return usageError{errors.New("--max-output-tokens must be an integer")}
		}
		if err = p.validate(); err != nil {
			return usageError{err}
		}
	}
	if err = o.done(); err != nil {
		return usageError{err}
	}
	if pos[0] == "set" {
		if c.PiProfiles == nil {
			c.PiProfiles = make(map[string]piProfile)
		}
		c.PiProfiles[alias] = p
		if err = saveContext(dir, name, c); err != nil {
			return err
		}
	} else {
		var found bool
		if p, found = c.PiProfiles[alias]; !found {
			return fmt.Errorf("no Pi profile for %q in this context", alias)
		}
	}
	return cli.print(struct {
		Alias string `json:"alias"`
		piProfile
	}{alias, p}, "")
}

func piInvocation(raw []byte, c connection, alias string, status bool) ([]byte, error) {
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil || body == nil {
		return nil, errors.New("invalid invocation body")
	}
	control := map[string]any{"action": "status"}
	var content []json.RawMessage
	if status {
		if len(body) != 0 {
			return nil, errors.New("pi status accepts no invocation body")
		}
	} else {
		p, ok := c.PiProfiles[alias]
		if !ok {
			return nil, fmt.Errorf("no Pi profile for %q in this context; use pi profile set", alias)
		}
		if err := p.validate(); err != nil {
			return nil, err
		}
		if json.Unmarshal(body["content"], &content) != nil || len(content) == 0 {
			return nil, errors.New("--pi-profile requires a nonempty content array")
		}
		control = map[string]any{"action": "invoke", "alias": alias, "provider": p.Provider,
			"context_window": p.ContextWindow, "max_output_tokens": p.MaxOutputTokens}
	}
	part, err := json.Marshal(map[string]any{"type": "json", "json": map[string]any{"agentcapsule_pi": control}})
	if err != nil {
		return nil, err
	}
	body["content"], err = json.Marshal(append([]json.RawMessage{part}, content...))
	if err != nil {
		return nil, err
	}
	return json.Marshal(body)
}

// A status query returns a small document even if streaming deltas is disabled.
// Wait for its completion, then read the result under the original identity.
func (cli console) piStatusResult(ctx context.Context, api *client, id string, textOnly bool) error {
	route := "/v1/invocations/" + id
	watcher := cli
	watcher.out = io.Discard
	if err := watcher.watchInvocation(ctx, api, route+"/events", true); err != nil {
		return err
	}
	token := api.connection.Token
	if api.connection.SigningKey != "" {
		var err error
		token, err = signPersonal(api.connection.SigningKey, api.connection.Organization)
		if err != nil {
			return err
		}
	}
	res, err := api.request(ctx, "GET", route+"/result", "", token, nil)
	if err != nil {
		return err
	}
	var result struct{ Content []struct{ Type, Text string } }
	var status struct {
		Version int             `json:"version"`
		Last    json.RawMessage `json:"last_compaction"`
	}
	invalid := errors.New("the agent did not return a Pi compaction status")
	if json.Unmarshal(res.Data, &result) != nil || len(result.Content) != 1 || result.Content[0].Type != "text" ||
		json.Unmarshal([]byte(result.Content[0].Text), &status) != nil || status.Version != 1 || status.Last == nil {
		return invalid
	}
	if string(status.Last) != "null" {
		var event struct {
			Outcome string `json:"outcome"`
			Reason  string `json:"reason"`
			Before  *int64 `json:"tokens_before,omitempty"`
			After   *int64 `json:"estimated_tokens_after,omitempty"`
		}
		if json.Unmarshal(status.Last, &event) != nil ||
			!slices.Contains([]string{"completed", "failed", "aborted"}, event.Outcome) ||
			!slices.Contains([]string{"manual", "threshold", "overflow"}, event.Reason) ||
			(event.Before != nil && *event.Before < 0) || (event.After != nil && *event.After < 0) {
			return invalid
		}
		// Return only the documented diagnostic fields.
		status.Last, err = json.Marshal(event)
		if err != nil {
			return err
		}
	}
	if textOnly {
		return json.NewEncoder(cli.out).Encode(status)
	}
	return cli.print(status, res.RequestID)
}

var piRelease = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?$`)

const piRegistry = "ghcr.io/arnaudguiovanna/agentcapsule/runtime"

func piTemplate(args []string, o options) ([]byte, error) {
	release, alias, corpus := o.take("release"), o.take("alias"), o.take("corpus")
	version, err := strconv.Atoi(o.take("corpus-version"))
	if len(args) != 1 || !validName(args[0]) || !piRelease.MatchString(release) || !corpusmeta.ValidAlias(alias) ||
		!corpusmeta.ValidName(corpus) || err != nil || !corpusmeta.ValidVersion(int64(version)) {
		return nil, errors.New("use pi template NAME --release TAG --alias ALIAS --corpus NAME --corpus-version N [--mount NAME] [--a2a]")
	}
	mount := o.take("mount")
	if mount == "" {
		mount = corpusmeta.DefaultMount(corpus)
	}
	if !corpusmeta.ValidMount(mount) {
		return nil, errors.New("specify --mount with 1..63 lowercase letters, digits, underscores or hyphens, starting with a letter or digit")
	}
	caps := []string{"llm.invoke", "stream.output"}
	if o.take("a2a") != "" {
		caps = append(caps, "agents.discover", "agents.delegate")
	}
	if err = o.done(); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"name": args[0], "system_image": "pi-linux@" + release[1:],
		"harness":     map[string]string{"name": "pi-agent", "version": release[1:]},
		"resources":   map[string]int{"vcpus": 1, "memory_mib": 1024, "data_volume_mib": 1024},
		"llm_profile": alias, "capabilities": caps, "corpora": []map[string]any{{"name": corpus, "mount": mount, "version": version}}})
}

type piReleaseEntry struct{ Name, Version, Digest, Signer, Base string }

type piHostReceipt struct {
	Signer   string            `json:"signer"`
	Schema   string            `json:"schema"`
	Release  string            `json:"release"`
	Packages map[string]string `json:"packages"`
	Image    struct {
		Reference string   `json:"reference"`
		Kernel    string   `json:"kernel_digest"`
		Initrd    string   `json:"initrd_digest"`
		Features  []string `json:"features"`
	} `json:"system_image"`
}

func (cli console) piImport(ctx context.Context, api *client, o options) error {
	source := o.take("file")
	if api.connection.Kind != "platform" || source == "" {
		return usageError{errors.New("pi import requires a platform context and --file from host pi enable")}
	}
	if err := o.done(); err != nil {
		return usageError{err}
	}
	raw, err := readSource(source, cli.in, false)
	if err != nil {
		return err
	}
	var host piHostReceipt
	if json.Unmarshal(raw, &host) != nil || host.Schema != "agentcapsule.pi-host/v1" || !reference.ValidDigest(host.Signer) || !piRelease.MatchString(host.Release) ||
		host.Image.Reference != "pi-linux@"+host.Release[1:] || !reference.ValidDigest(host.Image.Kernel) || !reference.ValidDigest(host.Image.Initrd) ||
		!slices.Equal(host.Image.Features, []string{"corpus.mount"}) || len(host.Packages) != 2 {
		return usageError{errors.New("invalid host pi enable receipt")}
	}
	names := []string{"agentcapsule-corpus-builder", "pi-agent"}
	for _, name := range names {
		ref, err := reference.Parse(host.Packages[name])
		if err != nil || ref.Registry+"/"+ref.Repository != piRegistry || ref.Tag != "" || host.Packages[names[0]] == host.Packages[names[1]] {
			return usageError{errors.New("expected two distinct digest-pinned official Pi packages")}
		}
	}
	token := api.connection.Token
	if err := api.compatible(ctx); err != nil {
		return err
	}
	if _, err := api.verifyToken(ctx, token); err != nil {
		return err
	}
	image, err := json.Marshal(host.Image)
	if err != nil {
		return err
	}
	if _, err = api.request(ctx, "POST", "/v1/system-images", "pi-image-"+host.Release, token, image); err != nil {
		return err
	}
	imports := make(map[string]string)
	for _, name := range names {
		body, _ := json.Marshal(map[string]string{"reference": host.Packages[name]})
		// The server coalesces pending and already successful imports by digest.
		// A fresh request also permits retry after a terminal download failure.
		r, err := api.request(ctx, "POST", "/v1/harness-imports", randomKey(), token, body)
		if err != nil {
			return err
		}
		var imp struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(r.Data, &imp) != nil || !codePattern.MatchString(imp.ID) {
			return errors.New("invalid import identifier")
		}
		imports[name] = imp.ID
		fmt.Fprintf(cli.errout, "harness=%s import=%s\n", name, imp.ID)
	}
	for _, name := range names {
		id := imports[name]
		for {
			r, err := api.request(ctx, "GET", "/v1/harness-imports/"+id, "", token, nil)
			if err != nil {
				return err
			}
			state, disposition, err := operationState(r.Data)
			if err != nil {
				return err
			}
			if disposition == "failure" {
				return terminalFailure{state: fmt.Sprintf("%s (registry show %s)", state, id)}
			}
			if disposition == "success" {
				break
			}
			if err = wait(ctx, 2*time.Second); err != nil {
				return err
			}
		}
	}
	// A digest may have been imported before this host enabled the trusted
	// catalog. Confirm the signer actually recorded by the verifying worker.
	r, err := api.request(ctx, "GET", "/v1/harness-releases", "", token, nil)
	if err != nil {
		return err
	}
	var releases struct {
		Items []piReleaseEntry `json:"items"`
	}
	if json.Unmarshal(r.Data, &releases) != nil {
		return errors.New("invalid registry release list")
	}
	for _, name := range names {
		found := slices.ContainsFunc(releases.Items, func(item piReleaseEntry) bool {
			return item.Name == name && item.Version == host.Release[1:] && item.Signer == host.Signer &&
				item.Base == "agentcapsule-guest/2" && host.Packages[name] == piRegistry+"@"+item.Digest
		})
		if !found {
			return fmt.Errorf("no active release of %s matches the catalog's version, signature, digest and guest ABI", name)
		}
	}
	return cli.print(map[string]any{"release": host.Release, "system_image": host.Image.Reference, "imports": imports, "state": "ready"}, "")
}
