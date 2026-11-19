// Command agentcapsule administers AgentCapsule over HTTPS.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/hostops"
)

type terminalFailure struct{ state string }

func (e terminalFailure) Error() string { return "operation ended with " + e.state }

type usageError struct{ error }
type console struct {
	in          io.Reader
	out, errout io.Writer
	contextName string
	outputFile  string
}

func (cli console) print(v any, id string) error {
	envelope := struct {
		Version    int       `json:"version"`
		Context    string    `json:"context,omitempty"`
		ObservedAt time.Time `json:"observed_at"`
		RequestID  string    `json:"request_id,omitempty"`
		Data       any       `json:"data"`
	}{1, cli.contextName, time.Now().UTC(), id, v}
	if cli.outputFile != "" {
		b, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		// Only create new outputs. Existing configuration, credentials and
		// support archives must survive a mistaken destination or failed write.
		f, err := createPrivateFile(cli.outputFile)
		if err != nil {
			return err
		}
		if _, err = f.Write(append(b, '\n')); err == nil {
			err = f.Sync()
		}
		cerr := f.Close()
		if err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(cli.outputFile)
		}
		return err
	}
	return json.NewEncoder(cli.out).Encode(envelope)
}
func randomKey() string {
	var b [32]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func run(ctx context.Context, args []string, in io.Reader, out, errout io.Writer) error {
	cli := console{in: in, out: out, errout: errout}
	if len(args) == 1 && args[0] == "--version" {
		args = []string{"version"}
	}
	if handled, err := runHostCommand(ctx, args, in, out, errout); handled {
		return err
	}
	pos, o, err := parse(args)
	if err != nil {
		return usageError{err}
	}
	if len(pos) == 0 || o.take("help") != "" || pos[0] == "help" {
		listCommands(out)
		return nil
	}
	o.take("json")
	o.take("non-interactive")
	cli.contextName = o.take("context")
	cli.outputFile = o.take("output-file")
	if len(pos) == 1 && pos[0] == "version" {
		if err = o.done(); err != nil {
			return usageError{err}
		}
		return cli.print(map[string]any{"release": hostops.Version, "api_major": 1, "cli_protocol": 1}, "")
	}
	if pos[0] == "identity" {
		return cli.identity(pos, o)
	}
	dir, err := configDir()
	if err != nil {
		return err
	}
	if pos[0] == "context" {
		return cli.contextCommand(dir, pos[1:], o)
	}
	name, err := currentName(dir, cli.contextName)
	if err != nil {
		return err
	}
	cli.contextName = name
	identityCommand := pos[0] == "login" || pos[0] == "logout" || strings.Join(pos, " ") == "session renew"
	if identityCommand {
		unlock, err := lockConfig(filepath.Join(dir, "lock-"+name))
		if err != nil {
			return fmt.Errorf("context busy: %w", err)
		}
		defer unlock()
	}
	c, err := loadContext(dir, name)
	if err != nil {
		return err
	}
	api, err := newClient(c)
	if err != nil {
		return err
	}
	defer api.http.CloseIdleConnections()
	cmd := strings.Join(pos, " ")
	if cmd == "doctor" || cmd == "support export" || cmd == "status" {
		watch := o.take("watch") != ""
		if watch && (cmd != "status" || cli.outputFile != "") {
			return errors.New("--watch requires status on stdout")
		}
		if err = o.done(); err != nil {
			return usageError{err}
		}
		return cli.status(ctx, api, cmd, watch)
	}
	if err = api.compatible(ctx); err != nil {
		return err
	}
	if identityCommand {
		return cli.sessionCommand(ctx, dir, name, api, strings.Join(pos, " "), o)
	}
	if c.SigningKey != "" {
		c.Token, err = signPersonal(c.SigningKey, c.Organization)
		if err != nil {
			return err
		}
		api.connection.Token = c.Token
	}
	if _, err = api.verifyToken(ctx, c.Token); err != nil {
		return err
	}
	key := o.take("idempotency-key")
	a, err := buildAction(pos, o, in)
	if err != nil {
		return usageError{err}
	}
	if cli.outputFile == "" && returnsCredential(a) {
		return usageError{errors.New("this command issues a credential; choose a private --output-file PATH")}
	}
	if a.method != "GET" {
		for _, r := range key {
			if r < 33 || r > 126 {
				return usageError{errors.New("idempotency key must be printable ASCII without spaces")}
			}
		}
		if len(key) > 200 {
			return usageError{errors.New("idempotency key is too long")}
		}
		if key == "" {
			key = randomKey()
		}
		fmt.Fprintf(errout, "context=%s target=%s method=%s path=%s idempotency_key=%s\n", name, c.URL, a.method, strings.Split(a.path, "?")[0], key)
	}
	for {
		if c.SigningKey != "" {
			c.Token, err = signPersonal(c.SigningKey, c.Organization)
			if err != nil {
				return err
			}
		}
		r, err := api.request(ctx, a.method, a.path, key, c.Token, a.body)
		if err != nil {
			return err
		}
		if a.name == "app connection" {
			return cli.appConnection(c, r)
		}
		if a.name != "operation wait" {
			return cli.print(r.Data, r.RequestID)
		}
		state, disposition, err := operationState(r.Data)
		if err != nil {
			return err
		}
		if disposition != "pending" {
			if err := cli.print(r.Data, r.RequestID); err != nil {
				return err
			}
			if disposition == "failure" {
				return terminalFailure{state}
			}
			return nil
		}
		delay, _ := strconv.Atoi(r.RetryAfter)
		if delay < 1 {
			delay = 1
		}
		if err = wait(ctx, time.Duration(min(delay, 60))*time.Second); err != nil {
			return err
		}
	}
}
func operationState(data json.RawMessage) (string, string, error) {
	var op struct {
		Status string `json:"status"`
		State  string `json:"state"`
		Stage  string `json:"stage"`
	}
	if err := json.Unmarshal(data, &op); err != nil {
		return "", "", errors.New("invalid operation response")
	}
	state := op.Status
	if state == "" {
		state = op.State
	}
	if state == "" {
		state = op.Stage
	}
	switch strings.ToLower(state) {
	case "ready", "succeeded", "completed":
		return state, "success", nil
	case "failed", "cancelled", "canceled", "expired", "lost", "rejected", "paused", "disabled", "refused":
		return state, "failure", nil
	case "pending", "running", "accepted", "queued", "in_progress", "planned", "provisioning", "starting", "verifying", "importing", "working", "scheduled", "capturing", "restoring", "preparing", "waiting_capacity":
		return state, "pending", nil
	default:
		return "", "", fmt.Errorf("unrecognized operation state %q", state)
	}
}

func (cli console) appConnection(c connection, r reply) error {
	// Select the fields a frontend can receive even if the registration API
	// gains additional administrative metadata later.
	var app struct {
		ID           string   `json:"id"`
		Tenant       string   `json:"tenant_id"`
		Issuer       string   `json:"issuer"`
		ClientID     string   `json:"client_id"`
		Audience     string   `json:"audience"`
		RedirectURIs []string `json:"redirect_uris"`
		Policies     []string `json:"policy_ids"`
		Status       string   `json:"status"`
	}
	if json.Unmarshal(r.Data, &app) != nil || app.ID == "" || app.Issuer == "" || app.Tenant != c.Organization {
		return errors.New("invalid application connection response")
	}
	return cli.print(map[string]any{"api_url": c.URL, "application_id": app.ID, "organization_id": app.Tenant, "issuer": app.Issuer,
		"discovery_url": strings.TrimRight(app.Issuer, "/") + "/.well-known/openid-configuration", "client_id": app.ClientID,
		"audience": app.Audience, "redirect_uris": app.RedirectURIs, "policy_ids": app.Policies, "status": app.Status,
		"response_type": "code", "code_challenge_method": "S256"}, r.RequestID)
}

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func (cli console) contextCommand(dir string, pos []string, o options) error {
	if len(pos) == 1 && pos[0] == "list" {
		if err := o.done(); err != nil {
			return usageError{err}
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		names := []string{}
		for _, e := range entries {
			n := e.Name()
			if strings.HasPrefix(n, "context-") && strings.HasSuffix(n, ".json") {
				names = append(names, n[8:len(n)-5])
			}
		}
		active, _ := currentName(dir, "")
		return cli.print(map[string]any{"items": names, "current": active}, "")
	}
	if len(pos) != 2 || !validName(pos[1]) {
		return errors.New("context expects add/use/show and a valid name")
	}
	name := pos[1]
	cli.contextName = name
	switch pos[0] {
	case "add":
		c := connection{URL: strings.TrimRight(o.take("url"), "/"), Kind: o.take("kind"), Organization: o.take("organization"), CA: o.take("ca")}
		if err := o.done(); err != nil {
			return usageError{err}
		}
		if err := c.validate(); err != nil {
			return err
		}
		if c.CA != "" {
			abs, err := filepath.Abs(c.CA)
			if err != nil {
				return err
			}
			c.CA = abs
		}
		unlock, err := lockConfig(filepath.Join(dir, "lock-"+name))
		if err != nil {
			return err
		}
		defer unlock()
		_, err = os.Lstat(contextPath(dir, name))
		if !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return errors.New("context already exists")
			}
			return err
		}
		if err = saveContext(dir, name, c); err != nil {
			return err
		}
		return cli.print(c.public(), "")
	case "use", "show":
		if err := o.done(); err != nil {
			return usageError{err}
		}
		c, err := loadContext(dir, name)
		if err != nil {
			return err
		}
		if pos[0] == "use" {
			if err = writeFile(filepath.Join(dir, "current"), []byte(name)); err != nil {
				return err
			}
		}
		return cli.print(c.public(), "")
	default:
		return errors.New("unknown context command")
	}
}

func (cli console) sessionCommand(ctx context.Context, dir, name string, api *client, cmd string, o options) error {
	c := api.connection
	if cmd == "logout" {
		if err := o.done(); err != nil {
			return usageError{err}
		}
		if c.Kind == "platform" {
			who, err := api.verifyToken(ctx, c.Token)
			var denied *apiError
			if err != nil && !(errors.As(err, &denied) && denied.Status == 401) {
				return err
			}
			if err == nil {
				var s struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(who.Data, &s) != nil || !validName(s.ID) {
					return errors.New("invalid platform session")
				}
				r, err := api.request(ctx, "POST", "/v1/platform/sessions/"+s.ID+"/revoke", randomKey(), c.Token, []byte("{}"))
				if err != nil {
					return err
				}
				c.Token = ""
				c.Pending = ""
				if err = saveContext(dir, name, c); err != nil {
					return err
				}
				return cli.print(r.Data, r.RequestID)
			}
		}
		c.Token = ""
		c.SigningKey = ""
		c.Pending = ""
		if err := saveContext(dir, name, c); err != nil {
			return err
		}
		return cli.print(map[string]string{"status": "local_session_removed"}, "")
	}
	sf, ef, kf := o.take("token-file"), o.take("enrollment-file"), o.take("key-file")
	if err := o.done(); err != nil {
		return usageError{err}
	}
	var proof string
	switch cmd {
	case "login":
		if kf != "" {
			if c.Kind != "organization" || sf != "" || ef != "" {
				return errors.New("login --key-file requires an organization context and one identity source")
			}
			path, err := filepath.Abs(kf)
			if err != nil {
				return err
			}
			for attempt := 0; attempt < 2; attempt++ {
				token, err := signPersonal(path, c.Organization)
				if err != nil {
					return err
				}
				who, err := api.verifyToken(ctx, token)
				var rejected *apiError
				if attempt == 0 && errors.As(err, &rejected) && rejected.Status == 401 {
					if err = wait(ctx, time.Second); err != nil {
						return err
					}
					continue
				}
				if err != nil {
					return err
				}
				c.SigningKey, c.Token, c.Pending = path, "", ""
				if err = saveContext(dir, name, c); err != nil {
					return err
				}
				return cli.print(who.Data, who.RequestID)
			}
		}
		if (sf == "") == (ef == "") {
			return errors.New("login requires one of --token-file or --enrollment-file")
		}
		file := sf
		if ef != "" {
			file = ef
		}
		b, err := readSource(file, cli.in, true)
		if err != nil {
			return err
		}
		proof = strings.TrimSpace(string(b))
		if sf != "" {
			who, err := api.verifyToken(ctx, proof)
			if err != nil {
				return err
			}
			c.SigningKey = ""
			c.Token = proof
			c.Pending = ""
			if err = saveContext(dir, name, c); err != nil {
				return err
			}
			return cli.print(who.Data, who.RequestID)
		}
		if !strings.HasPrefix(proof, "acpe_") {
			return errors.New("invalid enrollment proof")
		}
	case "session renew":
		if sf != "" || ef != "" || kf != "" {
			return errors.New("renew uses the context credential")
		}
		proof = c.Token
	default:
		return errors.New("invalid session command")
	}
	if c.Kind != "platform" || proof == "" {
		return errors.New("enrollment and renewal require a platform context and proof")
	}
	if c.Pending == "" {
		c.Pending = "acpp_" + randomKey()
		if err := saveContext(dir, name, c); err != nil {
			return err
		}
	} else {
		// A previous request may have committed before the connection broke.
		who, err := api.verifyToken(ctx, c.Pending)
		if err == nil {
			c.Token, c.Pending = c.Pending, ""
			if err = saveContext(dir, name, c); err != nil {
				return err
			}
			return cli.print(who.Data, who.RequestID)
		}
		var rejected *apiError
		if !errors.As(err, &rejected) || rejected.Status != 401 {
			return err
		}
	}
	hash := sha256.Sum256([]byte(c.Pending))
	digest := hex.EncodeToString(hash[:])
	body, _ := json.Marshal(map[string]any{"token_sha256": digest, "replace_current": true})
	fmt.Fprintf(cli.errout, "context=%s target=%s action=session_exchange\n", name, c.URL)
	r, err := api.request(ctx, "POST", "/v1/platform/sessions", "session-"+digest, proof, body)
	if err != nil {
		return err
	}
	c.Token, c.Pending = c.Pending, ""
	if err = saveContext(dir, name, c); err != nil {
		return err
	}
	return cli.print(r.Data, r.RequestID)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	if err == nil {
		return
	}
	code := 1
	var api *apiError
	var usage usageError
	var failed terminalFailure
	var detail any = err.Error()
	switch {
	case errors.As(err, &api):
		detail = api
		if api.Status == 401 || api.Status == 403 {
			code = 3
		} else {
			code = 4
		}
	case errors.As(err, &usage):
		code = 2
	case errors.As(err, &failed):
		code = 5
	case errors.Is(err, context.Canceled):
		code = 130
	}
	_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"version": 1, "error": detail})
	os.Exit(code)
}
