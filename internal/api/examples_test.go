package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// docs/api/examples.md shows every MVP feature used with curl, without a UI
// (EXT-008). TestHTTPExamplesRunAsWritten runs that page against the API
// over HTTPS on PostgreSQL: each shell block in order, each answer checked
// against the one the page shows and against openapi/openapi.yaml. A note
// "<!-- worker: ... -->" marks what the worker or another agent does at that
// point; the test plays it. A command the test does not understand fails it,
// so the page shows only what ran.

const examplesDoc = "../../docs/api/examples.md"

// exampleBlock is a fenced block of the page ("sh" or "http") or a worker
// note.
type exampleBlock struct {
	line       int
	kind, text string
}

var (
	workerNote      = regexp.MustCompile(`^<!-- worker: (.+) -->$`)
	shellVariable   = regexp.MustCompile(`^(\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)`)
	shellAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	curlQuietFlags  = regexp.MustCompile(`^-[fsS]+$`)
	jqStep          = regexp.MustCompile(`\.[A-Za-z_][A-Za-z0-9_]*|\[[0-9]+\]|\.`)
)

func readExamples(t *testing.T) []exampleBlock {
	t.Helper()
	raw, err := os.ReadFile(examplesDoc)
	if err != nil {
		t.Fatal(err)
	}
	var blocks []exampleBlock
	var open *exampleBlock
	for i, line := range strings.Split(string(raw), "\n") {
		switch {
		case open != nil && line == "```":
			blocks, open = append(blocks, *open), nil
		case open != nil:
			open.text += line + "\n"
		case strings.HasPrefix(line, "```"):
			kind := strings.TrimPrefix(line, "```")
			if kind != "sh" && kind != "http" {
				t.Fatalf("%s:%d: a %q block; the page holds only sh and http blocks, which run", examplesDoc, i+1, kind)
			}
			open = &exampleBlock{line: i + 1, kind: kind}
		case workerNote.MatchString(line):
			blocks = append(blocks, exampleBlock{line: i + 1, kind: "worker", text: workerNote.FindStringSubmatch(line)[1]})
		}
	}
	if open != nil {
		t.Fatalf("%s:%d: the block is not closed", examplesDoc, open.line)
	}
	return blocks
}

// exampleAnswer is one HTTP answer to a curl command of the page.
type exampleAnswer struct {
	method, path string
	status       int
	header       http.Header
	body         []byte
}

// exampleShell runs the small part of the shell the page uses: one command
// per line (a final backslash continues it), quotes, $NAME, NAME=$(...),
// export, comments, and pipelines of curl and jq.
type exampleShell struct {
	vars     map[string]string
	provided map[string]string // the reader's own values, which export names
	base     string
	client   *http.Client
	doc      *openAPIDoc
	answers  []exampleAnswer // of the current block
	checks   []error         // answers that do not match the contract
	called   map[string]bool // "METHOD /v1/documented/{path}"
}

var errShell = errors.New("not in the shell the examples may use")

// splitCommands splits a block into its commands.
func splitCommands(src string) ([]string, error) {
	var out []string
	var cur strings.Builder
	quote, depth := byte(0), 0
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
			cur.WriteByte(c)
		case c == '\\' && i+1 < len(src) && src[i+1] == '\n':
			i++
		case c == '\\' && i+1 < len(src):
			cur.WriteByte(c)
			cur.WriteByte(src[i+1])
			i++
		case quote == '"':
			if c == '$' && i+1 < len(src) && src[i+1] == '(' {
				return nil, fmt.Errorf("%w: $( ) inside double quotes", errShell)
			}
			if c == '"' {
				quote = 0
			}
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == '$' && i+1 < len(src) && src[i+1] == '(':
			depth++
			cur.WriteString("$(")
			i++
		case c == ')' && depth > 0:
			depth--
			cur.WriteByte(c)
		case c == '#' && depth == 0 && (i == 0 || strings.ContainsRune(" \t\n", rune(src[i-1]))):
			for i+1 < len(src) && src[i+1] != '\n' {
				i++
			}
		case c == '\n' && depth == 0:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	if quote != 0 || depth != 0 {
		return nil, fmt.Errorf("%w: unclosed quote or $(", errShell)
	}
	flush()
	return out, nil
}

// variable reads $NAME or ${NAME} at the start of s and returns its length.
func (sh *exampleShell) variable(s string) (string, int, error) {
	name := shellVariable.FindString(s)
	if name == "" {
		return "", 0, fmt.Errorf("%w: a lone $", errShell)
	}
	value, ok := sh.vars[strings.Trim(name, "{}")]
	if !ok {
		return "", 0, fmt.Errorf("$%s is not set at this point of the page", strings.Trim(name, "{}"))
	}
	return value, len(name), nil
}

// closing finds the parenthesis that closes the $( opened before start.
func closing(s string, start int) (int, error) {
	depth, quote := 1, byte(0)
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			if depth--; depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("%w: unclosed $(", errShell)
}

// stages expands a command into the words of each stage of its pipeline.
func (sh *exampleShell) stages(cmd string) ([][]string, error) {
	var stages [][]string
	var words []string
	var word strings.Builder
	in := false
	end := func() {
		if in {
			words = append(words, word.String())
			word.Reset()
			in = false
		}
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			end()
		case c == '|':
			end()
			stages, words = append(stages, words), nil
		case c == '\'':
			j := strings.IndexByte(cmd[i+1:], '\'')
			if j < 0 {
				return nil, fmt.Errorf("%w: unclosed '", errShell)
			}
			word.WriteString(cmd[i+1 : i+1+j])
			i, in = i+1+j, true
		case c == '"':
			for i++; i < len(cmd) && cmd[i] != '"'; i++ {
				switch {
				case cmd[i] == '\\' && i+1 < len(cmd) && strings.ContainsRune("$\"\\`", rune(cmd[i+1])):
					word.WriteByte(cmd[i+1])
					i++
				case cmd[i] == '$':
					value, n, err := sh.variable(cmd[i+1:])
					if err != nil {
						return nil, err
					}
					word.WriteString(value)
					i += n
				case cmd[i] == '`':
					return nil, fmt.Errorf("%w: backquotes", errShell)
				default:
					word.WriteByte(cmd[i])
				}
			}
			if i >= len(cmd) {
				return nil, fmt.Errorf("%w: unclosed \"", errShell)
			}
			in = true
		case c == '\\' && i+1 < len(cmd):
			word.WriteByte(cmd[i+1])
			i, in = i+1, true
		case c == '$' && strings.HasPrefix(cmd[i:], "$("):
			// Only a whole assignment, NAME=$(...): no word splitting.
			if w := word.String(); shellAssignment.FindString(w) != w || w == "" || len(words) > 0 {
				return nil, fmt.Errorf("%w: $( ) outside NAME=$(...)", errShell)
			}
			j, err := closing(cmd, i+2)
			if err != nil {
				return nil, err
			}
			out, err := sh.run(cmd[i+2 : j])
			if err != nil {
				return nil, err
			}
			word.WriteString(strings.TrimRight(out, "\n"))
			i, in = j, true
		case c == '$':
			value, n, err := sh.variable(cmd[i+1:])
			if err != nil {
				return nil, err
			}
			word.WriteString(value)
			i, in = i+n, true
		case strings.ContainsRune(";&<>()`*?[]{}~!", rune(c)):
			return nil, fmt.Errorf("%w: %q outside quotes", errShell, c)
		default:
			word.WriteByte(c)
			in = true
		}
	}
	end()
	return append(stages, words), nil
}

// run runs a command and returns what it prints.
func (sh *exampleShell) run(cmd string) (string, error) {
	stages, err := sh.stages(cmd)
	if err != nil {
		return "", err
	}
	out := ""
	for i, words := range stages {
		if len(words) == 0 {
			return "", fmt.Errorf("%w: an empty command", errShell)
		}
		switch {
		case words[0] == "curl" && i == 0:
			out, err = sh.curl(words[1:])
		case words[0] == "jq" && i > 0:
			out, err = jq(words[1:], out)
		case i == 0 && len(stages) == 1 && words[0] == "export":
			for _, w := range words[1:] {
				name, _, ok := strings.Cut(w, "=")
				value, mine := sh.provided[name]
				if !ok || !mine {
					return "", fmt.Errorf("export %s: not one of the reader's own values the test gives (%v)", w, sortedKeys(sh.provided))
				}
				sh.vars[name] = value
			}
		case i == 0 && len(stages) == 1 && len(words) == 1 && shellAssignment.MatchString(words[0]):
			name, value, _ := strings.Cut(words[0], "=")
			if value == "" || value == "null" {
				return "", fmt.Errorf("%s is empty: the command gave nothing", name)
			}
			sh.vars[name] = value
		default:
			return "", fmt.Errorf("%w: %s", errShell, words[0])
		}
		if err != nil {
			return "", err
		}
	}
	return out, nil
}

// curl sends one request as curl would with the options the page uses.
func (sh *exampleShell) curl(args []string) (string, error) {
	method, target, fail, quiet := "", "", false, false
	var body *string
	header := http.Header{}
	value := func(i int) (string, error) {
		if i+1 >= len(args) {
			return "", fmt.Errorf("curl %s: no value", args[i])
		}
		return args[i+1], nil
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-X" || a == "--request" || a == "-H" || a == "--header" || a == "-o" || a == "--output" ||
			a == "-d" || a == "--data" || a == "--data-raw" || a == "--data-binary":
			v, err := value(i)
			if err != nil {
				return "", err
			}
			i++
			switch a {
			case "-X", "--request":
				method = v
			case "-H", "--header":
				name, val, ok := strings.Cut(v, ":")
				if !ok {
					return "", fmt.Errorf("curl -H %q: not a header", v)
				}
				header.Add(strings.TrimSpace(name), strings.TrimSpace(val))
			case "-o", "--output":
				quiet = true
			default:
				if body != nil || (strings.HasPrefix(v, "@") && a != "--data-raw") {
					return "", fmt.Errorf("%w: curl %s %q", errShell, a, v)
				}
				body = &v
			}
		case a == "--fail" || a == "--silent" || a == "--show-error":
			fail = fail || a == "--fail"
		case curlQuietFlags.MatchString(a):
			fail = fail || strings.Contains(a, "f")
		case strings.HasPrefix(a, "-"):
			return "", fmt.Errorf("%w: curl %s", errShell, a)
		case target != "":
			return "", fmt.Errorf("curl: two URLs, %s and %s", target, a)
		default:
			target = a
		}
	}
	path, ok := strings.CutPrefix(target, sh.base)
	if !ok || !strings.HasPrefix(path, "/v1/") {
		return "", fmt.Errorf("curl %s: not a URL of the API ($API/v1/...)", target)
	}
	if method == "" {
		method = "GET"
		if body != nil {
			method = "POST"
		}
	}
	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(*body)
		if header.Get("Content-Type") == "" {
			header.Set("Content-Type", "application/x-www-form-urlencoded") // curl's default
		}
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return "", err
	}
	req.Header = header
	resp, err := sh.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	sh.answers = append(sh.answers, exampleAnswer{method: method, path: path, status: resp.StatusCode, header: resp.Header, body: out})
	if template, _ := sh.doc.operation(method, path); template != "" {
		sh.called[method+" "+template] = true
	}
	if err = sh.doc.checkAnswer(method, path, resp.StatusCode, out); err != nil {
		sh.checks = append(sh.checks, err)
	}
	if fail && resp.StatusCode >= 400 {
		return "", fmt.Errorf("curl --fail: %s %s answered %d: %s", method, path, resp.StatusCode, out)
	}
	if quiet {
		return "", nil
	}
	return string(out), nil
}

// jq applies a path filter (.a.b, .items[0].id) as jq would.
func jq(args []string, input string) (string, error) {
	raw, filter := false, ""
	for _, a := range args {
		switch {
		case a == "-r" || a == "--raw-output":
			raw = true
		case strings.HasPrefix(a, "-") || filter != "":
			return "", fmt.Errorf("%w: jq %s", errShell, a)
		default:
			filter = a
		}
	}
	var v any
	if err := json.Unmarshal([]byte(input), &v); err != nil {
		return "", fmt.Errorf("jq: the input is not JSON: %q", input)
	}
	steps := jqStep.FindAllString(filter, -1)
	if !strings.HasPrefix(filter, ".") || strings.Join(steps, "") != filter {
		return "", fmt.Errorf("%w: jq %s", errShell, filter)
	}
	for _, step := range steps {
		switch {
		case step == ".":
		case strings.HasPrefix(step, "["):
			n, _ := strconv.Atoi(strings.Trim(step, "[]"))
			list, _ := v.([]any)
			if n >= len(list) {
				return "null\n", nil
			}
			v = list[n]
		default:
			object, _ := v.(map[string]any)
			v = object[step[1:]]
		}
	}
	if s, ok := v.(string); ok && raw {
		return s + "\n", nil
	}
	out, err := json.Marshal(v)
	return string(out) + "\n", err
}

// matchShown checks an answer against the one the page shows. Objects may
// show only some fields; a string ending in "..." stands for any string
// that starts the same; a list ending in "..." for any longer list.
func matchShown(where string, shown, actual any) error {
	switch s := shown.(type) {
	case map[string]any:
		a, ok := actual.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: %v is not an object", where, actual)
		}
		for k, v := range s {
			got, ok := a[k]
			if !ok {
				return fmt.Errorf("%s.%s: absent from the answer", where, k)
			}
			if err := matchShown(where+"."+k, v, got); err != nil {
				return err
			}
		}
	case []any:
		a, ok := actual.([]any)
		if !ok {
			return fmt.Errorf("%s: %v is not a list", where, actual)
		}
		open := len(s) > 0 && s[len(s)-1] == "..."
		if open {
			s = s[:len(s)-1]
		}
		if len(a) < len(s) || !open && len(a) != len(s) {
			return fmt.Errorf("%s: %d items, the page shows %d", where, len(a), len(s))
		}
		for i := range s {
			if err := matchShown(fmt.Sprintf("%s[%d]", where, i), s[i], a[i]); err != nil {
				return err
			}
		}
	case string:
		a, ok := actual.(string)
		prefix, elided := strings.CutSuffix(s, "...")
		if !ok || (elided && !strings.HasPrefix(a, prefix)) || (!elided && a != s) {
			return fmt.Errorf("%s: %v, the page shows %q", where, actual, s)
		}
	default: // a number, a boolean or null: comparable, and of the same type
		if shown != actual {
			return fmt.Errorf("%s: %v, the page shows %v", where, actual, shown)
		}
	}
	return nil
}

// checkShown compares an answer with an http block: its status, the headers
// it shows, and its body.
func checkShown(block string, got exampleAnswer) error {
	head, body, _ := strings.Cut(block, "\n\n")
	lines := strings.Split(strings.TrimSpace(head), "\n")
	fields := strings.Fields(lines[0])
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return fmt.Errorf("the block does not start with a status line: %q", lines[0])
	}
	if fields[1] != strconv.Itoa(got.status) {
		return fmt.Errorf("%s %s answered %d, the page shows %s: %s", got.method, got.path, got.status, fields[1], got.body)
	}
	for _, line := range lines[1:] {
		name, value, _ := strings.Cut(line, ":")
		if v := got.header.Get(strings.TrimSpace(name)); v != strings.TrimSpace(value) {
			return fmt.Errorf("%s: %q, the page shows %q", strings.TrimSpace(name), v, strings.TrimSpace(value))
		}
	}
	if strings.TrimSpace(body) == "" {
		return nil
	}
	var shown, actual any
	if err := json.Unmarshal([]byte(body), &shown); err != nil {
		return fmt.Errorf("the page's answer is not JSON: %v", err)
	}
	if err := json.Unmarshal(got.body, &actual); err != nil {
		return fmt.Errorf("the answer is not JSON: %s", got.body)
	}
	if err := matchShown("answer", shown, actual); err != nil {
		return fmt.Errorf("%w; the answer was %s", err, got.body)
	}
	return nil
}

// examplesLab is an organization whose trust is installed, with the
// transit keys the worker's delivery needs, served over HTTPS.
type examplesLab struct {
	l       *apiDelegationFixture
	transit *controlplane.Transit
	owner   string
	shell   *exampleShell
}

func newExamplesLab(t *testing.T) *examplesLab {
	t.Helper()
	l, at, owner := apiAgentsLab(t)
	l.store.RecordAccessWith(&fakeAuthority{onReplica: true})
	transit, err := controlplane.NewTransit(l.store, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x45}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	server, err := NewForHostWithTransit(l.store, l.server.accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	server.SetDelegatedIdentityVerifier(l.verifier)
	l.server = server
	https := httptest.NewTLSServer(server)
	t.Cleanup(https.Close)
	return &examplesLab{l: l, transit: transit, owner: owner, shell: &exampleShell{
		vars: map[string]string{}, called: map[string]bool{}, base: https.URL, client: https.Client(), doc: loadOpenAPI(t),
		provided: map[string]string{
			"API":            https.URL,
			"ISSUER":         l.trust.Issuer,
			"PLATFORM_TOKEN": l.platform,
			"OWNER_TOKEN":    owner,
			"BOB_TOKEN":      l.sign(t, at, "bob-examples", "bob", allAgentScopes),
			"TOKEN_EXPIRES":  time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
			"AUDIT_FROM":     time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			"AUDIT_TO":       time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		}}}
}

// worker plays what the worker, or another agent, does at a note of the page.
func (x *examplesLab) worker(t *testing.T, note string) error {
	stages, err := x.shell.stages(note)
	if err != nil || len(stages) != 1 || len(stages[0]) == 0 {
		return fmt.Errorf("a worker note that is not a command: %q (%v)", note, err)
	}
	words, ctx := stages[0], t.Context()
	args := func(n int) error {
		if len(words) != n+1 {
			return fmt.Errorf("worker %s takes %d arguments", words[0], n)
		}
		return nil
	}
	switch words[0] {
	case "import": // NAME VERSION: the worker imports the package, whose manifest names it so.
		if err = args(2); err != nil {
			return err
		}
		job, err := x.l.store.ClaimHarnessImport(ctx, "examples-worker", time.Minute)
		if err != nil {
			return err
		}
		sum := sha256.Sum256([]byte(words[1] + words[2]))
		_, err = x.l.store.CompleteHarnessImport(ctx, job, controlplane.ImportedRelease{Name: words[1], Version: words[2],
			RootfsDigest: fmt.Sprintf("sha256:%x", sum), RootfsBytes: 4 << 20})
		return err
	case "provision": // AGENT: the worker formats its volume, then activates it.
		if err = args(1); err != nil {
			return err
		}
		apiProvisionAgent(t, x.l, words[1])
		return nil
	case "answer": // AGENT: the agent answers the invocation at the head of its queue with its content.
		if err = args(1); err != nil {
			return err
		}
		id, err := x.l.store.HeadDelivery(ctx, words[1])
		if err != nil {
			return err
		}
		return x.transit.DispatchMailbox(ctx, id, time.Minute, &echoRuntime{})
	case "request": // AGENT: another agent of the organization sends it a request.
		if err = args(1); err != nil {
			return err
		}
		// The mandate comes from the work the sender is doing.
		sender := apiActiveTenantAgent(t, x.l, x.owner, "examples-sender")
		execSQL(t, x.l, `INSERT INTO mandates(id,agent_id,origin_event_id,max_requests,remaining,expires_at)
            VALUES ('examples-mandate',$1,'examples-event',10,10,clock_timestamp()+interval '1 hour')`, sender)
		r, err := x.l.store.Submit(ctx, sender, "examples-request", controlplane.Submission{RecipientAgentID: words[1], MandateID: "examples-mandate",
			PayloadRef: "payload-examples", PayloadHash: [32]byte{1}, ExpiresAt: time.Now().Add(time.Hour)})
		if err == nil && r.State != controlplane.PendingApproval {
			err = fmt.Errorf("the request is %s, not held", r.State)
		}
		return err
	}
	return fmt.Errorf("an unknown worker note: %q", note)
}

// EXT-008, CONV-1: the page of examples runs as written, against the API
// over HTTPS on PostgreSQL, and every answer has the fields the contract
// documents.
func TestHTTPExamplesRunAsWritten(t *testing.T) {
	x := newExamplesLab(t)
	blocks := readExamples(t)
	ran := 0
	for i, b := range blocks {
		where := fmt.Sprintf("%s:%d", examplesDoc, b.line)
		switch b.kind {
		case "worker":
			if err := x.worker(t, b.text); err != nil {
				t.Fatalf("%s: %v", where, err)
			}
		case "http":
			if i == 0 || blocks[i-1].kind != "sh" {
				t.Fatalf("%s: an answer that follows no command", where)
			}
		case "sh":
			x.shell.answers = nil
			commands, err := splitCommands(b.text)
			if err != nil {
				t.Fatalf("%s: %v", where, err)
			}
			for _, cmd := range commands {
				if _, err := x.shell.run(cmd); err != nil {
					t.Fatalf("%s: %v", where, err)
				}
			}
			shown := i+1 < len(blocks) && blocks[i+1].kind == "http"
			for j, a := range x.shell.answers {
				last := j == len(x.shell.answers)-1
				if a.status >= 400 && !(last && shown) {
					t.Fatalf("%s: %s %s answered %d: %s", where, a.method, a.path, a.status, a.body)
				}
			}
			if shown {
				if len(x.shell.answers) == 0 {
					t.Fatalf("%s: an answer is shown for a block that sends nothing", where)
				}
				if err := checkShown(blocks[i+1].text, x.shell.answers[len(x.shell.answers)-1]); err != nil {
					t.Errorf("%s: %v", where, err)
				}
			}
			ran += len(x.shell.answers)
		}
	}
	for _, err := range x.shell.checks {
		t.Error("openapi/openapi.yaml:", err)
	}
	for _, route := range examplesCover {
		if !x.shell.called[route] {
			t.Error("the page shows no call of", route)
		}
	}
	t.Logf("%d requests on %d routes", ran, len(x.shell.called))
}

// The checks of TestHTTPExamplesRunAsWritten refuse what they should: shell
// they cannot run, an answer unlike the page's, fields unlike the contract.
// No database: it runs in CI.
func TestExampleChecksRefuseWhatTheyCannotVouchFor(t *testing.T) {
	commands, err := splitCommands("A=1 \\\n  B # a comment\n# a line of comment\ncurl \"$API/v1/x\" | jq -r .id\n")
	if err != nil || len(commands) != 2 || commands[0] != "A=1   B" {
		t.Fatalf("commands %q %v", commands, err)
	}
	sh := &exampleShell{vars: map[string]string{"API": "https://api.test"}, provided: map[string]string{"API": "https://api.test"}}
	for _, bad := range []string{
		`curl "$API/v1/x"; rm -rf /`, `curl $API/v1/x?a=1`, "curl `id`", `curl "$UNSET/v1/x"`, `echo hello`,
		`X=$(curl -k "$API/v1/x")`, `curl -fsS "https://elsewhere.test/v1/x"`, `export TOKEN=x`, `curl -d @file "$API/v1/x"`,
		`curl "$API/v1/x" | sort`, `X=$(curl "$API/v1/x" | jq 'map(.id)')`,
	} {
		if _, err := sh.run(bad); err == nil {
			t.Error("ran:", bad)
		}
	}
	if _, err := splitCommands(`curl "$(id)"`); err == nil {
		t.Error("a command substitution inside double quotes was split")
	}
	if out, err := jq([]string{"-r", ".items[1].id"}, `{"items":[{"id":"a"},{"id":"b"}]}`); err != nil || out != "b\n" {
		t.Error("jq", out, err)
	}
	if out, err := jq([]string{".n"}, `{"n":3}`); err != nil || out != "3\n" {
		t.Error("jq", out, err)
	}
	for _, c := range []struct{ shown, actual string }{
		{`{"state":"STOPPED"}`, `{"state":"RUNNING"}`},
		{`{"id":"agt_..."}`, `{"id":"op_1"}`},
		{`{"x":1}`, `{}`},
		{`["a"]`, `["a","b"]`},
		{`["a","b","..."]`, `["a"]`},
		{`{"n":1}`, `{"n":"1"}`},
	} {
		var shown, actual any
		_ = json.Unmarshal([]byte(c.shown), &shown)
		_ = json.Unmarshal([]byte(c.actual), &actual)
		if matchShown("answer", shown, actual) == nil {
			t.Error("matched:", c.shown, c.actual)
		}
	}
	if err := checkShown("HTTP/1.1 201 Created\n", exampleAnswer{status: 200}); err == nil {
		t.Error("another status matched")
	}
	doc := loadOpenAPI(t)
	if err := doc.checkAnswer("POST", "/v1/agents", 202, []byte(`{"agent_id":"a","operation_id":"o","status":"PENDING"}`)); err != nil {
		t.Error(err)
	}
	for _, c := range []struct {
		method, path string
		status       int
		body         string
	}{
		{"POST", "/v1/agents", 202, `{"agent_id":"a","status":"PENDING"}`},
		{"POST", "/v1/agents", 202, `{"agent_id":"a","operation_id":"o","status":"PENDING","host_id":"h"}`},
		{"POST", "/v1/agents", 200, `{}`},
		{"GET", "/v1/teams", 200, `{"items":[{"id":"t","name":"n","status":"active","created_at":"2026-11-16T00:00:00Z","owner":"x"}]}`},
		{"GET", "/v1/nowhere", 200, `{}`},
	} {
		if doc.checkAnswer(c.method, c.path, c.status, []byte(c.body)) == nil {
			t.Error("the contract allowed", c.method, c.path, c.status, c.body)
		}
	}
}

// examplesCover are the MVP features the page must show (EXT-008): agents,
// assignments, invocations and their polling, wake and sleep, inbound and
// held requests, technical accounts, the audit trail, model providers and
// budgets, files and download links.
var examplesCover = []string{
	"POST /v1/harness-imports", "GET /v1/harness-imports/{id}", "GET /v1/harness-releases",
	"POST /v1/members",
	"POST /v1/agents", "GET /v1/operations/{id}", "GET /v1/agents/{id}", "GET /v1/agents", "DELETE /v1/agents/{id}",
	"POST /v1/agents/{id}/assignments", "GET /v1/agents/{id}/assignments",
	"POST /v1/agents/{id}/invocations", "GET /v1/invocations/{id}", "GET /v1/invocations/{id}/result", "GET /v1/agents/{id}/invocations", "GET /v1/queue",
	"POST /v1/agents/{id}/attachments", "POST /v1/invocations/{id}/result/link", "GET /v1/downloads/{token}",
	"POST /v1/agents/{id}/wake", "POST /v1/agents/{id}/sleep", "POST /v1/agents/{id}/idle-policy",
	"PUT /v1/agents/{id}/directory", "PUT /v1/agents/{id}/inbound", "GET /v1/agents/{id}/held-requests", "POST /v1/agents/{id}/held-requests/{request_id}/accept",
	"POST /v1/service-accounts", "POST /v1/service-accounts/{id}/tokens", "GET /v1/service-accounts/{id}/tokens", "POST /v1/service-accounts/{id}/tokens/{token_id}/revoke",
	"POST /v1/llm/providers", "POST /v1/llm/providers/{id}/rotate", "POST /v1/llm/aliases", "POST /v1/llm/aliases/{alias}/grants", "POST /v1/llm/budgets", "GET /v1/llm/usage",
	"GET /v1/audit", "GET /v1/audit/export",
}
