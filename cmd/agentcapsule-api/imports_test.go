package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The programs that run inside a guest: its init, the harnesses and the
// guests of the verification labs.
var guestPrograms = []string{"cmd/capsule-init", "cmd/capsule-echo", "cmd/capsule-adapter", "examples/a2a-agent",
	"internal/verification/guest", "internal/verification/controlguest"}

// guestShared are linked by the guests and by the host on purpose: the
// protocol between them, the capability names, and the guest's event store,
// whose envelopes and outcome fingerprints the host checks. They start no VM
// and run no harness.
var guestShared = []string{"internal/capsuleprotocol", "internal/capability", "internal/harnessstore"}

// hostRuntime starts and stops VMs, and opens, mounts or archives their
// volumes: the worker's code, which runs as root.
var hostRuntime = []string{"internal/runtime", "internal/worker", "internal/volumestore", "internal/volumearchive"}

// deps lists the packages of this module that the packages link, relative to
// the module, with go list.
func deps(t *testing.T, module string, packages ...string) []string {
	t.Helper()
	args := []string{"list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}"}
	for _, p := range packages {
		args = append(args, module+"/"+p)
	}
	out, err := exec.CommandContext(t.Context(), "go", args...).Output()
	if err != nil {
		t.Fatal("go list", packages, err)
	}
	var linked []string
	for _, line := range strings.Fields(string(out)) {
		if rest, ok := strings.CutPrefix(line, module+"/"); ok {
			linked = append(linked, rest)
		}
	}
	return linked
}

func goModule(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", "list", "-m").Output()
	if err != nil {
		t.Fatal("go list -m", err)
	}
	return strings.TrimSpace(string(out))
}

// guestCode is what the guest programs link, but the host may not: the
// programs themselves, the guest's init library and the harnesses.
func guestCode(t *testing.T, module string) []string {
	t.Helper()
	var code []string
	for _, p := range deps(t, module, guestPrograms...) {
		if !slices.Contains(guestShared, p) {
			code = append(code, p)
		}
	}
	for _, must := range []string{"internal/guestinit", "internal/referenceharness", "internal/agentadapter"} {
		if !slices.Contains(code, must) {
			t.Fatal("the guest programs no longer link", must, "; review guestPrograms:", code)
		}
	}
	return code
}

// CONV-9, RUN-010: the API is an HTTP front end over PostgreSQL. It links
// neither the runtime that starts Firecracker, nor the worker, nor any code
// that runs in a guest. No route can then hand a command to a VM or to the
// host, nor run a harness, whatever it is sent.
func TestAPILinksNoRuntimeWorkerOrGuestCode(t *testing.T) {
	module := goModule(t)
	denied := append(guestCode(t, module), hostRuntime...)
	deps(t, module, hostRuntime...) // fails when one is renamed or gone
	linked := deps(t, module, "cmd/agentcapsule-api")
	if !slices.Contains(linked, "internal/api") {
		t.Fatal("go list does not see the API's own packages", linked)
	}
	for _, p := range linked {
		if slices.Contains(denied, p) {
			t.Error("agentcapsule-api links", p)
		}
	}
}

// RUN-010: the worker drives the guests through their protocol, and links no
// harness nor any other code that runs in a guest. A harness runs only in its
// VM.
func TestWorkerLinksNoHarnessCode(t *testing.T) {
	module := goModule(t)
	denied := guestCode(t, module)
	linked := deps(t, module, "cmd/agentcapsule-worker")
	if !slices.Contains(linked, "internal/worker") || !slices.Contains(linked, "internal/capsuleprotocol") {
		t.Fatal("go list does not see the worker's own packages", linked)
	}
	for _, p := range linked {
		if slices.Contains(denied, p) {
			t.Error("agentcapsule-worker links", p)
		}
	}
}

// workerStarts is every place in the worker's code that starts a program,
// with the programs and why. None takes a package's content: a harness runs
// only in its VM (REG-007, RUN-010).
var workerStarts = map[string]struct {
	sites int
	why   string
}{
	"internal/harnesspkg/inspect.go":               {1, "debugfs -R stat, read-only, on a downloaded image before it is accepted"},
	"internal/harnesspkg/build.go":                 {2, "mkfs.ext4 and debugfs -w, which build a package: the publisher's side, never called by the worker"},
	"internal/runtime/firecracker_limits_linux.go": {1, "the pinned jailer, which starts the pinned Firecracker: the boot"},
	"internal/preflight/preflight_linux.go":        {1, "the pinned Firecracker and jailer with --version"},
	"internal/worker/host_restore_linux.go":        {1, "the archive shipper the operator names with -archive-fetch"},
}

// processStarts are the calls that start a program, by package path.
var processStarts = map[string][]string{
	"os/exec":               {"Command", "CommandContext"},
	"os":                    {"StartProcess"},
	"syscall":               {"Exec", "ForkExec", "StartProcess"},
	"golang.org/x/sys/unix": {"Exec"},
}

// REG-007, RUN-010: the worker starts only the programs workerStarts names,
// each from the place it names, and no code of the worker calls what builds
// a package; its C code starts nothing. The import itself is observed in
// internal/worker (TestTheHostNeverRunsWhatAPackageHolds).
func TestWorkerStartsOnlyTheProgramsItNames(t *testing.T) {
	module := goModule(t)
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f",
		"{{if not .Standard}}{{.ImportPath}}|{{.Dir}}|{{join .GoFiles \",\"}},{{join .CgoFiles \",\"}}{{end}}", module+"/cmd/agentcapsule-worker").Output()
	if err != nil {
		t.Fatal("go list", err)
	}
	found := map[string]int{}
	var building []string
	cgoStarts := regexp.MustCompile(`\b(system|popen|execv[pe]*|execl[pe]*|posix_spawnp?|fork|vfork|clone)\s*\(`)
	files := 0
	for _, line := range strings.Fields(string(out)) {
		parts := strings.Split(line, "|")
		pkg, ok := strings.CutPrefix(parts[0], module+"/")
		if !ok || len(parts) != 3 {
			continue
		}
		for _, name := range strings.Split(parts[2], ",") {
			if name == "" {
				continue
			}
			files++
			site := pkg + "/" + name
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(parts[1], name), nil, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			imported := map[string]string{}
			for _, spec := range file.Imports {
				p, _ := strconv.Unquote(spec.Path.Value)
				local := p[strings.LastIndex(p, "/")+1:]
				if spec.Name != nil {
					local = spec.Name.Name
				}
				imported[local] = p
				// The preamble of import "C" is its C code.
				if p == "C" && spec.Doc != nil && cgoStarts.MatchString(spec.Doc.Text()) {
					t.Errorf("%s: its C code may start a program", site)
				}
				if p == "C" && file.Imports[0] == spec {
					for _, group := range file.Comments {
						if group.End() < spec.Pos() && cgoStarts.MatchString(group.Text()) {
							t.Errorf("%s: its C code may start a program", site)
						}
					}
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if lit, ok := n.(*ast.CompositeLit); ok {
					// An exec.Cmd built by hand starts without the calls below.
					if sel, ok := lit.Type.(*ast.SelectorExpr); ok {
						if x, ok := sel.X.(*ast.Ident); ok && imported[x.Name] == "os/exec" && sel.Sel.Name == "Cmd" {
							t.Errorf("%s: an exec.Cmd literal", site)
						}
					}
					return true
				}
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				x, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				switch p := imported[x.Name]; {
				case slices.Contains(processStarts[p], sel.Sel.Name):
					found[site]++
				case p == module+"/internal/harnesspkg" && (sel.Sel.Name == "BuildRootfs" || sel.Sel.Name == "WritePackage"):
					building = append(building, site+": "+sel.Sel.Name)
				}
				return true
			})
		}
	}
	if files < 100 {
		t.Fatal("go list named too few of the worker's files", files)
	}
	for site, n := range found {
		if want, ok := workerStarts[site]; !ok || want.sites != n {
			t.Errorf("%s starts a program %d times; workerStarts says %d", site, n, want.sites)
		}
	}
	for site, want := range workerStarts {
		if found[site] != want.sites {
			t.Errorf("workerStarts names %s (%s), which no longer starts it %d times", site, want.why, want.sites)
		}
	}
	if len(building) != 0 {
		t.Error("the worker's code builds packages:", building)
	}
}
