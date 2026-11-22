package controlplane

import (
	"go/build"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The control plane is the data layer: it stores and checks what the API, the
// worker and the LLM service ask of it, and it calls no model provider and no
// guest (v0.1.0 audit, finding A-02). It must not depend, even through another
// package, on the LLM gateway or service, on the guest protocol's transport or
// on the guest's SQLite store. What it shares with them comes from leaf
// packages, which import nothing of the module but other leaves.
func TestTheControlPlaneDependsOnNoHigherLayer(t *testing.T) {
	module := modulePath
	deps := moduleDeps(t, module, module+"/internal/controlplane")
	for _, forbidden := range []string{"internal/llmgateway", "internal/llmservice", "internal/capsuleprotocol", "internal/harnessstore"} {
		if chain, ok := deps[module+"/"+forbidden]; ok {
			t.Errorf("the control plane imports %s: %s", forbidden, strings.Join(chain, " -> "))
		}
	}
	if chain, ok := deps["github.com/mattn/go-sqlite3"]; ok {
		t.Errorf("the control plane links the guest's SQLite: %s", strings.Join(chain, " -> "))
	}
	if len(deps) < 10 {
		t.Fatal("too few dependencies found", len(deps))
	}
}

// The packages the control plane shares with the LLM gateway and the guest
// import nothing of the module but each other: they are where a type both
// sides use lives, never a way back to a higher layer.
func TestTheSharedPackagesAreLeaves(t *testing.T) {
	module := modulePath
	leaves := []string{"internal/addrpolicy", "internal/llmpolicy", "internal/capsuleprotocol/wire", "internal/harnessstore/envelope"}
	for _, leaf := range leaves {
		for dep, chain := range moduleDeps(t, module, module+"/"+leaf) {
			if strings.HasPrefix(dep, module+"/") && !slices.Contains(leaves, strings.TrimPrefix(dep, module+"/")) {
				t.Errorf("leaf %s imports %s: %s", leaf, dep, strings.Join(chain, " -> "))
			}
			if !strings.HasPrefix(dep, module+"/") && strings.Contains(strings.SplitN(dep, "/", 2)[0], ".") {
				t.Errorf("leaf %s imports %s, outside the standard library", leaf, dep)
			}
		}
	}
}

// moduleDeps is every package that root's non-test files import, directly or
// through a package of the module, as the Linux build selects its files. Each
// maps to the chain of imports that reaches it. Packages outside the module
// are listed, not followed.
func moduleDeps(t *testing.T, module, root string) map[string][]string {
	t.Helper()
	ctx := build.Default
	ctx.GOOS, ctx.CgoEnabled = "linux", true
	deps := map[string][]string{}
	queue := [][]string{{root}}
	for len(queue) > 0 {
		chain := queue[0]
		queue = queue[1:]
		dir := filepath.Join("..", "..", filepath.FromSlash(strings.TrimPrefix(chain[len(chain)-1], module+"/")))
		pkg, err := ctx.ImportDir(dir, 0)
		if err != nil {
			t.Fatal(chain, err)
		}
		for _, path := range pkg.Imports {
			if _, seen := deps[path]; seen || path == root {
				continue
			}
			next := append(slices.Clone(chain), path)
			deps[path] = next
			if strings.HasPrefix(path, module+"/") {
				queue = append(queue, next)
			}
		}
	}
	return deps
}
