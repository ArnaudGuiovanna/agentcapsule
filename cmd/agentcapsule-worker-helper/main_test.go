//go:build linux

package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/workerhelper"
)

// The helper stays small (ADR 024 §2): of this repository, it links the
// protocol and its operations, and the sandbox, nothing else. A package
// that joins its import graph runs as root.
func TestHelperImportsTwoInternalPackages(t *testing.T) {
	const module = "github.com/ArnaudGuiovanna/agentcapsule/"
	root := filepath.Join("..", "..")
	seen := map[string]bool{}
	var walk func(dir string)
	walk = func(dir string) {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, dir, e.Name()), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range f.Imports {
				path, _ := strconv.Unquote(spec.Path.Value)
				if pkg, ok := strings.CutPrefix(path, module); ok && !seen[pkg] {
					seen[pkg] = true
					walk(pkg)
				}
			}
		}
	}
	walk("cmd/agentcapsule-worker-helper")
	var got []string
	for pkg := range seen {
		got = append(got, pkg)
	}
	slices.Sort(got)
	if want := []string{"internal/sandbox", "internal/workerhelper"}; !slices.Equal(got, want) {
		t.Fatalf("the helper imports %v, want %v", got, want)
	}
}

// The confined programs run as a UID that owns nothing: never an agent's,
// the worker's, an account's or a group's.
func TestTheInspectionUIDIsReserved(t *testing.T) {
	c := workerhelper.Config{FirstUID: 20000, LastUID: 20100, WorkerUID: 990, WorkerGID: 990}
	for _, uid := range []uint32{65535, 20000, 20050, 990, uint32(os.Getuid()), 1 << 31} {
		c.InspectionUID = uid
		if inspectionUID(c) == nil {
			t.Fatal("accepted", uid)
		}
	}
	c.InspectionUID = 0
	if err := inspectionUID(c); err != nil {
		t.Fatal(err)
	}
}

// rootsOnly refuses an executable that another account could change.
func TestTheHelperRunsOnlyRootsExecutables(t *testing.T) {
	mine := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(mine, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && rootsOnly(mine) == nil {
		t.Fatal("an executable of this account was accepted")
	}
	if rootsOnly("relative") == nil {
		t.Fatal("a relative path was accepted")
	}
}
