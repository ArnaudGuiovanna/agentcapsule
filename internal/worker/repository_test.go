//go:build linux && cgo

package worker

import (
	"os"
	"path/filepath"
	"testing"
)

// repositoryRoot is the root of the sources under test: the nearest
// directory at or above the working directory that holds go.mod. go test
// runs a package's tests in the package's directory, but the KVM campaign
// (scripts/verify-product-guest.py) runs its compiled tests from the root of
// the copy of the sources it records, wherever its checkout and its output
// directory are. A path relative to the package's directory points outside
// that copy.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if st, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && st.Mode().IsRegular() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod at or above the working directory")
		}
		dir = parent
	}
}

// The KVM campaign's working directory is the root of its copy of the
// sources, go test's is the package's: both find the same root.
func TestRepositoryRootFromEitherWorkingDirectory(t *testing.T) {
	root := repositoryRoot(t)
	if _, err := os.Stat(filepath.Join(root, "internal", "worker", "repository_test.go")); err != nil {
		t.Fatal("not the root of these sources", root, err)
	}
	t.Chdir(root)
	if got := repositoryRoot(t); got != root {
		t.Fatal("another root from the sources' root", got, root)
	}
}
