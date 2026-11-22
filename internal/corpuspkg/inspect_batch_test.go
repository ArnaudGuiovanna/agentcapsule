//go:build linux

package corpuspkg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// fakeLayoutDebugfs puts first on PATH a debugfs that answers -f - with
// listings: listing maps an inode to the lines of its directory.
func fakeLayoutDebugfs(t *testing.T, listing map[int][]string) {
	t.Helper()
	var cases strings.Builder
	for inode, lines := range listing {
		fmt.Fprintf(&cases, "    \"ls -p <%d>\") echo \"debugfs: $line\";", inode)
		for _, l := range lines {
			fmt.Fprintf(&cases, " echo '%s';", l)
		}
		cases.WriteString(" ;;\n")
	}
	script := "#!/bin/sh\nwhile IFS= read -r line; do\n  case \"$line\" in\n    \"#\"*) echo \"$line\" ;;\n" + cases.String() +
		"    *) echo \"debugfs: $line\" ;;\n  esac\ndone\n"
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "debugfs"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// P-12: the walk lists each level of directories in batches, and finds the
// required files in the listings: no run per file or per directory. Two
// entries of one name in a directory, which the kernel would resolve to one
// of them, are refused.
func TestInspectImageWalksTheListingsInBatches(t *testing.T) {
	image := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(image, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb := sandbox.Options{TestTools: true}
	layout := func(index string) map[int][]string {
		return map[int][]string{
			2:  {"/2/040755/0/0/.//", "/12/100644/0/0/corpus.json/3/", "/13/100644/0/0/INDEX.md/" + index + "/", "/14/040755/0/0/search//", "/15/040755/0/0/ext//"},
			14: {"/16/100644/0/0/fts.sqlite/9000/"},
			15: {},
		}
	}
	fakeLayoutDebugfs(t, layout("100"))
	if err := InspectImage(t.Context(), image, sb); err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]map[int][]string{
		"INDEX.md too large": layout("70000"),
		"no search index":    {2: layout("1")[2], 14: {}, 15: {}},
		"a required file is a directory": {2: {"/12/040755/0/0/corpus.json//", "/13/100644/0/0/INDEX.md/1/", "/14/040755/0/0/search//"},
			12: {}, 14: layout("1")[14]},
		"two entries of one name": {2: append(layout("1")[2], "/17/100644/0/0/INDEX.md/1/"), 14: layout("1")[14], 15: {}},
		"a file in ext":           {2: layout("1")[2], 14: layout("1")[14], 15: {"/18/100644/0/0/x.md/1/"}},
	} {
		fakeLayoutDebugfs(t, l)
		if err := InspectImage(t.Context(), image, sb); !errors.Is(err, corpusmeta.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// 2,000 directories under the root: four runs, each starting a confined
	// process, where a run per directory took 2,001.
	wide := []string{"/12/100644/0/0/corpus.json/3/", "/13/100644/0/0/INDEX.md/1/", "/14/040755/0/0/search//"}
	for i := range 2000 {
		wide = append(wide, fmt.Sprintf("/%d/040755/0/0/d%d//", 100+i, i))
	}
	fakeLayoutDebugfs(t, map[int][]string{2: wide, 14: layout("1")[14]})
	started := time.Now()
	if err := InspectImage(t.Context(), image, sb); err != nil {
		t.Fatal(err)
	}
	t.Logf("2,001 directories inspected in %s", time.Since(started))
}
