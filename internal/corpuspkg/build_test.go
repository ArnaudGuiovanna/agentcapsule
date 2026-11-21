package corpuspkg

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
)

const testUUID = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"

// layout returns the files of a small published layout, by path.
func layout() map[string]string {
	files := map[string]string{
		corpusmeta.InfoFile:        `{"schema":"agentcapsule.corpus/v1"}`,
		corpusmeta.IndexFile:       "# Finance\n\n- [Chapter 1](docs/d1/README.md)\n",
		corpusmeta.SearchFile:      strings.Repeat("SQLite format 3\x00", 300),
		corpusmeta.ReportFile:      `{"schema":"agentcapsule.corpus-report/v1"}`,
		corpusmeta.GlossaryFile:    "# Glossary\n",
		"topics/discounting.md":    "# Discounting\n",
		"docs/d1/doc.json":         "{}",
		"docs/d1/README.md":        "# Chapter 1\n",
		"docs/d1/part-001.md":      "<a id=\"e0001\"></a>\n# Chapter 1\n",
		"docs/d1/pages/0001.webp":  "RIFF....WEBP",
		"docs/d2/data/table-1.csv": "a,b\n1,2\n",
		"docs/d2/data/table-1.md":  "Table 1\n",
		"docs/d2/README.md":        "# Data\n",
		"docs/d3/part-001.md":      strings.Repeat("words ", 20000),
		"docs/d3/pages/0001.webp":  strings.Repeat("\x01", 70000),
		"docs/d3/pages/0002.webp":  "",
		"docs/d3/README.md":        "# Long\n",
		"docs/d3/doc.json":         "{}",
		"docs/d2/doc.json":         "{}",
		"docs/d2/data/empty.csv":   "",
	}
	return files
}

// write puts files under a new directory, in the order given, with the
// mode given.
func write(t *testing.T, files map[string]string, order []string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range order {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(files[name]), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, corpusmeta.ExtDir), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func keys(files map[string]string) []string {
	var k []string
	for name := range files {
		k = append(k, name)
	}
	slices.Sort(k)
	return k
}

func build(t *testing.T, dir, uuid string) (string, int64) {
	t.Helper()
	out := filepath.Join(t.TempDir(), ImageFile)
	size, err := BuildImage(t.Context(), dir, out, uuid, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(b)) != size {
		t.Fatalf("the image has %d bytes, BuildImage says %d", len(b), size)
	}
	return harnesspkg.Digest(b), size
}

// The exit criterion of the corpus plan's lot 1: two builds of the same tree
// give the same digest. The second tree is written later, in another order,
// with other modes and directory modes, and one of its files has a link
// outside the tree, as a builder's conversion cache would hold: none of that
// reaches the image. Another UUID, or one byte changed, gives another.
func TestTwoBuildsOfTheSameTreeGiveTheSameDigest(t *testing.T) {
	files := layout()
	order := keys(files)
	first, size := build(t, write(t, files, order, 0o644), testUUID)
	if again, _ := build(t, write(t, files, order, 0o644), testUUID); again != first {
		t.Fatal("the same tree built twice gave two images")
	}
	time.Sleep(1100 * time.Millisecond)
	reversed := slices.Clone(order)
	slices.Reverse(reversed)
	dir := write(t, files, reversed, 0o600)
	if err := os.Link(filepath.Join(dir, corpusmeta.IndexFile), filepath.Join(t.TempDir(), "cache-entry")); err != nil {
		t.Fatal(err)
	}
	if second, _ := build(t, dir, testUUID); second != first {
		t.Fatal("the same tree, written otherwise, gave another image")
	}
	if other, _ := build(t, write(t, files, order, 0o644), "6fa459ea-ee8a-4ca4-894e-db77e160355e"); other == first {
		t.Fatal("another UUID gave the same image")
	}
	files["docs/d1/README.md"] += "."
	if changed, _ := build(t, write(t, files, order, 0o644), testUUID); changed == first {
		t.Fatal("other contents gave the same image")
	}
	if size < MinImageBytes || size%(1<<20) != 0 {
		t.Fatal("size", size)
	}
}

// The size estimate fits a layout of many small files and of large ones, and
// stays within a margin of the content.
func TestBuildImageSizeFitsTheTree(t *testing.T) {
	files := layout()
	random := rand.New(rand.NewPCG(3, 4))
	big := make([]byte, 24<<20)
	for i := range big {
		big[i] = byte(random.Uint32())
	}
	files["docs/big/part-001.md"] = string(big)
	for i := range 3000 {
		files[fmt.Sprintf("docs/many/pages/%04d.webp", i)] = strings.Repeat("p", i%5000)
	}
	dir := write(t, files, keys(files), 0o644)
	out := filepath.Join(t.TempDir(), ImageFile)
	size, err := BuildImage(t.Context(), dir, out, testUUID, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	var content int64
	for _, data := range files {
		content += int64(len(data))
	}
	if size < content || size > content*2+16<<20 {
		t.Fatalf("an image of %d bytes for %d bytes of files", size, content)
	}
	if _, err = BuildImage(t.Context(), dir, filepath.Join(t.TempDir(), ImageFile), testUUID, 16<<20); !errors.Is(err, ErrTooLarge) {
		t.Fatal("past the maximum:", err)
	}
}

// BuildImage takes only directories and regular files, each path once, the
// required files and an empty ext/.
func TestBuildImageRefusesWhatTheLayoutCannotHold(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, dir string){
		"symbolic link": func(t *testing.T, dir string) {
			mustDo(t, os.Symlink(corpusmeta.IndexFile, filepath.Join(dir, "docs/d1/link.md")))
		},
		"hard link inside": func(t *testing.T, dir string) {
			mustDo(t, os.Link(filepath.Join(dir, corpusmeta.IndexFile), filepath.Join(dir, "docs/d1/same.md")))
		},
		"FIFO": func(t *testing.T, dir string) {
			mustDo(t, syscall.Mkfifo(filepath.Join(dir, "docs/d1/fifo"), 0o644))
		},
		"no corpus.json":  func(t *testing.T, dir string) { mustDo(t, os.Remove(filepath.Join(dir, corpusmeta.InfoFile))) },
		"no search index": func(t *testing.T, dir string) { mustDo(t, os.Remove(filepath.Join(dir, corpusmeta.SearchFile))) },
		"INDEX.md too large": func(t *testing.T, dir string) {
			mustDo(t, os.WriteFile(filepath.Join(dir, corpusmeta.IndexFile), make([]byte, corpusmeta.MaxIndexBytes+1), 0o644))
		},
		"INDEX.md a directory": func(t *testing.T, dir string) {
			mustDo(t, os.Remove(filepath.Join(dir, corpusmeta.IndexFile)))
			mustDo(t, os.Mkdir(filepath.Join(dir, corpusmeta.IndexFile), 0o755))
		},
		"ext not empty": func(t *testing.T, dir string) {
			mustDo(t, os.WriteFile(filepath.Join(dir, corpusmeta.ExtDir, "x.md"), nil, 0o644))
		},
		"a quote in a name": func(t *testing.T, dir string) {
			mustDo(t, os.WriteFile(filepath.Join(dir, `docs/d1/a"b.md`), nil, 0o644))
		},
		"a control character": func(t *testing.T, dir string) {
			mustDo(t, os.WriteFile(filepath.Join(dir, "docs/d1/a\nb.md"), nil, 0o644))
		},
	} {
		dir := write(t, layout(), keys(layout()), 0o644)
		change(t, dir)
		if _, err := BuildImage(t.Context(), dir, filepath.Join(t.TempDir(), ImageFile), testUUID, 64<<20); !errors.Is(err, corpusmeta.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := BuildImage(t.Context(), t.TempDir(), filepath.Join(t.TempDir(), ImageFile), "not-a-uuid", 64<<20); !errors.Is(err, corpusmeta.ErrInvalid) {
		t.Error("a bad UUID:", err)
	}
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// The UUID formula of ADR 023 §2.3, computed here independently.
func TestImageUUIDIsTheADRFormula(t *testing.T) {
	corpus, commit, builder := "cor_"+strings.Repeat("0a", 16), strings.Repeat("ab", 20), "sha256:"+strings.Repeat("cd", 32)
	got, err := ImageUUID(corpus, commit, builder)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("agentcapsule.corpus-uuid.v1\x00" + corpus + "\x00" + commit + "\x00" + builder))
	h := fmt.Sprintf("%x", sum[:16])
	if want := h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]; got != want || !corpusmeta.ValidUUID(got) {
		t.Fatal(got, want)
	}
	if again, _ := ImageUUID(corpus, commit, builder); again != got {
		t.Fatal("not deterministic")
	}
	for _, bad := range [][3]string{
		{"cor_x", commit, builder},
		{corpus, strings.ToUpper(commit), builder},
		{corpus, commit[:39], builder},
		{corpus, commit, "sha256:" + strings.Repeat("CD", 32)},
		{"cbd_" + strings.Repeat("0a", 16), commit, builder},
	} {
		if _, err := ImageUUID(bad[0], bad[1], bad[2]); !errors.Is(err, corpusmeta.ErrInvalid) {
			t.Error("accepted", bad)
		}
	}
}
