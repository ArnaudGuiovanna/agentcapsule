//go:build linux

package corpuspkg

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// built returns a built image of the test layout.
func built(t *testing.T) (string, int64) {
	t.Helper()
	out := filepath.Join(t.TempDir(), ImageFile)
	size, err := BuildImage(t.Context(), write(t, layout(), keys(layout()), 0o644), out, testUUID, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	return out, size
}

// derive copies image and changes the copy with debugfs -w.
func derive(t *testing.T, image, script string) string {
	t.Helper()
	b, err := os.ReadFile(image)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "derived.ext4")
	if err = os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "debugfs", "-w", "-f", "-", out)
	cmd.Stdin = strings.NewReader(script)
	if b, err := cmd.CombinedOutput(); err != nil || strings.Contains(string(b), "rror") {
		t.Fatal(err, string(b))
	}
	return out
}

func checkFile(t *testing.T, image string, max int64, uuid string) error {
	t.Helper()
	f, err := os.Open(image)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return CheckImage(f, st.Size(), max, uuid)
}

// The worker's superblock check (ADR 023 §6.4, step 2): the build's UUID,
// the corpus label, a filesystem filling the file, cleanly made, with the
// corpus features only.
func TestCheckImageReadsTheSuperblock(t *testing.T) {
	image, size := built(t)
	if err := checkFile(t, image, size, testUUID); err != nil {
		t.Fatal(err)
	}
	if err := checkFile(t, image, size, "6fa459ea-ee8a-4ca4-894e-db77e160355e"); !errors.Is(err, ErrInvalid) {
		t.Error("another UUID:", err)
	}
	if err := checkFile(t, image, size-4096, testUUID); !errors.Is(err, ErrInvalid) {
		t.Error("past the maximum:", err)
	}
	errorState := derive(t, image, "ssv state 2\n")
	if err := checkFile(t, errorState, size, testUUID); !errors.Is(err, ErrInvalid) {
		t.Error("errors recorded:", err)
	}
	longer := derive(t, image, "")
	f, err := os.OpenFile(longer, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(make([]byte, 4096))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkFile(t, longer, size*2, testUUID); !errors.Is(err, ErrInvalid) {
		t.Error("bytes after the filesystem:", err)
	}
	// An ext4 image of the default features, with a journal, and one
	// labelled otherwise, are not corpus images.
	src := write(t, layout(), keys(layout()), 0o644)
	for name, args := range map[string][]string{
		"journal":     {"-L", Label},
		"other label": {"-L", "harness", "-O", "^has_journal,^metadata_csum_seed,^orphan_file"},
	} {
		out := filepath.Join(t.TempDir(), name)
		cmd := exec.CommandContext(t.Context(), "mkfs.ext4", append(append([]string{"-q", "-F", "-b", "4096", "-U", testUUID}, args...), "-d", src, out, "8M")...)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err, string(b))
		}
		if err := checkFile(t, out, 8<<20, testUUID); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The worker's layout check (ADR 023 §6.4, step 3), confined: a built image
// passes; one that lacks a required file, holds a special file, a symbolic
// link, a setuid file or files in ext/, or reaches a directory twice, does
// not.
func TestInspectImageChecksTheLayout(t *testing.T) {
	image, _ := built(t)
	if err := InspectImage(t.Context(), image, sandbox.Options{}); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(t.TempDir(), "x.md")
	if err := os.WriteFile(host, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"no search index":    "rm /search/fts.sqlite\n",
		"no corpus.json":     "rm /corpus.json\n",
		"INDEX.md too large": "sif /INDEX.md size 70000\n",
		"FIFO":               "cd /docs/d1\nmknod fifo p\n",
		"device":             "cd /docs/d2/data\nmknod null c 1 3\n",
		"symbolic link":      "symlink /docs/d3/link /etc/passwd\n",
		"setuid file":        "sif /docs/d1/README.md mode 0104644\n",
		"setgid directory":   "sif /docs/d2 mode 042755\n",
		"file in ext":        "cd /ext\nwrite " + host + " x.md\n",
		"directory twice":    "link /docs /docs/d1/loop\n",
	} {
		if err := InspectImage(t.Context(), derive(t, image, script), sandbox.Options{}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// InspectImage runs every debugfs confined: a debugfs that starts a process,
// as a compromised one would, is killed.
func TestInspectImageRunsDebugfsConfined(t *testing.T) {
	image, _ := built(t)
	bin := t.TempDir()
	script := "#!/bin/sh\nanswer=$(echo regular)\necho \"Inode: 12   Type: $answer    Mode:  0644   Flags: 0x0\"\necho 'User:     0   Group:     0   Size: 3'\n"
	if err := os.WriteFile(filepath.Join(bin, "debugfs"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := InspectImage(t.Context(), image, sandbox.Options{}); !errors.Is(err, sandbox.ErrSyscall) {
		t.Fatal("a debugfs that starts a process, confined:", err)
	}
}

func TestCorpusExtensionDataTreeIsInspectedWithoutBusinessFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("reviewed material\n"), 0644); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), ImageFile)
	if _, err := BuildExtensionImage(t.Context(), dir, image, testUUID, 64<<20); err != nil {
		t.Fatal(err)
	}
	if err := InspectExtension(t.Context(), image, sandbox.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := InspectImage(t.Context(), image, sandbox.Options{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("extension accepted as base", err)
	}
	if err := os.Symlink("notes.txt", filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildExtensionImage(t.Context(), dir, image, testUUID, 64<<20); !errors.Is(err, ErrInvalid) {
		t.Fatal("symlink", err)
	}
}
