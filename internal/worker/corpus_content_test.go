//go:build linux

package worker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource/forgetest"
)

// hostileArchive is a repository's archive written to run on any host that
// opens it: scripts, a name that is a command, Git attributes whose filters
// run commands, an LFS pointer to an object that is a script too. Each run
// would leave a marker file.
func hostileArchive(t *testing.T, marker func(string) string, object []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	files := map[string]string{
		"acme-handbook-1111111/harness":                  "#!/bin/sh\necho ran > " + marker("archive-script") + "\n",
		"acme-handbook-1111111/usr/bin/setup":            "#!/bin/sh\necho ran > " + marker("archive-setup") + "\n",
		"acme-handbook-1111111/$(echo ran > x)":          "a name that is a command",
		"acme-handbook-1111111/.gitattributes":           "* filter=run\n",
		"acme-handbook-1111111/.git/config":              "[filter \"run\"]\n\tsmudge = sh -c 'echo ran > " + marker("git-filter") + "'\n",
		"acme-handbook-1111111/agentcapsule-corpus.yaml": "schema: agentcapsule.corpus-source/v1\ntitle: \"`echo ran > " + marker("manifest") + "`\"\n",
		"acme-handbook-1111111/videos/talk.mp4":          "version https://git-lfs.github.com/spec/v1\noid sha256:" + forgetest.OID(object) + "\nsize " + fmt.Sprint(len(object)) + "\n",
	}
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), ModTime: time.Unix(1, 0)}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// REG-007 and RUN-010 extended to corpus sources (ADR 023 §4): the host
// downloads, hashes, pads and concatenates a repository's bytes; it runs no
// program on them, decompresses nothing and reads no file inside them. The
// fetch of a hostile archive and of an LFS object that is a script runs with
// a PATH where every program a host could open them with announces itself
// (hostTraps: tar, gzip, git, git-lfs, ffmpeg, pdftotext, soffice, unzip,
// the shells...). No marker exists after, no program reported, and the
// drives hold the forge's bytes as sent: the archive still gzip.
func TestTheHostNeverRunsWhatACorpusSourceHolds(t *testing.T) {
	markers := t.TempDir()
	marker := func(name string) string { return filepath.Join(markers, name) }
	object := []byte("#!/bin/sh\necho ran > " + marker("lfs-object") + "\n")
	archive := hostileArchive(t, marker, object)

	traps := t.TempDir()
	reports := filepath.Join(t.TempDir(), "reports")
	if err := syscall.Mkfifo(reports, 0o600); err != nil {
		t.Fatal(err)
	}
	fifo, err := os.OpenFile(reports, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fifo.Close()
	for _, name := range append(hostTraps, "debugfs") {
		trap := fmt.Sprintf("#!/bin/sh\nprintf 'forbidden %s %%s\\n' \"$*\" >> %s\nexit 1\n", name, reports)
		if err = os.WriteFile(filepath.Join(traps, name), []byte(trap), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	l := newCorpusLab(t, corpusLimits)
	l.forge.Add(&forgetest.Repo{Kind: corpussource.GitHub, Path: "acme/handbook", Private: true, Token: forgeToken,
		Refs: map[string]string{"main": corpusCommit}, Archives: map[string][]byte{corpusCommit: archive},
		Objects: map[string][]byte{forgetest.OID(object): object}})
	b := l.store.add(corpusJob(corpussource.GitHub, "acme/handbook", "scr_github"))
	// From here, every program is found in traps only.
	t.Setenv("PATH", traps)
	if err = l.fetchOne(t); err != nil || b.state != "SCANNING" {
		t.Fatal("the archive", b.state, b.code, err)
	}
	l.store.scanned(b, []corpussource.Pointer{{OID: forgetest.OID(object), Size: int64(len(object))}})
	if err = l.fetchOne(t); err != nil || b.state != "CONVERTING" {
		t.Fatal("the LFS object", b.state, b.code, err)
	}

	for _, name := range []string{"archive-script", "archive-setup", "git-filter", "manifest", "lfs-object", "x"} {
		if _, err = os.Stat(marker(name)); !os.IsNotExist(err) {
			t.Error("the host ran the source's", name, err)
		}
	}
	if _, err = os.Stat(filepath.Join(l.fetcher.StagingDir(b.job.BuildID), "$(echo ran > x)")); !os.IsNotExist(err) {
		t.Error("the host unpacked the archive")
	}
	if err = fifo.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	if n, _ := fifo.Read(buf); n != 0 {
		t.Fatal("the host started programs on a corpus source:", strings.TrimSpace(string(buf[:n])))
	}
	dir := l.fetcher.StagingDir(b.job.BuildID)
	source, err := os.ReadFile(filepath.Join(dir, CorpusSourceFile))
	if err != nil || !bytes.Equal(source[:len(archive)], archive) || source[0] != 0x1f || source[1] != 0x8b {
		t.Fatal("source.bin is not the forge's gzip bytes as sent", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		if st, err := os.Stat(filepath.Join(dir, e.Name())); err != nil || st.Mode().Perm()&0o111 != 0 || st.Mode().Perm()&0o077 != 0 {
			t.Error("a staged file is executable or not private:", e.Name(), st.Mode())
		}
	}
	if strings.Join(names, " ") != strings.Join([]string{corpussource.LFSFile, corpussource.LFSJournal, CorpusSourceFile}, " ") {
		t.Fatal("the staging holds other files than the drives:", names)
	}
}
