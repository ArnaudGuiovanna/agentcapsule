//go:build linux

package ext4image

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// P-12: confined, one debugfs run lists many directories by their inodes,
// and each listing is the one List gives for the directory's path, on every
// image: 600 directories take two runs instead of 600.
func TestConfinedBatchListingsAreListsOwn(t *testing.T) {
	debugfs, err := Debugfs()
	if err != nil {
		t.Fatal(err)
	}
	for name, image := range images(t) {
		paths, inodes := []string{"/"}, []uint64{2}
		for _, dir := range []string{"/", "/docs"} {
			entries, err := List(t.Context(), sandbox.Options{}, debugfs, image, dir)
			if err != nil {
				t.Fatal(name, dir, err)
			}
			for _, e := range entries {
				if e.IsDir() {
					paths = append(paths, strings.TrimSuffix(dir, "/")+"/"+e.Name)
					inodes = append(inodes, e.Inode)
				}
			}
		}
		if len(inodes) <= ListBatch {
			t.Fatal(name, "too few directories for two runs:", len(inodes))
		}
		listings, err := ListInodes(t.Context(), sandbox.Options{}, debugfs, image, inodes)
		if err != nil || len(listings) != len(inodes) {
			t.Fatal(name, len(listings), err)
		}
		// One run per directory costs about 20 ms: a sample of them.
		for i, p := range paths {
			if i%50 != 0 && i != len(paths)-1 && i != ListBatch {
				continue
			}
			want, err := List(t.Context(), sandbox.Options{}, debugfs, image, p)
			if err != nil {
				t.Fatal(name, p, err)
			}
			if !reflect.DeepEqual(listings[i], want) {
				t.Errorf("%s %s: batch %v, alone %v", name, p, listings[i], want)
			}
		}
	}
}

// BenchmarkListingSixHundredDirectories lists the 602 directories of an
// image confined, one run per directory as before P-12, and batched.
func BenchmarkListingSixHundredDirectories(b *testing.B) {
	debugfs, err := Debugfs()
	if err != nil {
		b.Fatal(err)
	}
	image := images(b)["ext4"]
	entries, err := List(b.Context(), sandbox.Options{}, debugfs, image, "/docs")
	if err != nil {
		b.Fatal(err)
	}
	paths, inodes := []string{"/", "/docs"}, []uint64{2}
	for _, e := range entries {
		paths = append(paths, "/docs/"+e.Name)
		inodes = append(inodes, e.Inode)
	}
	b.Run("one run per directory", func(b *testing.B) {
		for b.Loop() {
			for _, p := range paths {
				if _, err := List(b.Context(), sandbox.Options{}, debugfs, image, p); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("batched", func(b *testing.B) {
		for b.Loop() {
			if _, err := ListInodes(b.Context(), sandbox.Options{}, debugfs, image, inodes); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// fakeBatchDebugfs answers debugfs -f - as debugfs does: it echoes each
// comment line, and each command after "debugfs: ", then prints lines
// entries for it.
func fakeBatchDebugfs(t *testing.T, lines int, extra string) string {
	t.Helper()
	return fakeDebugfs(t, `while IFS= read -r line; do
  case "$line" in
    "#"*) echo "$line" ;;
    *) echo "debugfs: $line"; `+extra+`
       i=0; while [ $i -lt `+strconv.Itoa(lines)+` ]; do echo "/12/100644/0/0/an-entry-with-a-rather-long-name-$i/3/"; i=$((i+1)); done ;;
  esac
done`)
}

// A run whose output reaches the sandbox's limit keeps the listings that
// ended before it; the next run lists the rest again. A listing that alone
// does not fit is refused.
func TestListInodesListsAgainWhatTheOutputLimitCut(t *testing.T) {
	image := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(image, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb := sandbox.Options{TestTools: true}
	inodes := []uint64{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}
	// About 300 KB a listing: 3 fit in a run.
	listings, err := ListInodes(t.Context(), sb, fakeBatchDebugfs(t, 5000, ""), image, inodes)
	if err != nil || len(listings) != len(inodes) {
		t.Fatal(len(listings), err)
	}
	for i, l := range listings {
		if len(l) != 5000 || l[4999].Name != "an-entry-with-a-rather-long-name-4999" {
			t.Fatal(i, len(l))
		}
	}
	if _, err = ListInodes(t.Context(), sb, fakeBatchDebugfs(t, 30000, ""), image, inodes); !errors.Is(err, ErrUnreadable) {
		t.Fatal("a listing longer than the limit:", err)
	}
}

// A name cannot forge the comment that starts a listing: the run's nonce
// is not in the image. A listing out of order is refused too.
func TestListInodesRefusesForgedOrMissingListings(t *testing.T) {
	image := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(image, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sb := sandbox.Options{TestTools: true}
	if l, err := ListInodes(t.Context(), sb, fakeBatchDebugfs(t, 2, ""), image, []uint64{2, 12}); err != nil || len(l) != 2 || len(l[1]) != 2 {
		t.Fatal(l, err)
	}
	for name, debugfs := range map[string]string{
		"forged comment":     fakeBatchDebugfs(t, 1, `echo "#0123456789abcdef0123456789abcdef 1";`),
		"another command":    fakeDebugfs(t, `while IFS= read -r line; do case "$line" in "#"*) echo "$line" ;; *) echo "debugfs: ls -p <99>" ;; esac; done`),
		"a listing missing":  fakeDebugfs(t, `while IFS= read -r line; do case "$line" in "#"*" 0") echo "$line" ;; "#"*) ;; *) echo "debugfs: $line" ;; esac; done`),
		"text before":        fakeDebugfs(t, `echo banner; while IFS= read -r line; do case "$line" in "#"*) echo "$line" ;; *) echo "debugfs: $line" ;; esac; done`),
		"comments reordered": fakeDebugfs(t, `while IFS= read -r line; do case "$line" in "#"*) echo "${line% *} 7" ;; *) echo "debugfs: $line" ;; esac; done`),
	} {
		if _, err := ListInodes(t.Context(), sb, debugfs, image, []uint64{2, 12}); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
