//go:build linux && cgo

package volumestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumestore/lukstest"
	"golang.org/x/sys/unix"
)

func TestScratchInspectionRevokesAccessAndRequiresPrivateCopy(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "copy")
	if err := os.WriteFile(path, []byte("scratch"), 0o600); err != nil {
		t.Fatal(err)
	}
	revoke, err := allowScratchInspection(path, 61999)
	if err != nil {
		t.Fatal(err)
	}
	if size, err := unix.Getxattr(path, "system.posix_acl_access", nil); err != nil || size != 44 {
		t.Fatal("missing inspector ACL", size, err)
	}
	if err := revoke(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Getxattr(path, "system.posix_acl_access", nil); !errors.Is(err, unix.ENODATA) {
		t.Fatal("inspector ACL survived", err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal("private file mode", st, err)
	}
	if err := os.Link(path, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := allowScratchInspection(path, 61999); !errors.Is(err, ErrState) {
		t.Fatal("hard link accepted", err)
	}
}

// scratchCopy prepares a volume and returns a copy of its container, as a
// restore test copies an archive, with its spec and key.
func scratchCopy(t *testing.T) (string, Spec, []byte) {
	t.Helper()
	s, spec, key := fixture(t)
	c, err := s.Prepare(t.Context(), spec, key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(c.Path)
	if err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(t.TempDir(), "copy.luks")
	if err = os.WriteFile(scratch, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return scratch, spec, key
}

// S-21: a guest may rewrite the LUKS2 header of the volume it holds open,
// and an archive keeps it. The check loads it confined, and refuses before
// any key derivation a header that would cost more than the platform's own:
// Argon2id over 1 GiB, 1000 passes or 4 threads, another derivation, a
// digest of 100 million iterations, a token. The same header rewritten as it
// was still opens: the rewrite alone refuses nothing. Each refusal is quick.
func TestCheckContainerRefusesAHeaderBeyondThePlatformsBounds(t *testing.T) {
	kdf := func(field string, value any) func(map[string]any) {
		return func(m map[string]any) { lukstest.Object(m, "keyslots", "0", "kdf")[field] = value }
	}
	for _, c := range []struct {
		name string
		edit func(map[string]any)
		want error
	}{
		{"unchanged", func(map[string]any) {}, nil},
		{"Argon2id over 1 GiB", kdf("memory", json.Number("1048576")), ErrHeader},
		{"Argon2id of 1000 passes", kdf("time", json.Number("1000")), ErrHeader},
		{"Argon2id on 4 threads", kdf("cpus", json.Number("4")), ErrHeader},
		{"Argon2i", kdf("type", "argon2i"), ErrHeader},
		{"PBKDF2", func(m map[string]any) {
			lukstest.Object(m, "keyslots", "0")["kdf"] = map[string]any{"type": "pbkdf2", "hash": "sha256", "iterations": json.Number("1000"),
				"salt": lukstest.Object(m, "keyslots", "0", "kdf")["salt"]}
		}, ErrHeader},
		{"a digest of 100 million iterations", func(m map[string]any) {
			lukstest.Object(m, "digests", "0")["iterations"] = json.Number("100000000")
		}, ErrHeader},
		{"a token", func(m map[string]any) {
			m["tokens"] = map[string]any{"0": map[string]any{"type": "luks2-keyring", "keyslots": []any{"0"}, "key_description": "agentcapsule"}}
		}, ErrHeader},
	} {
		t.Run(c.name, func(t *testing.T) {
			scratch, spec, key := scratchCopy(t)
			if err := lukstest.RewriteMetadata(scratch, c.edit); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			err := CheckContainer(t.Context(), sandbox.Options{}, scratch, spec.VolumeID, key)
			if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("%v, not %v", err, c.want)
			}
			if c.want != nil && time.Since(start) > 10*time.Second {
				t.Errorf("refused after %s", time.Since(start))
			}
		})
	}
}

// S-21: once a volume is published, its guest holds it and may rewrite its
// header; a relocated agent's volume holds the archive's bytes. Prepare,
// called again for it (a retried provisioning, a resumed restore), returns
// the same container from its journal, inode and key, and never loads that
// header in this process: a header whose derivation the guest moved to 4
// threads is returned as it is, unread and unchanged.
func TestPrepareNeverReadsThePublishedHeader(t *testing.T) {
	s, spec, key := fixture(t)
	c, err := s.Prepare(t.Context(), spec, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = lukstest.RewriteMetadata(c.Path, func(m map[string]any) {
		lukstest.Object(m, "keyslots", "0", "kdf")["cpus"] = json.Number("4")
	}); err != nil {
		t.Fatal(err)
	}
	before := header(t, c.Path)
	again, err := s.Prepare(t.Context(), spec, key)
	if err != nil || again != c {
		t.Fatal("the published container, again:", again, err)
	}
	if !bytes.Equal(header(t, c.Path), before) {
		t.Fatal("the guest's header changed")
	}
	wrong := bytes.Clone(key)
	wrong[0] ^= 1
	if _, err = s.Prepare(t.Context(), spec, wrong); !errors.Is(err, ErrConflict) {
		t.Fatal("another key:", err)
	}
}

// S-21: the check runs only confined: with a sandbox that cannot run it
// (an unconfined run, which RunSelf refuses), it fails, and libcryptsetup
// never reads the header in this process instead.
func TestCheckContainerNeverRunsInThisProcess(t *testing.T) {
	scratch, spec, key := scratchCopy(t)
	if err := CheckContainer(t.Context(), sandbox.Options{Unconfined: true}, scratch, spec.VolumeID, key); !errors.Is(err, sandbox.ErrUnavailable) {
		t.Fatal("an unconfined check:", err)
	}
	if err := CheckContainer(t.Context(), sandbox.Options{TestTools: true}, scratch, spec.VolumeID, key); !errors.Is(err, sandbox.ErrUnavailable) {
		t.Fatal("a check under the test tools' filter:", err)
	}
}

// S-21: the shape the check accepts is the platform's, read from the JSON
// libcryptsetup loaded: one key slot, one segment, one digest, no token, no
// requirement, and the bounds of the key derivation.
func TestPlatformHeaderShape(t *testing.T) {
	scratch, _, _ := scratchCopy(t)
	var platform map[string]any
	if err := lukstest.RewriteMetadata(scratch, func(m map[string]any) { platform = m }); err != nil {
		t.Fatal(err)
	}
	encode := func(edit func(map[string]any)) []byte {
		b, _ := json.Marshal(platform)
		var m map[string]any
		d := json.NewDecoder(strings.NewReader(string(b)))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		b, _ = json.Marshal(m)
		return b
	}
	if err := platformHeader(encode(func(map[string]any) {})); err != nil {
		t.Fatal("the platform's own header:", err)
	}
	kdf := func(m map[string]any) map[string]any { return lukstest.Object(m, "keyslots", "0", "kdf") }
	for name, edit := range map[string]func(map[string]any){
		"Argon2id at the bounds' end": func(m map[string]any) {
			kdf(m)["time"], kdf(m)["memory"] = json.Number("16"), json.Number("65536")
			lukstest.Object(m, "digests", "0")["iterations"] = json.Number("2000000")
		},
	} {
		if err := platformHeader(encode(edit)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, edit := range map[string]func(map[string]any){
		"17 passes":             func(m map[string]any) { kdf(m)["time"] = json.Number("17") },
		"no pass":               func(m map[string]any) { kdf(m)["time"] = json.Number("0") },
		"65537 KiB":             func(m map[string]any) { kdf(m)["memory"] = json.Number("65537") },
		"a number past 64 bits": func(m map[string]any) { kdf(m)["memory"] = json.Number("18446744073709551617") },
		"2 threads":             func(m map[string]any) { kdf(m)["cpus"] = json.Number("2") },
		"2000001 iterations": func(m map[string]any) {
			lukstest.Object(m, "digests", "0")["iterations"] = json.Number("2000001")
		},
		"a second key slot": func(m map[string]any) {
			lukstest.Object(m, "keyslots")["1"] = lukstest.Object(m, "keyslots", "0")
		},
		"a second segment": func(m map[string]any) {
			lukstest.Object(m, "segments")["1"] = lukstest.Object(m, "segments", "0")
		},
		"no digest": func(m map[string]any) { m["digests"] = map[string]any{} },
		"a requirement": func(m map[string]any) {
			lukstest.Object(m, "config")["requirements"] = map[string]any{"mandatory": []any{"online-reencrypt-v2"}}
		},
		"another cipher":    func(m map[string]any) { lukstest.Object(m, "segments", "0")["encryption"] = "aes-cbc-essiv:sha256" },
		"4096-byte sectors": func(m map[string]any) { lukstest.Object(m, "segments", "0")["sector_size"] = json.Number("4096") },
		"another splitter":  func(m map[string]any) { lukstest.Object(m, "keyslots", "0", "af")["stripes"] = json.Number("400000") },
		"a digest of another slot": func(m map[string]any) {
			lukstest.Object(m, "digests", "0")["keyslots"] = []any{"1"}
		},
	} {
		if err := platformHeader(encode(edit)); !errors.Is(err, errShape) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := platformHeader([]byte("not json")); !errors.Is(err, errShape) {
		t.Error("not JSON:", err)
	}
}
