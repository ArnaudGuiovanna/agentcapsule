//go:build linux && cgo

package volumearchive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

const keyID = "keyauth_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var ciphertext = bytes.Repeat([]byte{0x58, 0x39, 0xfe, 0x17}, 8192)

func archiveLab(t *testing.T) (*Store, *restoreauthority.Catalog, Spec) {
	t.Helper()
	parent := t.TempDir()
	a, err := restoreauthority.Initialize(t.Context(), filepath.Join(parent, "authority"), keyID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	b, err := a.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(filepath.Join(parent, "archives"))
	if err != nil {
		t.Fatal(err)
	}
	return s, a, Spec{ID: "arc_" + strings.Repeat("a", 32), Binding: b, HarnessDigest: "sha256:" + strings.Repeat("b", 64), Size: int64(len(ciphertext))}
}

func assertArchive(t *testing.T, s *Store, a *restoreauthority.Catalog, spec Spec) {
	t.Helper()
	f, m, err := s.Open(t.Context(), spec.ID, a)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(data, ciphertext) || m.Binding != spec.Binding || m.HarnessDigest != spec.HarnessDigest {
		t.Fatal("archive changed", err)
	}
}

func TestArchivePublicationRetryAndAuthority(t *testing.T) {
	s, a, spec := archiveLab(t)
	first, err := s.Capture(t.Context(), spec, bytes.NewReader(ciphertext), a)
	if err != nil {
		t.Fatal(err)
	}
	s, err = New(s.root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Capture(t.Context(), spec, strings.NewReader("changed source ignored on stable-ID retry"), a)
	if err != nil || first.Digest != second.Digest || !bytes.Equal(first.MAC, second.MAC) {
		t.Fatal("lost ACK changed archive", err)
	}
	assertArchive(t, s, a, spec)
	wrong := spec
	wrong.Binding.Store = "store-b"
	if _, err = s.Capture(t.Context(), wrong, bytes.NewReader(ciphertext), a); !errors.Is(err, restoreauthority.ErrConflict) {
		t.Fatal("archive ID rebound", err)
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	if f, _, err := s.Open(t.Context(), spec.ID, a); !errors.Is(err, restoreauthority.ErrUnavailable) || f != nil {
		t.Fatal("unavailable authority ignored", err)
	}
}

func TestArchiveRejectsIncompleteAlteredAndAliasedData(t *testing.T) {
	for _, fault := range []string{"short-source", "long-source", "ciphertext", "manifest", "symlink", "hardlink", "root-replaced"} {
		t.Run(fault, func(t *testing.T) {
			s, a, spec := archiveLab(t)
			source := ciphertext
			if fault == "short-source" {
				source = source[:len(source)-1]
			}
			if fault == "long-source" {
				source = append(bytes.Clone(source), 1)
			}
			_, err := s.Capture(t.Context(), spec, bytes.NewReader(source), a)
			if strings.HasSuffix(fault, "source") {
				if err == nil {
					t.Fatal("wrong source length published")
				}
				if _, err = os.Lstat(filepath.Join(s.root, spec.ID)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("partial archive visible", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.root, spec.ID, "volume.luks")
			switch fault {
			case "ciphertext":
				f, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteAt([]byte{0}, 10)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "manifest":
				p := filepath.Join(s.root, spec.ID, "manifest.json")
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				var m restoreauthority.Archive
				if err = json.Unmarshal(b, &m); err != nil {
					t.Fatal(err)
				}
				m.Binding.Volume = "another-volume"
				b, _ = json.Marshal(m)
				if err = os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err = os.Rename(path, path+".other"); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(path+".other", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err = os.Link(path, path+".other"); err != nil {
					t.Fatal(err)
				}
			case "root-replaced":
				if err = os.Rename(s.root, s.root+".old"); err != nil {
					t.Fatal(err)
				}
				if err = os.Mkdir(s.root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if f, _, err := s.Open(t.Context(), spec.ID, a); err == nil || f != nil {
				t.Fatal("altered archive accepted", err)
			}
		})
	}
}

type archiveCrash struct {
	Root, Authority, Identity, Boundary string
	Spec                                Spec
}

func TestArchiveProcessCrashPublication(t *testing.T) {
	for _, boundary := range []string{"image_synced", "manifest_synced", "archive_published", "archive_synced"} {
		t.Run(boundary, func(t *testing.T) {
			s, a, spec := archiveLab(t)
			input := archiveCrash{Root: s.root, Authority: filepath.Join(filepath.Dir(s.root), "authority"), Identity: a.Identity(), Boundary: boundary, Spec: spec}
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestArchiveCrashChild$", "-test.v")
			cmd.Env = append(os.Environ(), "AC_ARCHIVE_CHILD="+string(encoded))
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("expected publication interruption: %v %s", err, output)
			}
			if boundary == "image_synced" || boundary == "manifest_synced" {
				if f, _, err := s.Open(t.Context(), spec.ID, a); !errors.Is(err, os.ErrNotExist) || f != nil {
					t.Fatal("partial publication accepted", err)
				}
			} else {
				assertArchive(t, s, a, spec)
			}
			if _, err = s.Capture(t.Context(), spec, bytes.NewReader(ciphertext), a); err != nil {
				t.Fatal("retry after process death", err)
			}
			assertArchive(t, s, a, spec)
		})
	}
}

func TestArchiveCrashChild(t *testing.T) {
	encoded := os.Getenv("AC_ARCHIVE_CHILD")
	if encoded == "" {
		return
	}
	var input archiveCrash
	if err := json.Unmarshal([]byte(encoded), &input); err != nil {
		t.Fatal(err)
	}
	a, err := restoreauthority.Open(t.Context(), input.Authority, input.Identity, keyID)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	s, err := New(input.Root)
	if err != nil {
		t.Fatal(err)
	}
	s.hook = func(stage string) {
		if stage == input.Boundary {
			if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err = s.Capture(t.Context(), input.Spec, bytes.NewReader(ciphertext), a); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash boundary was not reached")
}
