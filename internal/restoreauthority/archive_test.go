//go:build linux && cgo

package restoreauthority

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestArchiveAuthenticationDoesNotAuthorizeActivation(t *testing.T) {
	c, b := fixture(t)
	a, err := c.SignArchive(t.Context(), Archive{ID: "arc_" + strings.Repeat("a", 32), Binding: b, HarnessDigest: "sha256:" + strings.Repeat("a", 64), Size: 4096, Digest: sha256.Sum256([]byte("ciphertext"))})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.ValidateArchive(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Archive){
		func(x *Archive) { x.Binding.Store = "different" }, func(x *Archive) { x.Binding.Volume = "different" },
		func(x *Archive) { x.Binding.Incarnation++ }, func(x *Archive) { x.Digest[0] ^= 1 },
		func(x *Archive) { x.Size++ }, func(x *Archive) { x.HarnessDigest = "sha256:" + strings.Repeat("b", 64) },
	} {
		x := a
		mutate(&x)
		if err = c.ValidateArchive(t.Context(), x); err == nil {
			t.Fatal("altered metadata authenticated")
		}
	}
	next, err := c.ReserveIncarnation(t.Context(), b, "restore")
	if err != nil {
		t.Fatal(err)
	}
	if err = c.ValidateArchive(t.Context(), a); err != nil {
		t.Fatal("historical archive cannot be inspected", err)
	}
	if _, err = c.SignArchive(t.Context(), a); !errors.Is(err, ErrStale) {
		t.Fatal("old incarnation signed a new archive", err)
	}
	if err = c.WithBinding(t.Context(), b, func() error { t.Error("archive reactivated old incarnation"); return nil }); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	if err = c.RecordRetiredSeal(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	if err = c.ValidateArchive(t.Context(), a); !errors.Is(err, ErrSealed) {
		t.Fatal("sealed store archive accepted", err)
	}
}
