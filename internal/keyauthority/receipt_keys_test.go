//go:build linux

package keyauthority

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A daily receipt key is a key of a reserved binding: the reserved agent and
// a volume ID that names its day (docs/adr/006-authority-service.md §7). The
// binding is a valid one, so the key is written, replicated and promoted as a
// volume key is; it names exactly one day, and no other binding names one.
func TestReceiptKeyBindingNamesOneDay(t *testing.T) {
	day := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	volume := ReceiptKeyVolume(day)
	if !valid(ReceiptKeyAgent, "agt_") || !valid(volume, "vol_") || volume != "vol_00000000000000000000000020261116" {
		t.Fatal("the binding is not a key authority binding", ReceiptKeyAgent, volume)
	}
	// Any time of the day names it, in UTC.
	late := time.Date(2026, 11, 16, 23, 59, 59, 0, time.UTC).In(time.FixedZone("east", 5*3600))
	if ReceiptKeyVolume(late) != volume {
		t.Fatal("a time of the day names another day", ReceiptKeyVolume(late))
	}
	got, ok := ReceiptKeyDay(ReceiptKeyAgent, volume)
	if !ok || !got.Equal(day) || got.Location() != time.UTC {
		t.Fatal("the day of the binding", got, ok)
	}
	for name, b := range map[string][2]string{
		"a volume key":           {testAgent, testVolume},
		"another agent":          {testAgent, volume},
		"the agent, a volume":    {ReceiptKeyAgent, testVolume},
		"no such date":           {ReceiptKeyAgent, "vol_00000000000000000000000020261332"},
		"a date not in its form": {ReceiptKeyAgent, "vol_000000000000000000000000+2026111"},
		"short":                  {ReceiptKeyAgent, "vol_0000000000000000000000002026111"},
	} {
		if _, ok := ReceiptKeyDay(b[0], b[1]); ok {
			t.Fatal(name, "names a day")
		}
	}
}

// ReceiptKeys lists the days whose key the authority holds, in order: not a
// volume key, not a destroyed day's, and a key whose creation did not
// complete is listed as not usable.
func TestReceiptKeysListsTheDaysHeld(t *testing.T) {
	s := fixture(t)
	days := []time.Time{
		time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC),
	}
	for _, d := range days {
		if err := s.Ensure(t.Context(), ReceiptKeyAgent, ReceiptKeyVolume(d)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Ensure(t.Context(), testAgent, testVolume); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(t.Context(), ReceiptKeyAgent, ReceiptKeyVolume(days[0])); err != nil {
		t.Fatal(err)
	}
	// Each day has its own key.
	var first, second []byte
	for i, out := range []*[]byte{&first, &second} {
		if err := s.WithKey(t.Context(), ReceiptKeyAgent, ReceiptKeyVolume(days[i+1]), func(k []byte) error {
			*out = bytes.Clone(k)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(first) != 32 || bytes.Equal(first, second) {
		t.Fatal("two days share a key")
	}
	if err := s.WithKey(t.Context(), ReceiptKeyAgent, ReceiptKeyVolume(days[0]), func([]byte) error { return nil }); !errors.Is(err, ErrRevoked) {
		t.Fatal("a destroyed day's key is readable", err)
	}
	held, err := s.ReceiptKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 2 || !held[0].Day.Equal(days[1]) || !held[1].Day.Equal(days[2]) || !held[0].Usable || !held[1].Usable {
		t.Fatal("held", held)
	}
	// A key published without its allocation marker, as a journaled
	// creation leaves it until the replica holds it, is not usable yet.
	pending := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	b, err := record("ACPKEY01", ReceiptKeyAgent, ReceiptKeyVolume(pending), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer release(b)
	if err = publish(filepath.Join(s.root, "records", ReceiptKeyVolume(pending)), b, nil, nil); err != nil {
		t.Fatal(err)
	}
	if held, err = s.ReceiptKeys(); err != nil || len(held) != 3 || !held[2].Day.Equal(pending) || held[2].Usable {
		t.Fatal("a key without its marker", held, err)
	}
	// Another authority's directory is refused, as every operation does.
	if err = os.WriteFile(filepath.Join(s.root, "identity"), []byte("keyauth_00000000000000000000000000000000"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReceiptKeys(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("listed another authority's keys", err)
	}
}
