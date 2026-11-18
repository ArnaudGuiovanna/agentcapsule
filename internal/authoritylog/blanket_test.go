package authoritylog

import (
	"testing"
	"time"
)

// A blanket record names the failover and the window from the standby's
// last contact, in objects that a record may carry, and reads back the
// same; its ID is one per promotion (ADR 005, item 14).
func TestBlanketRecordReadsBack(t *testing.T) {
	failover := time.Date(2026, 11, 16, 10, 0, 30, 123_000_000, time.FixedZone("CET", 3600))
	b := Blanket{IssuedBefore: failover, WindowFrom: failover.Add(-5 * time.Minute)}
	objects := b.Objects()
	if !ValidAccessObjects(objects) {
		t.Fatal("a blanket record's objects are not valid objects", objects)
	}
	got, ok := ParseBlanket(objects)
	if !ok || !got.IssuedBefore.Equal(b.IssuedBefore) || !got.WindowFrom.Equal(b.WindowFrom) {
		t.Fatal("read back", got, ok)
	}
	for _, bad := range [][][]string{nil, {objects[0]}, {objects[1], objects[0]},
		{{"issued_before", "yesterday"}, objects[1]},
		{objects[0], {"window", objects[0][1], objects[0][1] + "x"}},
		{objects[0], {"window", failover.Add(time.Hour).UTC().Format(time.RFC3339Nano), objects[0][1]}}} {
		if _, ok := ParseBlanket(bad); ok {
			t.Fatal("a malformed blanket record was read", bad)
		}
	}
	id := BlanketID("restoreauth_0123456789abcdef0123456789abcdef", 2)
	if !ValidID(id, "arv_") || id != BlanketID("restoreauth_0123456789abcdef0123456789abcdef", 2) ||
		id == BlanketID("restoreauth_0123456789abcdef0123456789abcdef", 3) {
		t.Fatal("blanket IDs", id)
	}
	if bearer, known := AccessBearer(AccessBlanket); !bearer || !known {
		t.Fatal("the blanket is a bearer tokens' revocation")
	}
}
