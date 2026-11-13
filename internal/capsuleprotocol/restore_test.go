package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// A restore inspects a restored image on its restricted boot: the guest
// reports which outcomes its store holds, with the digest of each stored
// result, and nothing else. The same store answers an ordinary boot.
func TestOutcomeInspectionReadsTheStoreOnRestrictedBoots(t *testing.T) {
	store, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "harness.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	serve := func(id Identity) *Client {
		h, g, err := NewCredentials(id, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewServer(g, ShutdownClean, store, func(_ context.Context, e harnessstore.Event, _ harnessstore.SQL) ([]byte, error) {
			return []byte("done " + e.ID), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		c, _ := volumeFixture(t, h, g, s)
		return c
	}
	ordinary := serve(Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"})
	want := map[string][32]byte{}
	var ids []string
	for _, name := range []string{"first", "second"} {
		e := event(name)
		r, err := ordinary.Send(t.Context(), e)
		if err != nil {
			t.Fatal(err)
		}
		id, digest, err := harnessstore.OutcomeFingerprint("a", e, r.Result)
		if err != nil {
			t.Fatal(err)
		}
		want[id] = digest
		ids = append(ids, id)
	}
	// IDs the store never held, beyond one request: the client splits them.
	for i := range MaxOutcomeQuery + 10 {
		id, _, err := harnessstore.OutcomeFingerprint("a", event(fmt.Sprint("absent-", i)), nil)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	restricted := serve(Identity{Incarnation: 2, AgentID: "a", Generation: 2, VMID: "fedcba9876543210", FenceOnly: true})
	contract, err := restricted.Negotiate(t.Context(), []string{Version})
	if err != nil || !contract.Supports(ControlOutcomes) {
		t.Fatal("restricted boot does not offer the inspection", contract, err)
	}
	if _, err = restricted.Send(t.Context(), event("third")); !errors.Is(err, ErrFenceOnly) {
		t.Fatal("inspection opened the restricted boot to deliveries", err)
	}
	for _, c := range []*Client{ordinary, restricted} {
		held, err := c.Outcomes(t.Context(), ids)
		if err != nil || len(held) != len(want) {
			t.Fatal("inspection", len(held), err)
		}
		for id, digest := range want {
			if held[id] != digest {
				t.Fatal("held outcome or digest", id)
			}
		}
	}
	// Another agent's view of the same IDs: the store computes them for the
	// identity of this boot, so none match.
	other := serve(Identity{Incarnation: 1, AgentID: "b", Generation: 3, VMID: "00000000000000aa", FenceOnly: true})
	if held, err := other.Outcomes(t.Context(), ids[:2]); err != nil || len(held) != 0 {
		t.Fatal("outcomes of another store", held, err)
	}
	if _, err = restricted.Outcomes(t.Context(), []string{"event-id"}); !errors.Is(err, ErrProtocol) {
		t.Fatal("invalid outcome ID sent", err)
	}
	for name, query := range map[string][]string{"duplicate": {ids[0], ids[0]}, "too-many": ids[:MaxOutcomeQuery+1], "empty": nil} {
		if _, err = restricted.call(t.Context(), "/v1/outcomes", &request{Outcomes: query}); !errors.Is(err, ErrProtocol) {
			t.Fatal("invalid inspection accepted", name, err)
		}
	}
	if _, err = restricted.call(t.Context(), "/v1/outcomes", &request{Outcomes: ids[:1], Subject: "agent/a"}); !errors.Is(err, ErrProtocol) {
		t.Fatal("inspection combined with a fence", err)
	}
	if _, err = restricted.call(t.Context(), "/v1/fences", &request{Outcomes: ids[:1], Subject: "agent/a"}); !errors.Is(err, ErrProtocol) {
		t.Fatal("fence combined with an inspection", err)
	}
}

// The client trusts only the outcomes it asked about, each once, with a
// well-formed digest.
func TestOutcomeInspectionRejectsUntrustedReplies(t *testing.T) {
	asked, _, err := harnessstore.OutcomeFingerprint("a", event("asked"), nil)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := harnessstore.OutcomeFingerprint("a", event("other"), nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%064x", 7)
	for name, held := range map[string][]HeldOutcome{
		"not-asked":    {{ID: other, Digest: digest}},
		"duplicate":    {{ID: asked, Digest: digest}, {ID: asked, Digest: digest}},
		"short-digest": {{ID: asked, Digest: digest[:62]}},
		"upper-digest": {{ID: asked, Digest: "A" + digest[1:]}},
	} {
		t.Run(name, func(t *testing.T) {
			h, g := credentialPair(t, "a", "0123456789abcdef")
			c, _ := volumeFixture(t, h, g, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(response{Protocol: Version, Identity: g.Identity, Held: held})
			}))
			if _, err := c.Outcomes(t.Context(), []string{asked}); !errors.Is(err, ErrProtocol) {
				t.Fatal("untrusted inspection reply accepted", err)
			}
		})
	}
}

// Only a restricted boot carries the restore flag, never with Initialize. A
// host that predates restores sends no flag: an ordinary opening.
func TestVolumeRestoreFlagOnlyOnRestrictedBoots(t *testing.T) {
	restore := volumeCommand(false)
	restore.Restore = true
	both := restore
	both.Initialize = true
	if restore.Validate() != nil || both.Validate() == nil {
		t.Fatal("restore flag validation")
	}
	open := func(restricted bool) (*Client, chan VolumeBoot) {
		h, g := volumeCredentials(t, restricted)
		next := volumeHarness(t, g)
		seen := make(chan VolumeBoot, 1)
		s, err := NewVolumeServer(g, func(_ context.Context, v VolumeBoot, _ []byte) (http.Handler, error) {
			seen <- v
			return next, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		c, _ := volumeFixture(t, h, g, s)
		return c, seen
	}
	key := bytes.Repeat([]byte{0x24}, 32)
	c, seen := open(true)
	if err := c.OpenVolume(t.Context(), restore, key); err != nil {
		t.Fatal(err)
	}
	if v := <-seen; !v.Restore || v.Initialize {
		t.Fatal("restore flag not delivered", v)
	}
	ordinary, seen := open(false)
	if err := ordinary.OpenVolume(t.Context(), restore, key); !errors.Is(err, ErrFenceOnly) {
		t.Fatal("ordinary boot sent the restore flag", err)
	}
	raw := func(c *Client, header string) int {
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, c.endpoint("/v1/volume"), bytes.NewReader(key))
		if err != nil {
			t.Fatal(err)
		}
		v := volumeCommand(false)
		r.Header.Set("Content-Type", "application/octet-stream")
		r.Header.Set("X-Capsule-Protocol", Version)
		r.Header.Set("X-Capsule-Volume", v.VolumeID)
		r.Header.Set("X-Capsule-Incarnation", strconv.FormatUint(v.Incarnation, 10))
		r.Header.Set("X-Capsule-UUID", v.UUID)
		r.Header.Set("X-Capsule-Initialize", "false")
		r.Header.Set("X-Capsule-Previous-Shutdown", string(v.PreviousShutdown))
		if header != "" {
			r.Header.Set("X-Capsule-Restore", header)
		}
		resp, err := c.http.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if status := raw(ordinary, "true"); status != http.StatusForbidden || len(seen) != 0 {
		t.Fatal("ordinary boot accepted the restore flag", status)
	}
	if status := raw(ordinary, "yes"); status != http.StatusBadRequest || len(seen) != 0 {
		t.Fatal("malformed restore flag accepted", status)
	}
	if status := raw(ordinary, ""); status != http.StatusOK {
		t.Fatal("opening without the restore header refused", status)
	}
	if v := <-seen; v.Restore {
		t.Fatal("absent restore header read as a restore")
	}
}
