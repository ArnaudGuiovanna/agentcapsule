package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

func TestControlNegotiationUsesAuthenticatedBootAndPreservesEffects(t *testing.T) {
	h, g := credentialPair(t, "a", "0123456789abcdef")
	c, _ := serverFixture(t, h, g, nil)
	features, err := c.Negotiate(t.Context(), []string{"capsule.v2", Version})
	if err != nil || features.Protocol != Version || features.Identity != h.Identity || features.Limits != (ControlLimits{MaxMessageBytes, MaxContentBytes}) {
		t.Fatal("negotiated contract", features, err)
	}
	if !reflect.DeepEqual(features.Features, []ControlFeature{ControlHealth, ControlFences, ControlEvents, ControlInvokeText}) {
		t.Fatal("unexpected control features", features.Features)
	}
	if features.Supports("llm.invoke") || features.Supports("agent:invoke") {
		t.Fatal("control negotiation invented application permissions")
	}
	e := event("after-negotiation")
	first, err := c.Send(t.Context(), e)
	if err != nil || first.Replayed || string(first.Result) != "1" {
		t.Fatal("read-only negotiation affected the application transaction", first, err)
	}
	if _, err = c.Negotiate(t.Context(), []string{Version}); err != nil {
		t.Fatal(err)
	}
	again, err := c.Send(t.Context(), e)
	if err != nil || !again.Replayed || string(again.Result) != "1" {
		t.Fatal("negotiation changed event replay", again, err)
	}
	if err = c.Fence(t.Context(), "request/r"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Negotiate(t.Context(), []string{Version}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Send(t.Context(), e); !errors.Is(err, harnessstore.ErrFenced) {
		t.Fatal("negotiation bypassed a durable fence", err)
	}
}

func TestRequiredControlContractRejectsNarrowerProfiles(t *testing.T) {
	for _, test := range []struct {
		name       string
		fenceOnly  bool
		features   []ControlFeature
		limits     ControlLimits
		compatible bool
	}{
		{"normal", false, []ControlFeature{ControlHealth, ControlFences, ControlEvents, ControlInvokeText}, ControlLimits{MaxMessageBytes, MaxContentBytes}, true},
		{"fences", true, []ControlFeature{ControlHealth, ControlFences}, ControlLimits{MaxMessageBytes, MaxContentBytes}, true},
		{"normal-without-events", false, []ControlFeature{ControlHealth, ControlFences, ControlInvokeText}, ControlLimits{MaxMessageBytes, MaxContentBytes}, false},
		{"normal-without-invoke", false, []ControlFeature{ControlHealth, ControlFences, ControlEvents}, ControlLimits{MaxMessageBytes, MaxContentBytes}, false},
		{"small-message-limit", false, []ControlFeature{ControlHealth, ControlFences, ControlEvents, ControlInvokeText}, ControlLimits{MaxMessageBytes - 1, MaxContentBytes}, false},
		{"small-content-limit", true, []ControlFeature{ControlHealth, ControlFences}, ControlLimits{MaxMessageBytes, MaxContentBytes - 1}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, g := volumeCredentials(t, test.fenceOnly)
			client, _ := volumeFixture(t, h, g, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/capabilities" || r.Header.Get(AcceptProtocolHeader) != Version {
					t.Error("admission attempted an alternate protocol or endpoint")
				}
				w.Header().Set("X-Capsule-Protocol", Version)
				_ = json.NewEncoder(w).Encode(capabilitiesResponse{Protocol: Version, Identity: g.Identity,
					Features: test.features, Limits: &test.limits})
			}))
			// Discovery can describe a narrower peer, but the current client
			// must not promise application readiness for that peer.
			if _, err := client.Negotiate(t.Context(), []string{Version}); err != nil {
				t.Fatal("fixture is not a valid discoverable contract", err)
			}
			err := client.RequireControlContract(t.Context())
			if (err == nil) != test.compatible || (!test.compatible && !errors.Is(err, ErrUnsupportedProtocol)) {
				t.Fatal("unexpected admission decision", err)
			}
		})
	}
}

func TestControlNegotiationRejectsIncompatibleAndAmbiguousOffers(t *testing.T) {
	h, g := credentialPair(t, "a", "0123456789abcdef")
	c, _ := serverFixture(t, h, g, nil)
	if _, err := c.Negotiate(t.Context(), []string{"capsule.v2"}); !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatal("incompatible protocol accepted", err)
	}
	for _, offered := range [][]string{nil, {""}, {"capsule.v0"}, {"capsule.v01"}, {"capsule.v1 "}, {"capsule.v1.1"}, {"*"}, {Version, Version}, {"capsule.v1", "capsule.v2", "capsule.v3", "capsule.v4", "capsule.v5", "capsule.v6", "capsule.v7", "capsule.v8", "capsule.v9"}} {
		if _, err := c.Negotiate(t.Context(), offered); !errors.Is(err, ErrProtocol) {
			t.Fatal("malformed client offer accepted", offered, err)
		}
	}
	// Bypass the client validator to exercise the server's wire boundary.
	tests := []struct {
		name   string
		values []string
		path   string
		method string
		body   string
	}{
		{name: "missing-offer"},
		{name: "duplicate-offer", values: []string{Version + ", " + Version}},
		{name: "multiple-headers", values: []string{Version, "capsule.v2"}},
		{name: "empty-member", values: []string{Version + ","}},
		{name: "malformed-version", values: []string{"capsule.v-1"}},
		{name: "non-http-whitespace", values: []string{"\u00a0" + Version}},
		{name: "oversized-offer", values: []string{strings.Repeat("a", maxProtocolOfferBytes+1)}},
		{name: "caller-identity-query", values: []string{Version}, path: "/v1/capabilities?agent_id=foreign"},
		{name: "caller-identity-body", values: []string{Version}, body: `{"agent_id":"foreign"}`},
		{name: "post-method", values: []string{Version}, method: http.MethodPost},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, method := test.path, test.method
			if path == "" {
				path = "/v1/capabilities"
			}
			if method == "" {
				method = http.MethodGet
			}
			r, err := http.NewRequestWithContext(t.Context(), method, c.endpoint(path), strings.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range test.values {
				r.Header.Add(AcceptProtocolHeader, value)
			}
			resp, err := c.http.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatal("invalid negotiation reached a successful response", resp.StatusCode)
			}
		})
	}
}

func TestCapabilitiesAreDeterministicAndIdentityHeadersAreIgnored(t *testing.T) {
	h, g := credentialPair(t, "a", "0123456789abcdef")
	c, _ := serverFixture(t, h, g, nil)
	var previous []byte
	for i := range 3 {
		r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, c.endpoint("/v1/capabilities"), nil)
		r.Header.Set(AcceptProtocolHeader, "capsule.v2, "+Version)
		r.Header.Set("X-Agent-ID", "foreign")
		r.Header.Set("X-Tenant-ID", "foreign-tenant")
		resp, err := c.http.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || len(body) > MaxCapabilitiesBytes || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("invalid response boundary", resp.StatusCode, err)
		}
		var out capabilitiesResponse
		if err = decode(bytes.NewReader(body), &out); err != nil || out.Identity != h.Identity {
			t.Fatal("caller header changed boot identity", out, err)
		}
		if bytes.Contains(body, []byte("foreign")) || bytes.Contains(body, []byte("tenant")) || bytes.Contains(body, []byte("/run/")) {
			t.Fatal("response includes caller-supplied identity or private path")
		}
		if i > 0 && !bytes.Equal(previous, body) {
			t.Fatal("unchanged capabilities are not deterministic")
		}
		previous = body
	}
}

func TestCapabilitiesRequireAuthenticationAndRespectFenceOnly(t *testing.T) {
	h, g, err := NewCredentials(Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef", FenceOnly: true}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, dial := serverFixture(t, h, g, nil)
	out, err := c.Negotiate(t.Context(), []string{Version})
	if err != nil || !reflect.DeepEqual(out.Features, []ControlFeature{ControlHealth, ControlFences}) {
		t.Fatal("restricted boot advertised application handlers", out, err)
	}
	if _, err = c.Send(t.Context(), event("restricted")); !errors.Is(err, ErrFenceOnly) {
		t.Fatal("negotiation relaxed restricted boot", err)
	}
	foreign, _ := credentialPair(t, "foreign", "fedcba9876543210")
	bad, err := NewClient(foreign, dial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bad.Negotiate(t.Context(), []string{Version}); !errors.Is(err, ErrTransport) {
		t.Fatal("foreign certificate negotiated another boot", err)
	}
	store, err := harnessstore.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s, err := NewServer(g, ShutdownClean, store, func(context.Context, harnessstore.Event, harnessstore.SQL) ([]byte, error) {
		t.Error("negotiation executed a mutation")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	r.Header.Set(AcceptProtocolHeader, Version)
	r.Header.Set("X-Authenticated", "true")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("header substituted for transport authentication")
	}
}

func TestCapabilitiesDoNotConfuseLegacyOrUnpreparedBootWithNegotiation(t *testing.T) {
	h, g := volumeCredentials(t, false)
	var healthCalls atomic.Int32
	legacy, _ := volumeFixture(t, h, g, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := response{Protocol: Version, Identity: g.Identity}
		if r.URL.Path == "/v1/health" {
			healthCalls.Add(1)
			out.PreviousShutdown = ShutdownClean
		} else {
			out.Code = "unknown_operation"
			w.WriteHeader(http.StatusNotFound)
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	if err := legacy.Health(t.Context()); err != nil {
		t.Fatal("historical health contract changed", err)
	}
	if _, err := legacy.Negotiate(t.Context(), []string{Version}); !errors.Is(err, ErrCapabilitiesUnavailable) || healthCalls.Load() != 1 {
		t.Fatal("legacy endpoint silently accepted or health fallback attempted", err)
	}
	next := volumeHarness(t, g)
	server, err := NewQuiescingVolumeServer(g, func(context.Context, VolumeBoot, []byte) (http.Handler, error) {
		return next, nil
	}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	c, _ := volumeFixture(t, h, g, server)
	if _, err = c.Negotiate(t.Context(), []string{Version}); !errors.Is(err, ErrTransport) {
		t.Fatal("unprepared boot advertised a ready harness", err)
	}
	if err = c.OpenVolume(t.Context(), volumeCommand(false), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Negotiate(t.Context(), []string{Version}); err != nil {
		t.Fatal("prepared proxy did not carry capabilities", err)
	}
	if err = c.Quiesce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Negotiate(t.Context(), []string{Version}); !errors.Is(err, ErrTransport) {
		t.Fatal("quiesced boot still advertised readiness", err)
	}
}

func TestCapabilitiesRejectMalformedOrMisboundResponses(t *testing.T) {
	tests := []struct {
		name   string
		change func(*capabilitiesResponse, http.Header)
		want   error
	}{
		{"wrong-identity", func(r *capabilitiesResponse, _ http.Header) { r.Identity.AgentID = "foreign" }, ErrIdentity},
		{"wrong-generation", func(r *capabilitiesResponse, _ http.Header) { r.Identity.Generation++ }, ErrIdentity},
		{"other-protocol", func(r *capabilitiesResponse, _ http.Header) { r.Protocol = "capsule.v2" }, ErrUnsupportedProtocol},
		{"missing-selection", func(_ *capabilitiesResponse, h http.Header) { h.Del("X-Capsule-Protocol") }, ErrProtocol},
		{"ambiguous-selection", func(_ *capabilitiesResponse, h http.Header) { h.Add("X-Capsule-Protocol", "capsule.v2") }, ErrProtocol},
		{"missing-limits", func(r *capabilitiesResponse, _ http.Header) { r.Limits = nil }, ErrProtocol},
		{"negative-limit", func(r *capabilitiesResponse, _ http.Header) { r.Limits.ContentBytes = -1 }, ErrProtocol},
		{"unbounded-limit", func(r *capabilitiesResponse, _ http.Header) { r.Limits.MessageBytes = MaxMessageBytes + 1 }, ErrProtocol},
		{"missing-fence", func(r *capabilitiesResponse, _ http.Header) {
			r.Features = []ControlFeature{ControlHealth, ControlEvents}
		}, ErrProtocol},
		{"duplicate-feature", func(r *capabilitiesResponse, _ http.Header) {
			r.Features = []ControlFeature{ControlHealth, ControlFences, ControlFences}
		}, ErrProtocol},
		{"permission-as-feature", func(r *capabilitiesResponse, _ http.Header) { r.Features[3] = "platform:admin" }, ErrProtocol},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h, g := credentialPair(t, "a", "0123456789abcdef")
			c, _ := volumeFixture(t, h, g, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				out := capabilitiesResponse{Protocol: Version, Identity: g.Identity, Features: controlFeatures(g.Identity), Limits: &ControlLimits{MaxMessageBytes, MaxContentBytes}}
				w.Header().Set("X-Capsule-Protocol", Version)
				test.change(&out, w.Header())
				_ = json.NewEncoder(w).Encode(out)
			}))
			out, err := c.Negotiate(t.Context(), []string{Version})
			if !errors.Is(err, test.want) || !reflect.DeepEqual(out, ControlCapabilities{}) {
				t.Fatal("untrusted capabilities accepted", out, err)
			}
		})
	}
	for name, body := range map[string]string{"oversized": strings.Repeat(" ", MaxCapabilitiesBytes+1), "trailing-json": `{} {}`, "unknown-fields": `{"roles":["org_owner"]}`} {
		t.Run(name, func(t *testing.T) {
			h, g := credentialPair(t, "a", "0123456789abcdef")
			c, _ := volumeFixture(t, h, g, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
			if _, err := c.Negotiate(t.Context(), []string{Version}); !errors.Is(err, ErrProtocol) {
				t.Fatal("malformed capability response accepted", err)
			}
		})
	}
	t.Run("fence-only-business-feature", func(t *testing.T) {
		h, g := volumeCredentials(t, true)
		c, _ := volumeFixture(t, h, g, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Capsule-Protocol", Version)
			_ = json.NewEncoder(w).Encode(capabilitiesResponse{
				Protocol: Version, Identity: g.Identity,
				Features: []ControlFeature{ControlHealth, ControlFences, ControlEvents},
				Limits:   &ControlLimits{MaxMessageBytes, MaxContentBytes},
			})
		}))
		if _, err := c.Negotiate(t.Context(), []string{Version}); !errors.Is(err, ErrProtocol) {
			t.Fatal("restricted boot advertised business execution", err)
		}
	})
}
