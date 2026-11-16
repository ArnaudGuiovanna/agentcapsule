package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// The readiness probe reports the authority service (ADR 006, wave 4): its
// mode while it answers with the pinned identities, and 503
// authority_unavailable when it does not. Degraded mode and the wait for the
// replica are reported, not refused: the API itself still serves. Without
// the service (development mode only), the probe does not name it.
func TestReadinessReportsTheAuthorityService(t *testing.T) {
	server, _, _, _ := apiLab(t)
	ready := func() (int, map[string]any) {
		t.Helper()
		r := call(t, server, "GET", "/v1/health/ready", "", "", "")
		var body map[string]any
		if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
			t.Fatal(err, r.Body.String())
		}
		return r.Code, body
	}
	if code, body := ready(); code != 200 || body["status"] != "ready" || len(body) != 1 {
		t.Fatal("without the authority service", code, body)
	}
	mode, failure := "", error(nil)
	server.ReportAuthority(func(ctx context.Context) (string, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("the probe has no deadline")
		}
		return mode, failure
	})
	for _, mode = range []string{"standalone", "synchronous", "degraded", "waiting"} {
		if code, body := ready(); code != 200 || body["status"] != "ready" || body["authority"] != mode {
			t.Fatal(mode, code, body)
		}
	}
	failure = errors.New("the authority service does not answer")
	if code, body := ready(); code != 503 || body["code"] != "authority_unavailable" {
		t.Fatal("an authority service that does not answer", code, body)
	}
	// A service that hangs: the probe gives up before the request's own
	// deadline.
	server.ReportAuthority(func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	})
	start := time.Now()
	if code, body := ready(); code != 503 || body["code"] != "authority_unavailable" || time.Since(start) > 5*time.Second {
		t.Fatal("a hung authority service", code, body, time.Since(start))
	}
}
