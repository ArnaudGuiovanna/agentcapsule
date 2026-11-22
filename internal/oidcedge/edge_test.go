package oidcedge

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAllowedPaths(t *testing.T) {
	for _, p := range []string{
		"/realms/agentcapsule/.well-known/openid-configuration",
		"/realms/agentcapsule/protocol/openid-connect/auth",
		"/realms/agentcapsule/protocol/openid-connect/token",
		"/realms/agentcapsule/protocol/openid-connect/certs",
		"/realms/agentcapsule/login-actions/authenticate",
		"/realms/agentcapsule/account/",
		"/realms/test-realm/protocol/openid-connect/auth",
		"/resources/abc12/login/keycloak.v2/css/styles.css",
	} {
		if !Allowed(p) {
			t.Errorf("refused %s", p)
		}
	}
	for _, p := range []string{
		"", "/", "/admin/", "/admin/master/console/", "/admin/realms/agentcapsule/users",
		"/realms/master/protocol/openid-connect/token", "/realms/master/", "/realms/", "/realms/agentcapsule",
		"/realms//protocol", "/resources/", "/metrics", "/health/ready", "/js/keycloak.js", "/.well-known/",
		"/realms/agentcapsule/../../admin/realms", "/realms/agentcapsule/./x", "/realms/agentcapsule//x",
		"/realms/agentcapsule/%2e%2e/admin", "/realms/agentcapsule;x/../../admin", "/realms/agentcapsule\\..\\admin",
		"realms/agentcapsule/x", "/resources/../admin/",
	} {
		if Allowed(p) {
			t.Errorf("allowed %q", p)
		}
	}
}

func TestHandlerForwardsOnlyAllowedRequests(t *testing.T) {
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RequestURI())
		fmt.Fprintf(w, "host=%s xff=%s proto=%s fwd=%s", r.Host, r.Header.Get("X-Forwarded-For"),
			r.Header.Get("X-Forwarded-Proto"), r.Header.Get("Forwarded"))
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	edge := httptest.NewTLSServer(Handler(target))
	defer edge.Close()
	client := edge.Client()

	req, _ := http.NewRequest(http.MethodGet, edge.URL+"/realms/agentcapsule/.well-known/openid-configuration?x=1", nil)
	req.Host = "id.example.net:9444"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("Forwarded", "for=203.0.113.9")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "host=id.example.net:9444 xff=127.0.0.1 proto=https fwd=") ||
		!strings.HasSuffix(string(body), "fwd=") {
		t.Fatalf("forwarded: %d %q", resp.StatusCode, body)
	}
	if len(seen) != 1 || seen[0] != "/realms/agentcapsule/.well-known/openid-configuration?x=1" {
		t.Fatalf("upstream saw %v", seen)
	}

	for _, p := range []string{"/admin/master/console/", "/admin/realms/agentcapsule", "/realms/master/protocol/openid-connect/token",
		"/metrics", "/realms/agentcapsule/%2e%2e/%2e%2e/admin/realms", "/realms/agentcapsule/..%2f..%2fadmin"} {
		resp, err := client.Get(edge.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	if len(seen) != 1 {
		t.Fatalf("refused requests reached Keycloak: %v", seen)
	}
}

func TestHandlerBoundsTheBody(t *testing.T) {
	var received int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received = int(n)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	edge := httptest.NewServer(Handler(target))
	defer edge.Close()
	resp, err := http.Post(edge.URL+"/realms/agentcapsule/protocol/openid-connect/token", "application/x-www-form-urlencoded",
		strings.NewReader(strings.Repeat("a", MaxBody+1)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK || received > MaxBody {
		t.Fatalf("an oversized body passed: %d, %d bytes", resp.StatusCode, received)
	}
}

func TestRawDotSegmentsAreRefused(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	edge := httptest.NewServer(Handler(target))
	defer edge.Close()
	for _, line := range []string{
		"GET /realms/agentcapsule/../../admin/realms HTTP/1.1",
		"GET /realms/agentcapsule/%2e%2e/%2e%2e/admin/realms HTTP/1.1",
		"GET /realms/agentcapsule;a/../../admin/realms HTTP/1.1",
		"GET //admin/realms HTTP/1.1",
	} {
		conn, err := net.Dial("tcp", strings.TrimPrefix(edge.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "%s\r\nHost: id.example.net\r\nConnection: close\r\n\r\n", line)
		status, err := bufio.NewReader(conn).ReadString('\n')
		conn.Close()
		if err != nil || !strings.Contains(status, " 404 ") && !strings.Contains(status, " 400 ") && !strings.Contains(status, " 301 ") {
			t.Errorf("%s: %q, %v", line, status, err)
		}
	}
	if reached {
		t.Fatal("a raw dot segment reached Keycloak")
	}
}

func TestServerBoundsItsRequests(t *testing.T) {
	s := Server(http.NotFoundHandler())
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 || s.IdleTimeout == 0 || s.MaxHeaderBytes == 0 {
		t.Fatalf("unbounded server: %+v", s)
	}
}
