// Package oidcedge is the public listener of the bundled identity provider
// (S-19). Keycloak listens on loopback only; this edge serves its TLS
// certificate on the public port and forwards only what browsers and
// applications need: the realms' pages and endpoints, and the static files.
// The administration console and its REST API (/admin/), the master realm,
// health and metrics never leave the host: operators reach them on the
// loopback listener, through SSH.
package oidcedge

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"
)

// MaxBody bounds a request's body: login forms and token requests are small.
const MaxBody = 1 << 20

// Allowed tells whether a request path may reach Keycloak from outside: a
// canonical path under /resources/ or under /realms/NAME/ for a realm other
// than master. A path with an escape, a parameter (;), a backslash or a dot
// segment is refused, whatever Keycloak would make of it.
func Allowed(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "%;\\") {
		return false
	}
	canonical := path.Clean(p)
	if strings.HasSuffix(p, "/") && canonical != "/" {
		canonical += "/"
	}
	if canonical != p {
		return false
	}
	if strings.HasPrefix(p, "/resources/") && len(p) > len("/resources/") {
		return true
	}
	rest, ok := strings.CutPrefix(p, "/realms/")
	if !ok {
		return false
	}
	realm, _, more := strings.Cut(rest, "/")
	return more && realm != "" && realm != "master"
}

// Handler forwards allowed requests to upstream (Keycloak's loopback
// listener) with the X-Forwarded headers Keycloak trusts from loopback, and
// answers 404 to every other one.
func Handler(upstream *url.URL) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			r.Out.Host = r.In.Host
			r.Out.Header.Del("Forwarded")
			r.SetXForwarded()
		},
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "identity provider unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawPath != "" || !Allowed(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
		proxy.ServeHTTP(w, r)
	})
}

// Server is the edge's HTTP server, with the bounds a public listener needs.
func Server(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}
