package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type appKey struct {
	Kty, Kid, N, E string
}

type registration struct {
	ID               string   `json:"id"`
	Tenant           string   `json:"tenant_id"`
	Issuer           string   `json:"issuer"`
	ClientID         string   `json:"client_id"`
	Audience         string   `json:"audience"`
	RedirectURIs     []string `json:"redirect_uris"`
	Policies         []string `json:"policy_ids"`
	Status           string   `json:"status"`
	VerificationKeys []appKey `json:"verification_keys"`
}

func (a registration) discoveryURL() string {
	return strings.TrimRight(a.Issuer, "/") + "/.well-known/openid-configuration"
}

func (cli console) applicationCommand(ctx context.Context, a action, c connection, r reply, issuerCA string) error {
	var app registration
	u, _ := url.ParseRequestURI(a.path) // buildAction validated the API route.
	if json.Unmarshal(r.Data, &app) != nil || app.ID == "" || app.ID != strings.TrimPrefix(u.Path, "/v1/applications/") ||
		app.Tenant != c.Organization || app.Issuer == "" {
		return errors.New("invalid application connection response")
	}
	if a.name == "app verify" {
		return cli.verifyApplication(ctx, app, issuerCA, r.RequestID)
	}
	// Select public fields for the developer handoff, including for disabled registrations.
	return cli.print(map[string]any{"api_url": c.URL, "application_id": app.ID, "organization_id": app.Tenant, "issuer": app.Issuer,
		"discovery_url": app.discoveryURL(), "client_id": app.ClientID, "audience": app.Audience,
		"redirect_uris": app.RedirectURIs, "policy_ids": app.Policies, "status": app.Status,
		"response_type": "code", "code_challenge_method": "S256"}, r.RequestID)
}

func httpsEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && !strings.Contains(raw, "#")
}

// Discovery and JWKS use public requests on a separate client with the issuer's trust roots.
func getIssuerDocument(ctx context.Context, h *http.Client, raw string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return errors.New("invalid issuer endpoint")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := h.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var transport *url.Error
		if errors.As(err, &transport) {
			err = transport.Err
		}
		return fmt.Errorf("issuer transport: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("issuer returned HTTP %d", resp.StatusCode)
	}
	data, err := readBounded(resp.Body, maxDocument)
	if err != nil {
		return err
	}
	if json.Unmarshal(data, dst) != nil {
		return errors.New("invalid issuer document")
	}
	return nil
}

func (cli console) verifyApplication(ctx context.Context, app registration, ca, requestID string) error {
	if app.Status != "active" {
		return errors.New("application is not active")
	}
	if !httpsEndpoint(app.Issuer) || strings.Contains(app.Issuer, "?") {
		return errors.New("expected a registered HTTPS issuer without a query")
	}
	h, err := httpsClient(ca)
	if err != nil {
		return err
	}
	defer h.CloseIdleConnections()
	var meta struct {
		Issuer        string   `json:"issuer"`
		Authorization string   `json:"authorization_endpoint"`
		Token         string   `json:"token_endpoint"`
		JWKS          string   `json:"jwks_uri"`
		ResponseTypes []string `json:"response_types_supported"`
		Grants        []string `json:"grant_types_supported"`
		Challenges    []string `json:"code_challenge_methods_supported"`
	}
	if err := getIssuerDocument(ctx, h, app.discoveryURL(), &meta); err != nil {
		return fmt.Errorf("OIDC discovery: %w", err)
	}
	if meta.Issuer != app.Issuer {
		return errors.New("OIDC discovery issuer differs from the registration")
	}
	if !httpsEndpoint(meta.Authorization) || !httpsEndpoint(meta.Token) || !httpsEndpoint(meta.JWKS) {
		return errors.New("OIDC discovery requires HTTPS authorization, token and JWKS endpoints")
	}
	if !slices.Contains(meta.ResponseTypes, "code") || (meta.Grants != nil && !slices.Contains(meta.Grants, "authorization_code")) {
		return errors.New("OIDC discovery does not support the authorization code flow")
	}
	pkce := "unadvertised"
	if meta.Challenges != nil {
		if !slices.Contains(meta.Challenges, "S256") {
			return errors.New("OIDC discovery excludes S256 PKCE")
		}
		pkce = "S256"
	}
	var jwks struct {
		Keys []struct {
			appKey
			Alg, Use string
			Ops      []string `json:"key_ops"`
		} `json:"keys"`
	}
	if err := getIssuerDocument(ctx, h, meta.JWKS, &jwks); err != nil {
		return fmt.Errorf("OIDC JWKS: %w", err)
	}
	published := make(map[appKey]bool)
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && key.Kid != "" && key.N != "" && key.E != "" && (key.Alg == "" || key.Alg == "RS256") && (key.Use == "" || key.Use == "sig") &&
			(key.Ops == nil || slices.Contains(key.Ops, "verify")) {
			published[key.appKey] = true
		}
	}
	if len(app.VerificationKeys) == 0 {
		return errors.New("registration has no pinned verification keys")
	}
	for _, key := range app.VerificationKeys {
		if !published[key] {
			return errors.New("a pinned RS256 signing key is missing or differs from the issuer JWKS")
		}
	}
	return cli.print(map[string]any{"application_id": app.ID, "organization_id": app.Tenant, "issuer": app.Issuer,
		"status": app.Status, "response_type": "code", "advertised_pkce": pkce,
		"matched_pinned_keys": len(app.VerificationKeys), "published_rs256_keys": len(published)}, requestID)
}
