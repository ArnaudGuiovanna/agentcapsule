package controlplane

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
)

// OIDCKey is a pinned public RSA signing key from the issuer's JWKS. The
// verifier never follows a token-supplied URL, and never accepts an ID token.
type OIDCKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (k OIDCKey) key() (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.Strict().DecodeString(k.N)
	if err != nil {
		return nil, ErrInput
	}
	e, err := base64.RawURLEncoding.Strict().DecodeString(k.E)
	if err != nil || len(e) == 0 || len(e) > 4 {
		return nil, ErrInput
	}
	exponent := new(big.Int).SetBytes(e).Int64()
	number := new(big.Int).SetBytes(n)
	if k.Kty != "RSA" || !validOrganizationText(k.Kid, 200) || number.BitLen() < 2048 || number.BitLen() > 8192 || number.Bit(0) != 1 || exponent < 3 || exponent > 2147483647 || exponent%2 == 0 {
		return nil, ErrInput
	}
	return &rsa.PublicKey{N: number, E: int(exponent)}, nil
}

func validOIDCKeys(keys []OIDCKey) bool {
	if len(keys) == 0 || len(keys) > 8 {
		return false
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if _, err := k.key(); err != nil || seen[k.Kid] {
			return false
		}
		seen[k.Kid] = true
	}
	return true
}

type appClaims struct {
	jwt.RegisteredClaims
	AuthorizedParty string `json:"azp"`
	ClientID        string `json:"client_id"`
	Type            string `json:"typ"`
	Scope           string `json:"scope"`
	Email           string `json:"email"`
	VerifiedEmail   bool   `json:"email_verified"`
}

// Only the verifier constructs the binding. The same claims are authenticated
// by the AEAD if serialized in a short-lived private download link.
type appBinding struct {
	Tenant, App, Subject, Token string
	Generation                  int64
	Issued, NotBefore, Expires  time.Time
	Scopes                      []string
}

func (c appClaims) client() string {
	if c.ClientID != "" {
		return c.ClientID
	}
	return c.AuthorizedParty
}

func selectApplication(raw string) (appClaims, bool) {
	var c appClaims
	if len(raw) > 8192 {
		return c, false
	}
	t, _, err := jwt.NewParser().ParseUnverified(raw, &c)
	return c, err == nil && t.Method.Alg() == "RS256" && c.Issuer != "" && c.client() != ""
}

func verifyAppToken(v Application, raw string, now time.Time) (appClaims, appBinding, error) {
	var c appClaims
	var b appBinding
	if v.Status != "active" || len(raw) > 8192 {
		return c, b, ErrAuthentication
	}
	t, err := jwt.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, ErrAuthentication
		}
		for _, k := range v.VerificationKeys {
			if k.Kid == kid {
				return k.key()
			}
		}
		return nil, ErrAuthentication
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(v.Issuer), jwt.WithAudience(v.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !t.Valid || !validOrganizationText(c.Subject, 255) || !validOrganizationText(c.ID, 200) || c.IssuedAt == nil || c.IssuedAt.Before(v.minimumIAT) || c.ExpiresAt.Sub(c.IssuedAt.Time) > time.Hour || !c.ExpiresAt.After(c.IssuedAt.Time) || c.client() != v.ClientID || c.AuthorizedParty != "" && c.AuthorizedParty != v.ClientID {
		return c, b, ErrAuthentication
	}
	typ, _ := t.Header["typ"].(string)
	if typ != "at+jwt" && c.Type != "Bearer" {
		return c, b, ErrAuthentication
	}
	b = appBinding{Tenant: v.TenantID, App: v.ID, Subject: c.Subject, Token: c.ID, Generation: v.Generation, Issued: c.IssuedAt.Time, Expires: c.ExpiresAt.Time}
	if c.NotBefore != nil {
		b.NotBefore = c.NotBefore.Time
	}
	for _, scope := range strings.Fields(c.Scope) {
		if slices.Contains([]string{"org:read", "agent:read", "agent:invoke", "agent:content:read", "member:accept", "member:invite"}, scope) {
			b.Scopes = append(b.Scopes, scope)
		}
	}
	return c, b, nil
}

func resolveApp(ctx context.Context, tx pgx.Tx, b appBinding) (CurrentOrganization, error) {
	var current CurrentOrganization
	o, err := scanOrganization(tx.QueryRow(ctx, `SELECT id,name,status,policy_version,created_at FROM organizations WHERE id=$1`+authorityLock(tx, " FOR SHARE"), b.Tenant))
	if errors.Is(err, ErrNotFound) || err == nil && o.Status != "active" {
		return current, ErrAuthentication
	}
	if err != nil {
		return current, err
	}
	current.Organization = o
	err = tx.QueryRow(ctx, `SELECT p.id,p.display_name,m.role FROM applications a
        JOIN principals signer ON signer.id=a.signing_principal AND signer.status='active'
        JOIN principals integration ON integration.id=a.id AND integration.status='active'
        JOIN app_activations v ON v.app_id=a.id AND NOT v.disabled
        JOIN principals p ON (p.tenant_id,p.id)=(v.tenant_id,v.principal_id)
        JOIN memberships m ON (m.tenant_id,m.principal_id)=(p.tenant_id,p.id)
        WHERE a.tenant_id=$1 AND a.id=$2 AND a.generation=$3 AND a.minimum_iat<=$6 AND p.issuer=a.issuer AND p.subject=$4
        AND p.status='active' AND m.status='active' AND $5>clock_timestamp() AND $6<=clock_timestamp() AND $7<=clock_timestamp()`+authorityLock(tx, " FOR SHARE OF a,integration,v,p,m"), b.Tenant, b.App, b.Generation, b.Subject, b.Expires, b.Issued, b.NotBefore).Scan(&current.PrincipalID, &current.DisplayName, &current.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrAuthentication
	}
	return current, err
}

func (s *Store) authenticateApp(ctx context.Context, raw string, c appClaims) (Principal, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return Principal{}, err
	}
	defer rollback(tx)
	v, err := scanApp(tx.QueryRow(ctx, appSelect+" WHERE a.issuer=$1 AND a.client_id=$2", c.Issuer, c.client()))
	if errors.Is(err, ErrNotFound) {
		return Principal{}, ErrAuthentication
	}
	if err != nil {
		return Principal{}, err
	}
	_, b, err := verifyAppToken(v, raw, time.Now())
	if err != nil {
		return Principal{}, err
	}
	current, err := resolveApp(ctx, tx, b)
	if err != nil {
		return Principal{}, err
	}
	return Principal{Kind: "tenant", ID: current.PrincipalID, TokenID: b.Token, TenantID: b.Tenant, Scopes: slices.Clone(b.Scopes), app: &b}, commit(ctx, tx)
}
