package controlplane

import (
	"context"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane/identity"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/jackc/pgx/v5"
)

type CurrentOrganization = identity.CurrentOrganization

// AuthenticateDelegation verifies a signature, then resolves existing state. It
// never installs trust or provisions identity. With a nil verifier, the one
// the API uses, the token is verified with the key it names among the trusts
// registered in PostgreSQL (ADR 001, D-01); a non-nil verifier is a fixed
// configuration, still checked against the registered trust.
func (s *Store) AuthenticateDelegation(ctx context.Context, verifier *delegatedidentity.Verifier, raw string) (Principal, error) {
	if c, ok := selectApplication(raw); ok {
		return s.authenticateApp(ctx, raw, c)
	}
	issuer, audience, kid, err := delegatedidentity.Select(raw)
	if verifier == nil && err != nil {
		return Principal{}, ErrAuthentication
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return Principal{}, err
	}
	defer rollback(tx)
	if verifier == nil {
		if verifier, err = identity.RegisteredVerifier(ctx, tx, issuer, audience, kid); err != nil {
			return Principal{}, err
		}
	}
	v, err := verifier.Verify(raw)
	if err != nil {
		return Principal{}, ErrAuthentication
	}
	current, err := identity.ResolveDelegation(ctx, tx, v)
	if err != nil {
		return Principal{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return Principal{}, err
	}
	return Principal{Kind: "tenant", ID: current.PrincipalID, TenantID: v.TenantID, TokenID: v.TokenID, Scopes: slices.Clone(v.Scopes), delegation: &v}, nil
}

func authorizeTenant(ctx context.Context, tx pgx.Tx, p Principal, scope string) (CurrentOrganization, error) {
	if !tenantBound(p) {
		return CurrentOrganization{}, ErrForbidden
	}
	var current CurrentOrganization
	var err error
	if p.delegation != nil {
		current, err = identity.ResolveDelegation(ctx, tx, *p.delegation)
	} else if p.app != nil {
		current, err = identity.ResolveApplication(ctx, tx, *p.app)
	} else {
		current, err = identity.ResolveServiceToken(ctx, tx, p.service.tenantID, p.service.tokenID)
	}
	if err != nil {
		return CurrentOrganization{}, err
	}
	if current.PrincipalID != p.ID || !slices.Contains(tenantScopes(p), scope) {
		return CurrentOrganization{}, ErrForbidden
	}
	return current, nil
}

func (a *Accounts) CurrentOrganization(ctx context.Context, p Principal) (CurrentOrganization, error) {
	tx, err := a.store.begin(ctx)
	if err != nil {
		return CurrentOrganization{}, err
	}
	defer rollback(tx)
	current, err := authorizeTenant(ctx, tx, p, "org:read")
	if err != nil {
		return CurrentOrganization{}, err
	}
	return current, commit(ctx, tx)
}
