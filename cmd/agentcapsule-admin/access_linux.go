//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityclient"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
)

// withoutAuthority is written on standard error by a revoking command that
// runs in development mode without the authority service: its revocation
// is recorded in PostgreSQL only, and a failover can undo it.
const withoutAuthority = "development_mode_without_authority_service_never_use_in_production"

// accessFlags reach the authority service's API socket, as the API's flags
// do (docs/adr/006-authority-service.md §6): a revoking command appends its
// access revocation record there once it has committed (wave 5, and the
// changes after the v0.1.0 audit).
type accessFlags struct {
	socket, restoreID, keyID *string
}

func newAccessFlags(f *flag.FlagSet) accessFlags {
	return accessFlags{
		socket:    f.String("authority-socket", "", "the authority service's API socket; required in production to revoke"),
		restoreID: f.String("restore-authority-id", "", "pinned identity of the restore authority (restoreauth_…)"),
		keyID:     f.String("key-authority-id", "", "pinned identity of the key authority (keyauth_…)"),
	}
}

// attach makes s append its access revocation records to the authority
// service. It returns the service's client, to close, or the code of its
// failure. In development without the flags it warns, and records nothing.
func (a accessFlags) attach(ctx context.Context, s *controlplane.Store) (*authorityclient.API, string) {
	if (*a.socket == "") != (*a.restoreID == "") || (*a.socket == "") != (*a.keyID == "") {
		return nil, "configuration_required"
	}
	if *a.socket == "" {
		mode, err := operatorconfig.ModeFromEnvironment()
		if err != nil {
			return nil, "mode_invalid"
		}
		if mode == operatorconfig.Production {
			return nil, "authority_required_in_production"
		}
		fmt.Fprintln(os.Stderr, withoutAuthority)
		return nil, ""
	}
	client, err := authorityclient.NewAPI(*a.socket, *a.restoreID, *a.keyID)
	if err != nil {
		return nil, "authority_configuration_invalid"
	}
	if _, err = client.Status(ctx); err != nil {
		client.Close()
		switch {
		case errors.Is(err, authorityservice.ErrIdentity):
			return nil, "authority_identity_mismatch"
		case errors.Is(err, authorityservice.ErrRole):
			return nil, "authority_socket_role_mismatch"
		case errors.Is(err, authorityservice.ErrProtocol):
			return nil, "authority_protocol_unsupported"
		}
		return nil, "authority_service_unavailable"
	}
	s.RecordAccessWith(client)
	return client, ""
}
