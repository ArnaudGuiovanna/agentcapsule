package authoritylog

import "unicode/utf8"

// Access revocation records (docs/adr/005-keys-outside-restored-domain.md,
// "What the code must do", items 6 and 7; docs/adr/006-authority-service.md
// §7). Every transaction that revokes access appends one record to the
// authorities before it commits in PostgreSQL, so that a database set back by
// a failover can learn it again (ADR 006 wave 7). A record names its kind,
// the organization, and the revoked objects; it holds no content and no
// secret. Records are never changed or deleted.

// The kinds of an access revocation record, a closed vocabulary. A bearer
// token's revocation is covered by the blanket revocation of every bearer
// token at a failover that ends a degraded period: the API confirms it at
// once in degraded mode. A standing grant's is not: the API confirms it only
// once the replica holds its record (finding 1, option (a)).
const (
	// Bearer tokens.
	AccessAPIToken           = "api_token"
	AccessServiceToken       = "service_token"
	AccessPlatformCredential = "platform_credential"
	AccessDelegatedToken     = "delegated_token"
	// AccessBlanket revokes every bearer token issued before a failover that
	// may have ended a degraded period (blanket.go). The promotion writes it;
	// nothing else does.
	AccessBlanket = "blanket"
	// Standing grants.
	AccessMember          = "member"
	AccessPrincipal       = "principal"
	AccessOrganization    = "organization"
	AccessTeam            = "team"
	AccessTeamMembership  = "team_membership"
	AccessAssignment      = "assignment"
	AccessMandate         = "mandate"
	AccessDelegationTrust = "delegation_trust"
	AccessLLMProvider     = "llm_provider"
	// AccessPersonalVolume permanently removes an agent volume from shared inventory.
	AccessPersonalVolume = "personal_volume"
)

// accessBearer classifies every kind: true for a bearer token.
var accessBearer = map[string]bool{
	AccessAPIToken: true, AccessServiceToken: true, AccessPlatformCredential: true, AccessDelegatedToken: true, AccessBlanket: true,
	AccessMember: false, AccessPrincipal: false, AccessOrganization: false, AccessTeam: false, AccessTeamMembership: false,
	AccessAssignment: false, AccessMandate: false, AccessDelegationTrust: false, AccessLLMProvider: false, AccessPersonalVolume: false,
}

// AccessKinds lists every kind of access revocation record.
func AccessKinds() []string {
	return []string{AccessAPIToken, AccessServiceToken, AccessPlatformCredential, AccessDelegatedToken, AccessBlanket,
		AccessMember, AccessPrincipal, AccessOrganization, AccessTeam, AccessTeamMembership, AccessAssignment,
		AccessMandate, AccessDelegationTrust, AccessLLMProvider, AccessPersonalVolume}
}

// AccessBearer reports whether kind is a bearer token's, and whether kind is
// known at all.
func AccessBearer(kind string) (bearer, known bool) {
	bearer, known = accessBearer[kind]
	return bearer, known
}

// Bounds of an access revocation record.
const (
	// MaxAccessObjects bounds the objects of one record.
	MaxAccessObjects = 1000
	// MaxAccessParts bounds the parts of one object's identity.
	MaxAccessParts = 6
	// maxAccessText bounds one part, and the organization.
	maxAccessText = 1024
)

// ValidAccessText reports whether s may name an organization or a part of an
// object's identity in a record: not empty, at most 1024 bytes of UTF-8,
// without control characters.
func ValidAccessText(s string) bool {
	if s == "" || len(s) > maxAccessText || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return false
		}
	}
	return true
}

// ValidAccessObjects reports whether objects can be a record's: from 1 to
// MaxAccessObjects identities, each of 1 to MaxAccessParts parts.
func ValidAccessObjects(objects [][]string) bool {
	if len(objects) == 0 || len(objects) > MaxAccessObjects {
		return false
	}
	for _, o := range objects {
		if len(o) == 0 || len(o) > MaxAccessParts {
			return false
		}
		for _, part := range o {
			if !ValidAccessText(part) {
				return false
			}
		}
	}
	return true
}
