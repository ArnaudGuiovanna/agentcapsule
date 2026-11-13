package capsuleprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
)

const (
	AcceptProtocolHeader  = "X-Capsule-Accept-Protocol"
	MaxCapabilitiesBytes  = 4096
	maxProtocolOffers     = 8
	maxProtocolOfferBytes = 256
)

var (
	ErrUnsupportedProtocol     = errors.New("capsule control protocol is not supported")
	ErrCapabilitiesUnavailable = errors.New("capsule control capabilities endpoint is unavailable")
)

// ControlFeature describes an implemented private control operation. It is not
// an application skill, an outbound permission, a tenant scope or authorization
// to perform an operation. A successful negotiation does not replace the current
// host authority checks or the guest's transactional fences.
type ControlFeature string

const (
	ControlHealth     ControlFeature = "health"
	ControlFences     ControlFeature = "fences"
	ControlEvents     ControlFeature = "events"
	ControlInvokeText ControlFeature = "invoke.message.user.text"
)

type ControlLimits struct {
	MessageBytes int `json:"message_bytes"`
	ContentBytes int `json:"content_bytes"`
}

// ControlCapabilities describes the harness-facing control layer of this boot.
// Supervisor-only volume preparation/quiescence and outbound platform adapters
// are separate contracts and are not inferred from this feature list.
type ControlCapabilities struct {
	Protocol string
	Identity Identity
	Features []ControlFeature
	Limits   ControlLimits
}

func (c ControlCapabilities) Supports(feature ControlFeature) bool {
	return slices.Contains(c.Features, feature)
}

// RequireControlContract rejects a boot that cannot serve the operations and
// sizes used by this version of the control client. Discovery alone may accept
// a narrower profile; admission must not silently use unsupported operations or
// exceed advertised limits. This read-only check grants no application authority.
func (c *Client) RequireControlContract(ctx context.Context) error {
	contract, err := c.Negotiate(ctx, []string{Version})
	if err != nil {
		return err
	}
	for _, feature := range controlFeatures(c.identity) {
		if !contract.Supports(feature) {
			return ErrUnsupportedProtocol
		}
	}
	if contract.Limits != (ControlLimits{MessageBytes: MaxMessageBytes, ContentBytes: MaxContentBytes}) {
		return ErrUnsupportedProtocol
	}
	return nil
}

type capabilitiesResponse struct {
	Protocol string           `json:"protocol"`
	Identity Identity         `json:"identity"`
	Features []ControlFeature `json:"features,omitempty"`
	Limits   *ControlLimits   `json:"limits,omitempty"`
	Code     string           `json:"code,omitempty"`
}

// controlFeatures are the features that every boot of this identity must
// offer (RequireControlContract).
func controlFeatures(id Identity) []ControlFeature {
	features := []ControlFeature{ControlHealth, ControlFences}
	if !id.FenceOnly {
		features = append(features, ControlEvents, ControlInvokeText)
	}
	return features
}

// offeredFeatures adds the optional ones that this server implements.
func offeredFeatures(id Identity) []ControlFeature {
	return append(controlFeatures(id), ControlOutcomes)
}

func validProtocolOffer(version string) bool {
	major, ok := strings.CutPrefix(version, "capsule.v")
	if !ok || len(major) < 1 || len(major) > 6 || major[0] == '0' {
		return false
	}
	for _, digit := range major {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func validProtocolOffers(versions []string) bool {
	if len(versions) < 1 || len(versions) > maxProtocolOffers {
		return false
	}
	seen := make(map[string]struct{}, len(versions))
	for _, version := range versions {
		if !validProtocolOffer(version) {
			return false
		}
		if _, duplicate := seen[version]; duplicate {
			return false
		}
		seen[version] = struct{}{}
	}
	return len(strings.Join(versions, ",")) <= maxProtocolOfferBytes
}

func (s *Server) serveCapabilities(w http.ResponseWriter, r *http.Request) {
	out := capabilitiesResponse{Protocol: Version, Identity: s.credentials.Identity}
	write := func(status int, code string) {
		out.Code = code
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	}
	// Negotiation has no caller-authored identity or payload. Authentication and
	// slot admission are already enforced by ServeHTTP before reaching this route.
	values := r.Header.Values(AcceptProtocolHeader)
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(values) != 1 || len(values[0]) > maxProtocolOfferBytes {
		write(http.StatusBadRequest, "invalid_negotiation")
		return
	}
	versions := strings.Split(values[0], ",")
	for i := range versions {
		versions[i] = strings.Trim(versions[i], " \t")
	}
	if !validProtocolOffers(versions) {
		write(http.StatusBadRequest, "invalid_negotiation")
		return
	}
	if !slices.Contains(versions, Version) {
		write(http.StatusNotAcceptable, "unsupported_protocol")
		return
	}
	out.Features = offeredFeatures(s.credentials.Identity)
	out.Limits = &ControlLimits{MessageBytes: MaxMessageBytes, ContentBytes: MaxContentBytes}
	w.Header().Set("X-Capsule-Protocol", Version)
	write(http.StatusOK, "")
}

func validCapabilities(out capabilitiesResponse) bool {
	if out.Limits == nil || out.Limits.MessageBytes < 1 || out.Limits.MessageBytes > MaxMessageBytes || out.Limits.ContentBytes < 1 || out.Limits.ContentBytes > MaxContentBytes || out.Limits.ContentBytes > out.Limits.MessageBytes || len(out.Features) < 2 || len(out.Features) > 5 {
		return false
	}
	seen := make(map[ControlFeature]bool, len(out.Features))
	for _, feature := range out.Features {
		if seen[feature] {
			return false
		}
		seen[feature] = true
		switch feature {
		case ControlHealth, ControlFences, ControlOutcomes:
		case ControlEvents, ControlInvokeText:
			if out.Identity.FenceOnly {
				return false
			}
		default:
			return false
		}
	}
	return seen[ControlHealth] && seen[ControlFences]
}

// Negotiate explicitly discovers a compatible control contract from this boot's
// authenticated endpoint. It is opt-in: NewClient and Health retain historical
// behavior. Callers that require negotiation must fail startup on any error and
// check the features they need. A legacy endpoint returns the classifiable
// ErrCapabilitiesUnavailable; it is never accepted through an implicit fallback.
//
// The returned metadata does not change client state, grant authority or make an
// event safe to retry without its original identity/body/idempotency bindings.
func (c *Client) Negotiate(ctx context.Context, offered []string) (ControlCapabilities, error) {
	if !validProtocolOffers(offered) {
		return ControlCapabilities{}, ErrProtocol
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("/v1/capabilities"), nil)
	if err != nil {
		return ControlCapabilities{}, err
	}
	r.Header.Set(AcceptProtocolHeader, strings.Join(offered, ","))
	r.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(r)
	if err != nil {
		return ControlCapabilities{}, errors.Join(ErrTransport, err)
	}
	defer resp.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(resp.Body, MaxCapabilitiesBytes+1))
	if err != nil || len(encoded) > MaxCapabilitiesBytes {
		return ControlCapabilities{}, ErrProtocol
	}
	var out capabilitiesResponse
	if err = decode(bytes.NewReader(encoded), &out); err != nil {
		return ControlCapabilities{}, err
	}
	if out.Identity != c.identity {
		return ControlCapabilities{}, ErrIdentity
	}
	if out.Protocol != Version {
		return ControlCapabilities{}, ErrUnsupportedProtocol
	}
	if resp.StatusCode != http.StatusOK || out.Code != "" {
		switch {
		case resp.StatusCode == http.StatusNotFound && out.Code == "unknown_operation":
			return ControlCapabilities{}, ErrCapabilitiesUnavailable
		case resp.StatusCode == http.StatusNotAcceptable && out.Code == "unsupported_protocol":
			return ControlCapabilities{}, ErrUnsupportedProtocol
		case out.Code == "invalid_negotiation":
			return ControlCapabilities{}, ErrProtocol
		default:
			return ControlCapabilities{}, ErrTransport
		}
	}
	selected := resp.Header.Values("X-Capsule-Protocol")
	if len(selected) != 1 || selected[0] != out.Protocol || !slices.Contains(offered, out.Protocol) || !validCapabilities(out) {
		return ControlCapabilities{}, ErrProtocol
	}
	return ControlCapabilities{Protocol: out.Protocol, Identity: out.Identity, Features: out.Features, Limits: *out.Limits}, nil
}
