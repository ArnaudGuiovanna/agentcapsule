package capsuleprotocol

import (
	"net/http"
	"slices"
	"strings"
)

// ControlContentJSON says the harness accepts JSON parts (ContentPart of type
// json) in the invocations and the requests and replies it receives. It is
// optional and opt-in on both sides: a harness offers it only when its code
// handles JSON values (Server.AcceptJSONContent) and the client listed it in
// AcceptFeaturesHeader. A client that does not list it, such as capsule-init
// or a worker built before JSON content, sees the profile it already knows.
// Without it, the platform delivers each JSON part as text (TextOnlyEvent).
const ControlContentJSON ControlFeature = "content.json"

// AcceptFeaturesHeader lists the optional features a client understands.
const AcceptFeaturesHeader = "X-Capsule-Accept-Features"

// optionalFeatures are the features a client of this version asks for.
var optionalFeatures = []ControlFeature{ControlContentJSON}

// asked reports whether the request lists feature in AcceptFeaturesHeader.
// Unknown names are ignored, so that a newer client can ask for more.
func asked(r *http.Request, feature ControlFeature) bool {
	values := r.Header.Values(AcceptFeaturesHeader)
	if len(values) != 1 || len(values[0]) > maxProtocolOfferBytes {
		return false
	}
	for _, name := range strings.Split(values[0], ",") {
		if ControlFeature(strings.Trim(name, " \t")) == feature {
			return true
		}
	}
	return false
}

// AcceptJSONContent makes this harness server offer ControlContentJSON. Call
// it before serving, only when the harness handles JSON parts. A server that
// does not accept JSON content refuses an invocation or a request carrying it.
func (s *Server) AcceptJSONContent() { s.json = true }

// Accepts reports whether the last RequireControlContract of this client
// negotiated an optional feature. Before it, or after a failure, it is false.
func (c *Client) Accepts(feature ControlFeature) bool {
	contract := c.contract.Load()
	return contract != nil && slices.Contains(contract.Features, feature)
}
