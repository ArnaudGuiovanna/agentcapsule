package capsuleprotocol

import (
	"context"
	"net/url"
	"time"
)

// ValidAgentID bounds an agent ID named by a guest: 1 to 100 bytes of letters,
// digits, '.', '_' or '-'. Whether that agent exists, and whether the caller
// may see it, is the platform's answer.
func ValidAgentID(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// RequestStatus is what the sender of a request may know of it now. State is
// the platform's own request state (PENDING_APPROVAL, DELIVERING, PROCESSING,
// REPLIED, DECLINED, EXPIRED, CANCELED or FAILED); the reply itself arrives as
// a "reply" event, never through this read.
type RequestStatus struct {
	RequestID        string    `json:"request_id"`
	RecipientAgentID string    `json:"recipient_agent_id"`
	State            string    `json:"state"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// PeerAPI is optional on a PlatformAPI: the reads behind the guest's A2A
// endpoint. A host without it answers "unavailable".
type PeerAPI interface {
	// DescribeAgent returns an agent the caller may send requests to: of its
	// own domain, discoverable, live, not itself. A missing, hidden and foreign
	// agent are the same "not_found".
	DescribeAgent(context.Context, string) (DirectoryAgent, error)
	// RequestStatus returns a request the caller sent; any other request is
	// "not_found".
	RequestStatus(context.Context, string) (RequestStatus, error)
}

// DescribeAgent reads what the platform tells about one agent the caller may
// send requests to. Being described grants no right: a request still needs
// the recipient side's consent.
func (p *PlatformClient) DescribeAgent(ctx context.Context, agentID string) (DirectoryAgent, error) {
	if !ValidAgentID(agentID) {
		return DirectoryAgent{}, ErrProtocol
	}
	r, err := p.call(ctx, "/v1/directory/agent", &platformRequest{AgentID: agentID})
	if err != nil {
		return DirectoryAgent{}, err
	}
	if r.Described == nil || r.Described.AgentID != agentID {
		return DirectoryAgent{}, ErrProtocol
	}
	return *r.Described, nil
}

// RequestStatus reads the current state of a request the caller sent.
func (p *PlatformClient) RequestStatus(ctx context.Context, requestID string) (RequestStatus, error) {
	if requestID == "" || len(requestID) > 100 {
		return RequestStatus{}, ErrProtocol
	}
	r, err := p.call(ctx, "/v1/agent-requests/"+url.PathEscape(requestID)+"/status", &platformRequest{RequestID: requestID})
	if err != nil {
		return RequestStatus{}, err
	}
	if r.RequestStatus == nil || r.RequestStatus.RequestID != requestID {
		return RequestStatus{}, ErrProtocol
	}
	return *r.RequestStatus, nil
}
