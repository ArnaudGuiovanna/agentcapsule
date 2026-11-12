//go:build linux

package capsuleprotocol

import (
	"context"
	"net"
	"net/http"
)

// LocalPlatformServer is the supervisor end of the harness's outgoing channel.
// Kernel peer credentials authenticate the harness. Only typed platform methods
// can cross the bridge; no HTTP proxy target or caller identity is selected by it.
type LocalPlatformServer struct{ handler *platformHandler }

type remotePlatform struct{ client *PlatformClient }

func (r remotePlatform) Validate(ctx context.Context) error { return r.client.Health(ctx) }
func (r remotePlatform) Submit(ctx context.Context, key string, in Submission) (PlatformReceipt, error) {
	return r.client.Submit(ctx, key, in)
}
func (r remotePlatform) Reply(ctx context.Context, id, key string, in Reply) (PlatformReceipt, error) {
	return r.client.Reply(ctx, id, key, in)
}
func (r remotePlatform) Search(ctx context.Context, candidates []string) ([]string, error) {
	return r.client.Search(ctx, candidates)
}
func (r remotePlatform) FindAgents(ctx context.Context, q DirectoryQuery) ([]DirectoryAgent, error) {
	return r.client.FindAgents(ctx, q)
}
func (r remotePlatform) CompleteLLM(ctx context.Context, key string, in LLMRequest) (LLMResult, error) {
	return r.client.CompleteLLM(ctx, key, in)
}
func (r remotePlatform) ForwardLLM(ctx context.Context, key string, in LLMForward) (LLMForwardResult, error) {
	return r.client.ForwardLLM(ctx, key, in)
}
func (r remotePlatform) ReadAttachment(ctx context.Context, id string, index int) (AttachmentSegment, error) {
	return r.client.ReadAttachment(ctx, id, index)
}
func (r remotePlatform) CompleteInvocation(ctx context.Context, key string, in InvocationCompletion) (CompletionReceipt, error) {
	return r.client.CompleteInvocation(ctx, key, in)
}
func (r remotePlatform) PostOwner(ctx context.Context, key string, input OwnerPost) (OwnerPostReceipt, error) {
	return r.client.PostOwner(ctx, key, input)
}
func (r remotePlatform) DescribeAgent(ctx context.Context, id string) (DirectoryAgent, error) {
	return r.client.DescribeAgent(ctx, id)
}
func (r remotePlatform) RequestStatus(ctx context.Context, id string) (RequestStatus, error) {
	return r.client.RequestStatus(ctx, id)
}

// The guest's A2A endpoint reads cards and request states through this bridge.
var _ PeerAPI = remotePlatform{}

// NewLocalPlatformServer retains the remote credential inside the supervisor.
// A local client cannot itself be re-exported as a trusted remote endpoint.
func NewLocalPlatformServer(remote *PlatformClient) (*LocalPlatformServer, error) {
	if remote == nil || remote.client == nil || remote.client.scheme != "" || remote.client.identity.FenceOnly {
		return nil, ErrIdentity
	}
	h, err := NewPlatformHandler(remote.client.identity, remotePlatform{remote})
	if err != nil {
		return nil, err
	}
	p := h.(*platformHandler)
	p.localAuth = func(r *http.Request) bool { ok, _ := r.Context().Value(localPeerKey{}).(bool); return ok }
	return &LocalPlatformServer{handler: p}, nil
}

func (s *LocalPlatformServer) Serve(ctx context.Context, l *net.UnixListener, harnessUID uint32) error {
	if s == nil || s.handler == nil || l == nil {
		return ErrProtocol
	}
	return serveLocal(ctx, l, harnessUID, s.handler)
}

func (p *PlatformClient) Identity() Identity { return p.client.identity }

// NewLocalPlatformClient has no TLS material. Its path is supplied by the trusted
// boot record; the directory and socket must be protected by the supervisor.
func NewLocalPlatformClient(id Identity, path string) (*PlatformClient, error) {
	if id.FenceOnly {
		return nil, ErrIdentity
	}
	c, err := NewLocalClient(id, path)
	if err != nil {
		return nil, err
	}
	return &PlatformClient{client: c}, nil
}
