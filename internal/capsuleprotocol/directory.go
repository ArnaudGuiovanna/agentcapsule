package capsuleprotocol

import (
	"context"
	"errors"
)

// DirectoryQuery asks for agents of the caller's organization that offer any
// of the OASF skills (class IDs of schema 1.1.0). The caller and its
// organization come from the channel, never from the query.
type DirectoryQuery struct {
	Skills []int `json:"skills"`
}

func (q DirectoryQuery) Validate() error {
	if len(q.Skills) < 1 || len(q.Skills) > 20 {
		return errors.New("one to twenty skills")
	}
	seen := map[int]bool{}
	for _, s := range q.Skills {
		if s < 1 || s > 99_999_999 || seen[s] {
			return errors.New("skills are distinct positive class IDs")
		}
		seen[s] = true
	}
	return nil
}

// DirectoryAgent is one agent the caller may see now, as the platform
// describes it. Finding an agent grants no right: a request to it still needs
// the recipient side's consent.
type DirectoryAgent struct {
	AgentID     string `json:"agent_id"`
	Description string `json:"description"`
	Skills      []int  `json:"skills"`
	Domains     []int  `json:"domains"`
}

// DirectoryAPI is optional on a PlatformAPI: a host without a Directory
// answers "unavailable".
type DirectoryAPI interface {
	FindAgents(context.Context, DirectoryQuery) ([]DirectoryAgent, error)
}

// FindAgents searches the private Directory through the platform.
func (p *PlatformClient) FindAgents(ctx context.Context, q DirectoryQuery) ([]DirectoryAgent, error) {
	r, err := p.call(ctx, "/v1/directory/find", &platformRequest{Query: &q})
	if err != nil {
		return nil, err
	}
	if r.Found == nil {
		return []DirectoryAgent{}, nil
	}
	return r.Found, nil
}
