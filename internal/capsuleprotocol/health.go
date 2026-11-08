package capsuleprotocol

import "context"

// ShutdownState is the trusted host's observation of the previous boot, not a
// claim about this boot or a substitute for checking its filesystem. Missing or
// unknown observations must never be silently reported as a clean shutdown.
type ShutdownState string

const (
	ShutdownClean   ShutdownState = "clean"
	ShutdownUnclean ShutdownState = "unclean"
)

func (s ShutdownState) Valid() bool { return s == ShutdownClean || s == ShutdownUnclean }

type HealthStatus struct {
	Protocol         string        `json:"protocol"`
	Identity         Identity      `json:"identity"`
	PreviousShutdown ShutdownState `json:"previous_shutdown"`
}

func (c *Client) HealthStatus(ctx context.Context) (HealthStatus, error) {
	r, err := c.call(ctx, "/v1/health", nil)
	if err != nil {
		return HealthStatus{}, err
	}
	if !r.PreviousShutdown.Valid() {
		return HealthStatus{}, ErrProtocol
	}
	return HealthStatus{Protocol: r.Protocol, Identity: r.Identity, PreviousShutdown: r.PreviousShutdown}, nil
}
