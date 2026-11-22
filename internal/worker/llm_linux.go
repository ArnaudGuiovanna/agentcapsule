//go:build linux

package worker

import (
	"cmp"
	"errors"
	"path/filepath"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
)

// ServiceLLM enables the model bridge. ReceiptKey is the same private 32-byte
// installation key the API holds: provider credentials are encrypted under a key
// derived from it, so the worker must see the same one to decrypt them.
// AllowedInternalProviders lists the internal provider addresses the operator
// allows, as "host:port" or CIDR prefixes (llmgateway.ParseAllowlist); none by
// default, so the gateway calls public addresses only (ADR 010).
// StreamFirstByteTimeout and StreamIdleTimeout bound a provider stream (ADR
// 022): up to the provider's first byte, per attempt, and between two of its
// events; "60s" each by default, 5s to 290s. MaxIdleConnsPerHost is how many
// idle connections the gateway keeps to each provider address, 32 by
// default, 2 to 512. MaxCallsPerAgent is how many model calls an agent may
// have in flight at once, every route counted, 8 by default, 1 to 64.
type ServiceLLM struct {
	ReceiptKey               string   `json:"receipt_key"`
	AllowedInternalProviders []string `json:"allowed_internal_providers,omitempty"`
	StreamFirstByteTimeout   string   `json:"stream_first_byte_timeout,omitempty"`
	StreamIdleTimeout        string   `json:"stream_idle_timeout,omitempty"`
	MaxIdleConnsPerHost      int      `json:"max_idle_conns_per_host,omitempty"`
	MaxCallsPerAgent         int      `json:"max_calls_per_agent,omitempty"`
}

// callsPerAgent is MaxCallsPerAgent, checked: 0 is the default.
func (l *ServiceLLM) callsPerAgent() (int, error) {
	if l.MaxCallsPerAgent < 0 || l.MaxCallsPerAgent > 64 {
		return 0, errors.New("invalid llm max_calls_per_agent")
	}
	return cmp.Or(l.MaxCallsPerAgent, controlplane.DefaultLLMCallsPerAgent), nil
}

// gatewayConfig is the model gateway's configuration. With requireHTTPS
// (production), a provider on plain HTTP is refused before any request is sent.
func (l *ServiceLLM) gatewayConfig(requireHTTPS bool) (llmgateway.Config, error) {
	allow, err := llmgateway.ParseAllowlist(l.AllowedInternalProviders)
	if err != nil {
		return llmgateway.Config{}, err
	}
	var bounds [2]time.Duration
	for i, text := range []string{l.StreamFirstByteTimeout, l.StreamIdleTimeout} {
		bounds[i] = time.Minute
		if text == "" {
			continue
		}
		if bounds[i], err = time.ParseDuration(text); err != nil || bounds[i] < 5*time.Second || bounds[i] > 290*time.Second {
			return llmgateway.Config{}, errors.New("invalid llm stream timeout")
		}
	}
	if l.MaxIdleConnsPerHost != 0 && (l.MaxIdleConnsPerHost < 2 || l.MaxIdleConnsPerHost > 512) {
		return llmgateway.Config{}, errors.New("invalid llm max_idle_conns_per_host")
	}
	// Two attempts of 140 s fit inside the bridge's 300 s call budget; one
	// attempt leaves room for a long answer from an adapted agent. A stream
	// has its own bounds, and the channel's in total.
	return llmgateway.Config{Timeout: 140 * time.Second, RequireHTTPS: requireHTTPS, AllowInternal: allow,
		StreamFirstByte: bounds[0], StreamIdle: bounds[1], StreamTotal: capsuleprotocol.LLMCallTimeout,
		MaxIdleConnsPerHost: cmp.Or(l.MaxIdleConnsPerHost, llmgateway.DefaultMaxIdleConnsPerHost)}, nil
}

// OpenLLM never creates a key. Without the matching key the worker simply cannot
// open provider credentials, and the bridge answers unavailable.
func (c ServiceConfig) OpenLLM(s *controlplane.Store, requireHTTPS bool) (*controlplane.LLMService, error) {
	if c.LLM == nil {
		return nil, nil
	}
	gateway, err := c.LLM.gatewayConfig(requireHTTPS)
	if err != nil {
		return nil, err
	}
	perAgent, err := c.LLM.callsPerAgent()
	if err != nil {
		return nil, err
	}
	accounts, err := c.openBridgeAccounts(s)
	if err != nil {
		return nil, err
	}
	svc, err := controlplane.NewLLMService(accounts, llmgateway.New(gateway))
	if err != nil {
		return nil, err
	}
	svc.LimitCallsPerAgent(perAgent)
	return svc, nil
}

func (c ServiceConfig) openBridgeAccounts(s *controlplane.Store) (*controlplane.Accounts, error) {
	if !filepath.IsAbs(c.LLM.ReceiptKey) {
		return nil, operatorconfig.ErrPrivateFile
	}
	key, err := operatorconfig.ReadPrivate(c.LLM.ReceiptKey, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return controlplane.NewAccounts(s, key)
}

// EnableLLM attaches the model gateway once, like EnableTransit.
func (w *Placements) EnableLLM(s *controlplane.LLMService) error {
	if s == nil || !w.llm.CompareAndSwap(nil, s) {
		return controlplane.ErrConflict
	}
	return nil
}
