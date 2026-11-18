//go:build linux

package worker

import (
	"path/filepath"
	"time"

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
type ServiceLLM struct {
	ReceiptKey               string   `json:"receipt_key"`
	AllowedInternalProviders []string `json:"allowed_internal_providers,omitempty"`
}

// gatewayConfig is the model gateway's configuration. With requireHTTPS
// (production), a provider on plain HTTP is refused before any request is sent.
func (l *ServiceLLM) gatewayConfig(requireHTTPS bool) (llmgateway.Config, error) {
	allow, err := llmgateway.ParseAllowlist(l.AllowedInternalProviders)
	if err != nil {
		return llmgateway.Config{}, err
	}
	// Two attempts of 140 s fit inside the bridge's 300 s call budget; one
	// attempt leaves room for a long answer from an adapted agent.
	return llmgateway.Config{Timeout: 140 * time.Second, RequireHTTPS: requireHTTPS, AllowInternal: allow}, nil
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
	if !filepath.IsAbs(c.LLM.ReceiptKey) {
		return nil, operatorconfig.ErrPrivateFile
	}
	key, err := operatorconfig.ReadPrivate(c.LLM.ReceiptKey, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	accounts, err := controlplane.NewAccounts(s, key)
	if err != nil {
		return nil, err
	}
	return controlplane.NewLLMService(accounts, llmgateway.New(gateway))
}

// EnableLLM attaches the model gateway once, like EnableTransit.
func (w *Placements) EnableLLM(s *controlplane.LLMService) error {
	if s == nil || !w.llm.CompareAndSwap(nil, s) {
		return controlplane.ErrConflict
	}
	return nil
}
