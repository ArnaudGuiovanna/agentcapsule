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
type ServiceLLM struct {
	ReceiptKey string `json:"receipt_key"`
}

// OpenLLM never creates a key. Without the matching key the worker simply cannot
// open provider credentials, and the bridge answers unavailable.
func (c ServiceConfig) OpenLLM(s *controlplane.Store) (*controlplane.LLMService, error) {
	if c.LLM == nil {
		return nil, nil
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
	// Two attempts of 140 s fit inside the bridge's 300 s call budget; one
	// attempt leaves room for a long answer from an adapted agent.
	return controlplane.NewLLMService(accounts, llmgateway.New(llmgateway.Config{Timeout: 140 * time.Second}))
}

// EnableLLM attaches the model gateway once, like EnableTransit.
func (w *Placements) EnableLLM(s *controlplane.LLMService) error {
	if s == nil || !w.llm.CompareAndSwap(nil, s) {
		return controlplane.ErrConflict
	}
	return nil
}
