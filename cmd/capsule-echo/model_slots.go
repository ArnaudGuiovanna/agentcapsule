//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// The optional model-stream-slots KVM fixture holds sixteen independently
// admitted requests open until it reads the seventeenth HTTP response.
type slotProbe struct {
	*capsuleprotocol.PlatformClient
	id     capsuleprotocol.Identity
	socket string
}

func (p slotProbe) CompleteLLM(parent context.Context, key string, in capsuleprotocol.LLMRequest) (capsuleprotocol.LLMResult, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	opened := make(chan error, 16)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	for i := range 16 {
		workers.Go(func() {
			seen := false
			for frame, err := range p.CompleteLLMStream(ctx, fmt.Sprintf("%s/%d", key, i), in) {
				if err != nil {
					if !seen {
						opened <- err
					}
					return
				}
				if !seen && frame.Type == "text" {
					seen = true
					opened <- nil
				}
			}
			if !seen {
				opened <- capsuleprotocol.ErrProtocol
			}
		})
	}
	for range 16 {
		select {
		case err := <-opened:
			if err != nil {
				return capsuleprotocol.LLMResult{}, err
			}
		case <-ctx.Done():
			return capsuleprotocol.LLMResult{}, ctx.Err()
		}
	}
	body, err := json.Marshal(map[string]any{"protocol": capsuleprotocol.Version, "identity": p.id, "idempotency_key": key + "/overflow", "llm": in})
	if err != nil {
		return capsuleprotocol.LLMResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "http://platform"+capsuleprotocol.CompleteLLMStreamPath, bytes.NewReader(body))
	if err != nil {
		return capsuleprotocol.LLMResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", p.socket)
	}}
	defer tr.CloseIdleConnections()
	res, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return capsuleprotocol.LLMResult{}, err
	}
	defer res.Body.Close()
	var refusal struct {
		Code     string
		Protocol string
		Identity capsuleprotocol.Identity
	}
	if err = json.NewDecoder(res.Body).Decode(&refusal); err != nil || refusal.Identity != p.id || refusal.Protocol != capsuleprotocol.Version {
		return capsuleprotocol.LLMResult{}, capsuleprotocol.ErrProtocol
	}
	return capsuleprotocol.LLMResult{Text: fmt.Sprintf("%d %s", res.StatusCode, refusal.Code)}, nil
}
