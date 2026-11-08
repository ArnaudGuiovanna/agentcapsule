//go:build linux

package runtime

import (
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

func TestCredentialRenewalTimeBoundaries(t *testing.T) {
	c, _, err := capsuleprotocol.NewBootCredentials(capsuleprotocol.Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	before, after, err := c.Validity()
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name string
		now  time.Time
		due  bool
	}{
		{"clock_before_validity", before.Add(-time.Nanosecond), true},
		{"not_before_inclusive", before, false},
		{"before_margin", after.Add(-CredentialRenewalMargin - time.Nanosecond), false},
		{"margin_inclusive", after.Add(-CredentialRenewalMargin), true},
		{"expired", after.Add(time.Second), true},
	} {
		t.Run(check.name, func(t *testing.T) {
			due, err := credentialsDue(c, check.now)
			if err != nil || due != check.due {
				t.Fatal(due, err)
			}
		})
	}
	c.PrivateKey = []byte("corrupt")
	if _, err = credentialsDue(c, after); err == nil {
		t.Fatal("corrupt material was silently eligible for rotation")
	}
}
