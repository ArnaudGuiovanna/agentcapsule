package guestinit

import (
	"errors"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

func TestHarnessBootRequiresShutdownObservation(t *testing.T) {
	for _, previous := range []string{"", "unknown", "clean", "unclean"} {
		field := ""
		if previous != "" {
			field = `,"previous_shutdown":"` + previous + `"`
		}
		body := `{"protocol":"` + capsuleprotocol.Version + `","identity":{"incarnation":1,"agent_id":"a","generation":1,"vm_id":"0123456789abcdef"},"data_directory":"/var/lib/agent","supervisor_uid":0` + field + `}`
		b, err := ReadHarnessBoot(strings.NewReader(body))
		if capsuleprotocol.ShutdownState(previous).Valid() {
			if err != nil || string(b.PreviousShutdown) != previous {
				t.Fatal("valid shutdown observation rejected", b, err)
			}
		} else if !errors.Is(err, ErrGuest) {
			t.Fatal("missing/unknown shutdown observation accepted", b, err)
		}
	}
}
