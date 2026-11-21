//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capability"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/pgnotify"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

// The same HTTP subscriber stays connected while the worker restores the
// guest volume. Deltas after the reset restart at the new attempt's sequence.
func TestProductRestoreResetsALiveSubscriber(t *testing.T) {
	l := newRegistryLab(t)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	hub, err := pgnotify.New(l.store.Connect, "agentcapsule_invocation_stream")
	if err != nil {
		t.Fatal(err)
	}
	hubCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = hub.Run(hubCtx) }()
	defer func() { stop(); <-done }()
	if err = l.worker.EnableOutputStreams(DefaultOutputStreams, hub); err != nil {
		t.Fatal(err)
	}
	if err = l.handler.StartEventStreams(ctx, 8); err != nil {
		t.Fatal(err)
	}
	l.publishManifest("1.0.0", "opt/reset", &[]string{capability.StreamOutput})
	agent := l.create("stream-restore", "1.0.0").AgentID
	l.answers(agent, "before", "archive checkpoint")
	archives, err := volumearchive.New(filepath.Join(t.TempDir(), "archives"))
	if err != nil {
		t.Fatal(err)
	}
	archiveID := "arc_" + strings.Repeat("7", 32)
	if _, err = l.worker.CaptureArchive(ctx, agent, archiveID, archives); err != nil {
		t.Fatal(err)
	}
	op := l.invoke(agent, "across-restore", "/stream 180")
	req, err := http.NewRequestWithContext(ctx, "GET", l.server.URL+"/v1/invocations/"+op+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+l.user())
	c := *l.server.Client()
	c.Timeout = 0
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("subscriber", resp.StatusCode)
	}
	first := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		early, reset, again := false, false, false
		var event, id string
		scan := bufio.NewScanner(resp.Body)
		for scan.Scan() {
			line := scan.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "id: "):
				id = strings.TrimPrefix(line, "id: ")
			case line == "":
				switch event {
				case "delta":
					if !early && strings.HasPrefix(id, "1:") {
						early = true
						close(first)
					}
					if reset {
						if !strings.HasPrefix(id, "2:") {
							result <- fmt.Errorf("stale delta after reset, cursor %s", id)
							return
						}
						again = true
					}
				case "reset":
					if !early || id != "2:0" {
						result <- fmt.Errorf("unexpected reset, cursor %s", id)
						return
					}
					reset = true
				case "end":
					if !early || !reset || !again {
						result <- fmt.Errorf("incomplete event sequence, first %v reset %v resumed %v", early, reset, again)
					} else {
						result <- nil
					}
					return
				}
				event, id = "", ""
			}
		}
		result <- fmt.Errorf("subscription ended before the restored result: %v", scan.Err())
	}()
	l.await("first attempt's live delta", true, func() bool {
		select {
		case <-first:
			return true
		case err := <-result:
			t.Fatal(err)
		default:
		}
		return false
	})
	if _, err = l.worker.RestoreFromArchive(ctx, "rst_"+strings.Repeat("8", 32), agent, archiveID, archives, func(err error) { t.Error(err) }); err != nil {
		t.Fatal(err)
	}
	l.await("reset and resumed deltas on the same subscription", true, func() bool {
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
			return true
		default:
			return false
		}
	})
	var old, current int
	if err = l.db.QueryRow(ctx, "SELECT count(*) FILTER (WHERE attempt=1),count(*) FILTER (WHERE attempt=2) FROM invocation_stream_chunks WHERE operation_id=$1", op).Scan(&old, &current); err != nil || old != 0 || current == 0 {
		t.Fatal("stored attempts", old, current, err)
	}
}
