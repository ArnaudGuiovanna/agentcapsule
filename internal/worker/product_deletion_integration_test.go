//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityclient"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/directory"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// labDirectory wires the worker to the private Directory of deploy/interop, as
// its "directory" section does, and returns the client and a publisher.
func (l *registryLab) labDirectory(address, certs string) (*directory.Client, *directory.Publisher) {
	t := l.t
	t.Helper()
	read := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(certs, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	dir, err := directory.Dial(address, directory.Credentials{CA: read("control-plane/directory-ca.pem"),
		Cert: read("control-plane/directory.crt"), Key: read("control-plane/directory.key")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	if err = l.worker.EnableDirectory(dir); err != nil {
		t.Fatal(err)
	}
	return dir, &directory.Publisher{Store: l.store, Directory: dir}
}

// statusOf sends a JSON request and returns its HTTP status alone.
func (l *productPeerLab) statusOf(token, method, path, key string, input any) int {
	l.t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		l.t.Fatal(err)
	}
	r, err := http.NewRequestWithContext(l.t.Context(), method, l.server.URL+path, bytes.NewReader(body))
	if err != nil {
		l.t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	response, err := l.server.Client().Do(r)
	if err != nil {
		l.t.Fatal("HTTP transport", method, path, err)
	}
	response.Body.Close()
	return response.StatusCode
}

// Deleting an organization's agent blocks its work, stops its VM, and
// destroys its volume, its key and its Directory record (OPR-18). The work
// queued before the deletion is canceled and new work is refused as soon as
// the deletion is accepted. Once it completes: no VM, no volume file, the key
// revoked in the key authority, destroyed through the authority service,
// which destroys a key only under its store's permanent seal; and the
// Directory, which held the agent's record, no longer finds it.
func TestProductWorkerDeletionRemovesTheVolumeTheKeyAndTheDirectoryRecord(t *testing.T) {
	address, certs := os.Getenv("AGENTCAPSULE_KVM_DIRECTORY_ADDR"), os.Getenv("AGENTCAPSULE_KVM_INTEROP_CERTS")
	if address == "" || certs == "" {
		t.Fatal("the private Directory is required (verify-product-guest.py --slim-bridge-build)")
	}
	l := newRegistryLab(t)
	if _, ok := l.worker.authority.(*testAuthority).Authority.(*authorityclient.Client); !ok {
		t.Fatal("the lab's worker does not reach its authorities through the authority service")
	}
	dir, publisher := l.labDirectory(address, certs)
	agent := l.createOn("deleted", "reference", "1.0.0").AgentID
	tenant, err := l.store.AgentOrganization(t.Context(), agent)
	if err != nil {
		t.Fatal(err)
	}
	l.request(l.owner(), "PUT", "/v1/agents/"+agent+"/directory", "visible", map[string]any{"visible": true,
		"description": "Answers with the text it receives.", "skills": []int{10301}}, 200, nil)
	var cid string
	l.await("the agent's record in the Directory", false, func() bool {
		if _, err := publisher.RunOnce(t.Context()); err != nil {
			t.Log("publish:", err)
			return false
		}
		var e controlplane.DirectoryEntry
		l.request(l.owner(), "GET", "/v1/agents/"+agent+"/directory", "", nil, 200, &e)
		if e.Publication != "published" || e.RecordCID == nil {
			return false
		}
		cid = *e.RecordCID
		found, err := dir.Search(t.Context(), tenant, []int{10301}, 10)
		return err == nil && slices.Contains(found, cid)
	})
	l.answers(agent, "before-delete", "answered before the deletion")
	e, err := l.store.VolumeEnrollment(t.Context(), agent, "local")
	if err != nil {
		t.Fatal(err)
	}
	binding := enrollmentBinding(e)
	volume := filepath.Join(l.root, "volumes", e.VolumeID+".luks")
	run := l.runs(1)[agent]

	t.Log("stage: the deletion is accepted: queued work is canceled, new work refused")
	queued := l.invoke(agent, "queued-before-delete", "never delivered")
	var deletion controlplane.AgentCreation
	l.request(l.owner(), "DELETE", "/v1/agents/"+agent, "delete", nil, 202, &deletion)
	var status, code string
	if err = l.db.QueryRow(t.Context(), "SELECT status,coalesce(error_code,'') FROM platform_operations WHERE id=$1", queued).Scan(&status, &code); err != nil ||
		status != "CANCELED" || code != "agent_unavailable" {
		t.Fatal("work queued before the deletion was not canceled", status, code, err)
	}
	invoke := map[string]any{"content": []map[string]string{{"type": "text", "text": "after the deletion"}}}
	if got := l.statusOf(l.user(), "POST", "/v1/agents/"+agent+"/invocations", "after-delete", invoke); got/100 != 4 {
		t.Fatal("an invocation was admitted after the deletion", got)
	}
	if got := l.statusOf(l.owner(), "POST", "/v1/agents/"+agent+"/wake", "wake-deleted", map[string]any{}); got/100 != 4 {
		t.Fatal("a wake was admitted after the deletion", got)
	}

	t.Log("stage: the deletion completes: no VM, no volume, no key")
	l.awaitOperation(l.owner, deletion.OperationID)
	var phase string
	if err = l.db.QueryRow(t.Context(), "SELECT phase FROM agents WHERE id=$1", agent).Scan(&phase); err != nil || phase != "DELETED" {
		t.Fatal("the deletion did not include the physical cleanup", phase, err)
	}
	l.runs(0)
	if sameProcess(run.PID, run.StartTicks) {
		t.Fatal("the deleted agent's VMM survived")
	}
	if _, err = os.Lstat(volume); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the deleted agent's volume file remains", err)
	}
	if err = l.keys.WithKey(t.Context(), agent, e.VolumeID, func([]byte) error { t.Error("the deleted key was delivered"); return nil }); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("the key was not revoked", err)
	}
	if err = l.keys.Ensure(t.Context(), agent, e.VolumeID); !errors.Is(err, keyauthority.ErrRevoked) {
		t.Fatal("the deleted key could be created again", err)
	}
	// The service holds the store sealed, and destroys a key only under that
	// sealed binding: another incarnation's is refused.
	if _, err = l.worker.authority.Lookup(t.Context(), agent); !errors.Is(err, restoreauthority.ErrSealed) {
		t.Fatal("the authority service does not hold the store sealed", err)
	}
	stale := binding
	stale.Incarnation++
	if err = l.worker.authority.DestroyKey(t.Context(), stale); !errors.Is(err, restoreauthority.ErrStale) {
		t.Fatal("the service destroyed a key under another binding than the sealed one", err)
	}

	t.Log("stage: the Directory no longer holds the agent's record")
	l.await("the record withdrawn from the Directory", false, func() bool {
		if _, err := publisher.RunOnce(t.Context()); err != nil {
			t.Log("publish:", err)
			return false
		}
		found, err := dir.Search(t.Context(), tenant, []int{10301}, 10)
		return err == nil && !slices.Contains(found, cid)
	})
}
