//go:build interop_services

// Against the private Directory of deploy/interop, started by
// scripts/verify-interop.py --services (INTEROP_CERTS, INTEROP_DIRECTORY_ADDR):
// the records this package builds pass the real OASF 1.1.0 schema, and the
// publisher's steps leave exactly the expected records.
package directory

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

func labClient(t *testing.T) *Client {
	t.Helper()
	dir, addr := os.Getenv("INTEROP_CERTS"), os.Getenv("INTEROP_DIRECTORY_ADDR")
	if dir == "" || addr == "" {
		t.Fatal("INTEROP_CERTS and INTEROP_DIRECTORY_ADDR are required")
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, "control-plane", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	c, err := Dial(addr, Credentials{CA: read("directory-ca.pem"), Cert: read("directory.crt"), Key: read("directory.key")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestPublisherAgainstThePrivateDirectory(t *testing.T) {
	c := labClient(t)
	tenant := fmt.Sprintf("org_%d", time.Now().UnixNano())
	store := &memoryStore{row: controlplane.DirectoryWork{AgentID: "agt_summarizer", TenantID: tenant, Revision: 1, Publish: true,
		Description: "Summarizes documents.", Skills: []int{10302}, Domains: []int{111}, CreatedAt: time.Now()}}
	p := &Publisher{Store: store, Directory: c}
	run := func() {
		t.Helper()
		if _, err := p.RunOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
		if store.due() {
			t.Fatalf("work left after a round: %+v (deferred %s)", store.row, store.deferred)
		}
	}
	search := func(skills ...int) []string {
		t.Helper()
		cids, err := c.Search(t.Context(), tenant, skills, 100)
		if err != nil {
			t.Fatal(err)
		}
		return cids
	}

	run()
	first := store.row.PublishedCID
	if store.state != "published" || !reflect.DeepEqual(search(10302), []string{first}) || len(search(10301)) != 0 {
		t.Fatal("first publication", store.state, first)
	}
	// Another organization's scope does not see it.
	if cids, err := c.Search(t.Context(), tenant+"x", []int{10302}, 100); err != nil || len(cids) != 0 {
		t.Fatal("a neighbouring scope found the record", cids, err)
	}

	store.row.Revision, store.row.Description, store.row.Skills = 2, "Summarizes and completes documents.", []int{10301, 10302}
	run()
	second := store.row.PublishedCID
	if second == first || !reflect.DeepEqual(search(10301), []string{second}) || !reflect.DeepEqual(search(10302), []string{second}) {
		t.Fatal("the old record is still found", first, second, search(10302))
	}

	// The real schema refuses an unknown skill; the previous record goes too.
	store.row.Revision, store.row.Skills = 3, []int{99999}
	run()
	if store.state != "invalid" || !strings.Contains(store.reason, "99999") || len(search(10301, 10302, 99999)) != 0 {
		t.Fatal("invalid record", store.state, store.reason)
	}

	store.row.Revision, store.row.Skills = 4, []int{10302}
	run()
	if len(search(10302)) != 1 {
		t.Fatal("republication")
	}
	store.row.Revision, store.row.Publish = 5, false
	run()
	if store.state != "unpublished" || len(search(10301, 10302)) != 0 {
		t.Fatal("hidden agent still found")
	}
}
