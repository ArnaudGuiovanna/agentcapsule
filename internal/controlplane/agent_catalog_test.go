package controlplane

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func catalogInput(owner string) CreateAgentInput {
	return CreateAgentInput{OwnerUserID: owner, Name: "Compagnon", Harness: HarnessReference{Name: "reference", Version: "1.0.0"}, Resources: AgentResources{1, 256, 256}}
}
func catalogLab(t *testing.T) (*Store, *Accounts, *AgentCatalog, Principal, User, Principal) {
	t.Helper()
	s, a, admin := accountLab(t)
	u := createAccount(t, a, admin, "owner", "Arnaud")
	token := issueAccountToken(t, a, admin, u, "owner-token")
	owner, err := s.Authenticate(t.Context(), token.Token)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewAgentCatalog(a, "local")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RegisterLocalRelease(t.Context(), HarnessReference{"reference", "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err = s.ConfigureHostStorage(t.Context(), "local", 512); err != nil {
		t.Fatal(err)
	}
	return s, a, c, admin, u, owner
}
func TestAgentReservationAtomicPendingAndPrivate(t *testing.T) {
	s, a, c, admin, u, owner := catalogLab(t)
	in := catalogInput(u.ID)
	r, err := c.Reserve(t.Context(), owner, "create", in)
	if err != nil {
		t.Fatal(err)
	}
	var created AgentCreation
	if err = json.Unmarshal(r.Body, &created); err != nil {
		t.Fatal(err)
	}
	if r.Status != 202 || created.Status != "PENDING" {
		t.Fatal("reservation advertised completion")
	}
	view, err := c.Get(t.Context(), owner, created.AgentID)
	if err != nil || view.State != "PROVISIONING" {
		t.Fatal("unprovisioned volume advertised ready", err)
	}
	op, err := c.Operation(t.Context(), owner, created.OperationID)
	if err != nil || op.Kind != "provision" || op.Status != "PENDING" {
		t.Fatal("durable operation missing", err)
	}
	if _, err = s.GrantMandate(t.Context(), u.ID, created.AgentID, "early-instruction", 1, time.Now().Add(time.Hour)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unprovisioned agent gained authority", err)
	}
	again, err := c.Reserve(t.Context(), owner, "create", in)
	if err != nil || !again.Replayed || string(again.Body) != string(r.Body) {
		t.Fatal("creation replay", err)
	}
	if count(t, s, "platform_operations") != 1 || count(t, s, "agent_specs") != 1 {
		t.Fatal("duplicate provisioning")
	}
	v := createAccount(t, a, admin, "other", "Marc")
	otherToken := issueAccountToken(t, a, admin, v, "other-token")
	other, err := s.Authenticate(t.Context(), otherToken.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Get(t.Context(), other, created.AgentID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign agent leaked", err)
	}
	if _, err = c.Operation(t.Context(), other, created.OperationID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign operation leaked", err)
	}
	if _, err = c.Reserve(t.Context(), other, "impersonate", in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign owner creation accepted", err)
	}
	if _, err = c.Get(t.Context(), admin, created.AgentID); err != nil {
		t.Fatal("admin cannot inspect technical state", err)
	}
}

func TestAgentReservationConcurrentOwnerAndStorage(t *testing.T) {
	s, a, c, admin, u, owner := catalogLab(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		wg.Go(func() { _, err := c.Reserve(t.Context(), owner, string(rune('a'+i)), catalogInput(u.ID)); errs <- err })
	}
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrAgentExists) {
			t.Fatal("creation race", err)
		}
	}
	if success != 1 || count(t, s, "agent_specs") != 1 || count(t, s, "platform_operations") != 1 {
		t.Fatal("owner uniqueness lost", success)
	}
	if err := s.ConfigureHostStorage(t.Context(), "local", 128); !errors.Is(err, ErrStorageCapacity) {
		t.Fatal("quota shrank below reservations", err)
	}
	v := createAccount(t, a, admin, "second", "Marc")
	w := createAccount(t, a, admin, "third", "Lea")
	errs = make(chan error, 2)
	for _, id := range []string{v.ID, w.ID} {
		wg.Go(func() { _, err := c.Reserve(t.Context(), admin, "quota/"+id, catalogInput(id)); errs <- err })
	}
	wg.Wait()
	close(errs)
	success = 0
	for err := range errs {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrStorageCapacity) {
			t.Fatal("capacity race", err)
		}
	}
	if success != 1 || count(t, s, "agent_specs") != 2 {
		t.Fatal("storage reservation overcommitted", success)
	}
}

func TestAgentReservationRollbackAndReleaseImmutability(t *testing.T) {
	s, _, c, _, u, owner := catalogLab(t)
	if _, err := s.RegisterLocalRelease(t.Context(), HarnessReference{"reference", "1.0.0"}, "sha256:"+strings.Repeat("b", 64)); !errors.Is(err, ErrRelease) {
		t.Fatal("version rebound", err)
	}
	if _, err := s.pool.Exec(t.Context(), `CREATE FUNCTION reject_provision() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected operation failure'; END $$;
        CREATE TRIGGER reject_op BEFORE INSERT ON platform_operations FOR EACH ROW EXECUTE FUNCTION reject_provision()`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Reserve(t.Context(), owner, "atomic", catalogInput(u.ID)); err == nil {
		t.Fatal("operation failure ignored")
	}
	var n int
	if err := s.pool.QueryRow(t.Context(), "SELECT count(*) FROM agents WHERE owner_user_id=$1", u.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 || count(t, s, "agent_specs") != 0 || count(t, s, "platform_operations") != 0 {
		t.Fatal("partial provisioning reservation")
	}
	if _, err := s.pool.Exec(t.Context(), "DROP TRIGGER reject_op ON platform_operations"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Reserve(t.Context(), owner, "atomic", catalogInput(u.ID)); err != nil {
		t.Fatal("retry after rollback", err)
	}
}
