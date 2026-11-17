//go:build linux

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

// adoptionLab is a host registry of confirmed VMs whose physical census the
// test stands in for. Its Adopt counts each agent's adoptions and answers
// refuse[agent], nil by default.
type adoptionLab struct {
	h       *FirecrackerHost
	mu      sync.Mutex
	adopted map[string]int
	refuse  map[string]error
}

// newAdoptionLab runs agents agent-00 to agent-<running-1>, each at
// generation 1. With authenticated, each boot has its control credentials.
func newAdoptionLab(t *testing.T, running int, authenticated bool) *adoptionLab {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"admission", "volumes", "credentials"} {
		if err := os.Mkdir(filepath.Join(root, d), 0700); err != nil {
			t.Fatal(err)
		}
	}
	l := &adoptionLab{adopted: map[string]int{}, refuse: map[string]error{}}
	l.h = &FirecrackerHost{root: root, cgroup: filepath.Join(root, "groups"),
		census: func(*HostAgent) (bool, error) { return true, nil }}
	l.h.opts = FirecrackerOptions{MaxActive: running + 1, AuthenticatedControl: authenticated,
		Ready:   func(context.Context, string) error { return nil },
		Confirm: func(context.Context, string, VMRun) error { return nil },
		Adopt:   l.adopt}
	err := l.h.locked(t.Context(), func(r *hostRegistry) error {
		for i := range running {
			id := fmt.Sprintf("agent-%02d", i)
			run := &VMRun{Incarnation: 1, ID: fmt.Sprintf("%016x", i+1), Generation: 1, Phase: "RUNNING", PID: 1, StartTicks: "1"}
			run.Socket = filepath.Join(l.h.jail(run), "vsock")
			a := &HostAgent{ID: id, UID: uint32(10000 + i), Volume: filepath.Join(root, "volumes", id), Generation: 1, Run: run}
			r.Agents[id] = a
			if authenticated {
				if _, err := l.h.prepareControl(a); err != nil {
					return err
				}
			}
		}
		return l.h.save(r)
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (l *adoptionLab) adopt(_ context.Context, id string, _ VMRun) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.adopted[id]++
	return l.refuse[id]
}

// register adds a stopped agent, without a run.
func (l *adoptionLab) register(t *testing.T, id string) {
	t.Helper()
	err := l.h.locked(t.Context(), func(r *hostRegistry) error {
		r.Agents[id] = &HostAgent{ID: id, UID: uint32(10000 + len(r.Agents)), Volume: filepath.Join(l.h.root, "volumes", id)}
		return l.h.save(r)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// expectAdopted checks the adoptions since the last check, then forgets them.
func (l *adoptionLab) expectAdopted(t *testing.T, what string, want map[string]int) {
	t.Helper()
	l.mu.Lock()
	got := l.adopted
	l.adopted = map[string]int{}
	l.mu.Unlock()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s adopted %v, want %v", what, got, want)
	}
}

// expectRunning checks which agents still have a run in the registry.
func (l *adoptionLab) expectRunning(t *testing.T, want ...string) {
	t.Helper()
	var got []string
	err := l.h.locked(t.Context(), func(r *hostRegistry) error {
		for id, a := range r.Agents {
			if a.Run != nil {
				got = append(got, id)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("running %v, want %v", got, want)
	}
}

// Using one agent's VM, by reusing it at a start or by opening its control
// session (each delivery, each platform call), adopts that VM alone. The
// cost of a delivery to a running agent must not grow with the number of VMs
// that run beside it: the capacity benchmark of 2026-11-17 held 7 bindings
// per running VM to prepare each delivery.
func TestUsingAVMAdoptsOnlyThatVM(t *testing.T) {
	for _, n := range []int{1, 5, 20} {
		t.Run(fmt.Sprintf("%d VMs", n), func(t *testing.T) {
			reuse := newAdoptionLab(t, n, false)
			if _, err := reuse.h.Start(t.Context(), "agent-00", 1); err != nil {
				t.Fatal(err)
			}
			reuse.expectAdopted(t, "reusing a running VM", map[string]int{"agent-00": 1})

			control := newAdoptionLab(t, n, true)
			if _, err := control.h.ControlForRetirement(t.Context(), "agent-00"); err != nil {
				t.Fatal(err)
			}
			control.expectAdopted(t, "a control session", map[string]int{"agent-00": 1})
			_, due, err := control.h.CredentialRotation(t.Context(), "agent-00", time.Now())
			if err != nil || due {
				t.Fatal("fresh credentials found due", due, err)
			}
			control.expectAdopted(t, "an agent's credential check", map[string]int{"agent-00": 1})
			runs, err := control.h.ReconcileAgent(t.Context(), "agent-00")
			if err != nil || len(runs) != 1 || runs["agent-00"].ID == "" {
				t.Fatal("an agent's reconciliation", runs, err)
			}
			control.expectAdopted(t, "an agent's reconciliation", map[string]int{"agent-00": 1})
		})
	}
}

// A VM whose binding went stale or sealed fails its adoption (the worker's
// Adopt answers ErrGeneration). Its first use retires it and is refused.
func TestAStaleVMIsRetiredAtItsFirstUse(t *testing.T) {
	control := newAdoptionLab(t, 3, true)
	control.refuse["agent-01"] = ErrGeneration
	if _, err := control.h.ControlForRetirement(t.Context(), "agent-01"); !errors.Is(err, ErrNoVM) {
		t.Fatal("a control session reached a stale VM", err)
	}
	control.expectRunning(t, "agent-00", "agent-02")

	reuse := newAdoptionLab(t, 3, false)
	reuse.refuse["agent-01"] = ErrGeneration
	if _, err := reuse.h.Start(t.Context(), "agent-01", 1); !errors.Is(err, ErrGeneration) {
		t.Fatal("a stale VM was reused", err)
	}
	reuse.expectRunning(t, "agent-00", "agent-02")

	agent := newAdoptionLab(t, 3, true)
	agent.refuse["agent-01"] = ErrGeneration
	if runs, err := agent.h.ReconcileAgent(t.Context(), "agent-01"); err != nil || len(runs) != 0 {
		t.Fatal("a stale VM survived its agent's reconciliation", runs, err)
	}
	agent.expectRunning(t, "agent-00", "agent-02")
}

// A VM nobody uses is checked at the host's next census: Reconcile (each
// maintenance pass starts with one) and the credential census. A stale one is
// retired there; an outage keeps it and fails the census, as before.
func TestAnUnusedVMIsCheckedAtTheNextCensus(t *testing.T) {
	outage := errors.New("authority unavailable")
	for _, census := range []string{"reconcile", "credentials"} {
		t.Run(census, func(t *testing.T) {
			l := newAdoptionLab(t, 3, true)
			run := func() error {
				if census == "reconcile" {
					_, err := l.h.Reconcile(t.Context())
					return err
				}
				_, err := l.h.CredentialRotations(t.Context(), time.Now())
				return err
			}
			l.refuse["agent-02"] = outage
			// Another agent's outage does not block the use of agent-00.
			if _, err := l.h.ControlForRetirement(t.Context(), "agent-00"); err != nil {
				t.Fatal(err)
			}
			if err := run(); !errors.Is(err, outage) {
				t.Fatal("the census hid an outage", err)
			}
			l.expectRunning(t, "agent-00", "agent-01", "agent-02")
			l.refuse["agent-02"] = ErrGeneration
			if _, err := l.h.ControlForRetirement(t.Context(), "agent-00"); err != nil {
				t.Fatal(err)
			}
			l.expectRunning(t, "agent-00", "agent-01", "agent-02")
			l.expectAdopted(t, "using agent-00 twice, and one census", map[string]int{"agent-00": 3, "agent-01": 1, "agent-02": 1})
			if err := run(); err != nil {
				t.Fatal(err)
			}
			l.expectAdopted(t, "the census", map[string]int{"agent-00": 1, "agent-01": 1, "agent-02": 1})
			l.expectRunning(t, "agent-00", "agent-01")
		})
	}
}

// A boot counts the host's VMs after it checked each of them: a stale VM does
// not take a slot from it.
func TestABootChecksEveryVMBeforeCountingThem(t *testing.T) {
	l := newAdoptionLab(t, 3, false)
	l.h.opts.MaxActive = 3
	l.register(t, "agent-03")
	l.refuse["agent-01"] = ErrGeneration
	_, err := l.h.Start(t.Context(), "agent-03", 1)
	if err == nil || errors.Is(err, ErrCapacity) {
		// Past the count, the boot stops at the volume this lab lacks.
		t.Fatal("the boot counted a stale VM", err)
	}
	l.expectAdopted(t, "a boot", map[string]int{"agent-00": 1, "agent-01": 1, "agent-02": 1})
	l.expectRunning(t, "agent-00", "agent-02")
}
