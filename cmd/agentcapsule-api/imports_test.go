package main

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The programs that run inside a guest: its init, the harnesses and the
// guests of the verification labs.
var guestPrograms = []string{"cmd/capsule-init", "cmd/capsule-echo", "cmd/capsule-adapter", "examples/a2a-agent",
	"internal/verification/guest", "internal/verification/controlguest"}

// guestShared are linked by the guests and by the host on purpose: the
// protocol between them, the capability names, and the guest's event store,
// whose envelopes and outcome fingerprints the host checks. They start no VM
// and run no harness.
var guestShared = []string{"internal/capsuleprotocol", "internal/capability", "internal/harnessstore"}

// hostRuntime starts and stops VMs, and opens, mounts or archives their
// volumes: the worker's code, which runs as root.
var hostRuntime = []string{"internal/runtime", "internal/worker", "internal/volumestore", "internal/volumearchive"}

// deps lists the packages of this module that the packages link, relative to
// the module, with go list.
func deps(t *testing.T, module string, packages ...string) []string {
	t.Helper()
	args := []string{"list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}"}
	for _, p := range packages {
		args = append(args, module+"/"+p)
	}
	out, err := exec.CommandContext(t.Context(), "go", args...).Output()
	if err != nil {
		t.Fatal("go list", packages, err)
	}
	var linked []string
	for _, line := range strings.Fields(string(out)) {
		if rest, ok := strings.CutPrefix(line, module+"/"); ok {
			linked = append(linked, rest)
		}
	}
	return linked
}

func goModule(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", "list", "-m").Output()
	if err != nil {
		t.Fatal("go list -m", err)
	}
	return strings.TrimSpace(string(out))
}

// guestCode is what the guest programs link, but the host may not: the
// programs themselves, the guest's init library and the harnesses.
func guestCode(t *testing.T, module string) []string {
	t.Helper()
	var code []string
	for _, p := range deps(t, module, guestPrograms...) {
		if !slices.Contains(guestShared, p) {
			code = append(code, p)
		}
	}
	for _, must := range []string{"internal/guestinit", "internal/referenceharness", "internal/agentadapter"} {
		if !slices.Contains(code, must) {
			t.Fatal("the guest programs no longer link", must, "; review guestPrograms:", code)
		}
	}
	return code
}

// CONV-9, RUN-010: the API is an HTTP front end over PostgreSQL. It links
// neither the runtime that starts Firecracker, nor the worker, nor any code
// that runs in a guest. No route can then hand a command to a VM or to the
// host, nor run a harness, whatever it is sent.
func TestAPILinksNoRuntimeWorkerOrGuestCode(t *testing.T) {
	module := goModule(t)
	denied := append(guestCode(t, module), hostRuntime...)
	deps(t, module, hostRuntime...) // fails when one is renamed or gone
	linked := deps(t, module, "cmd/agentcapsule-api")
	if !slices.Contains(linked, "internal/api") {
		t.Fatal("go list does not see the API's own packages", linked)
	}
	for _, p := range linked {
		if slices.Contains(denied, p) {
			t.Error("agentcapsule-api links", p)
		}
	}
}

// RUN-010: the worker drives the guests through their protocol, and links no
// harness nor any other code that runs in a guest. A harness runs only in its
// VM.
func TestWorkerLinksNoHarnessCode(t *testing.T) {
	module := goModule(t)
	denied := guestCode(t, module)
	linked := deps(t, module, "cmd/agentcapsule-worker")
	if !slices.Contains(linked, "internal/worker") || !slices.Contains(linked, "internal/capsuleprotocol") {
		t.Fatal("go list does not see the worker's own packages", linked)
	}
	for _, p := range linked {
		if slices.Contains(denied, p) {
			t.Error("agentcapsule-worker links", p)
		}
	}
}
