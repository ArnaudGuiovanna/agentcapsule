//go:build linux && amd64 && root_integration

package sandbox

import "testing"

// REG-01: as root, the program, as the dedicated account, may make the
// system calls debugfs makes and no other.
func TestAsRootTheProgramIsKilledForAnyOtherSystemCall(t *testing.T) {
	o := requireRoot(t)
	o.TestTools = false
	for _, p := range syscallProbes {
		got := outcome(t, o, probe(t, p.nr, false, p.args...))
		if p.want == passed && got != killed {
			continue
		}
		if got != p.want {
			t.Errorf("%s: %s, not %s", p.name, got, p.want)
		}
	}
	confinedKillsAnotherArchitecture(t, o)
}
