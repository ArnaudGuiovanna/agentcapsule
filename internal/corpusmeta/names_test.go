package corpusmeta

import (
	"strings"
	"testing"
)

func TestNames(t *testing.T) {
	for name, want := range map[string]bool{"finance-l3": true, "a": true, "3d.models_v2": true, "-x": false, "X": false,
		"a b": false, "": false, strings.Repeat("a", 100): true, strings.Repeat("a", 101): false, "é": false} {
		if ValidName(name) != want {
			t.Error("name", name)
		}
	}
	for mount, want := range map[string]bool{"finance": true, "finance_l3": true, "a.b": false, "": false,
		strings.Repeat("m", 63): true, strings.Repeat("m", 64): false} {
		if ValidMount(mount) != want {
			t.Error("mount", mount)
		}
	}
	if DefaultMount("finance-l3") != "finance-l3" || DefaultMount("finance.l3") != "" {
		t.Error("default mount")
	}
	if !ValidVersion(1) || !ValidVersion(1<<31-1) || ValidVersion(0) || ValidVersion(1<<31) {
		t.Error("versions")
	}
	id := DocumentID("courses/chap1.pdf")
	if !ValidMount(id) || len(id) != 17 || id[0] != 'd' || DocumentID("courses/chap1.pdf") != id || DocumentID("courses/chap2.pdf") == id {
		t.Error("document ID", id)
	}
}
