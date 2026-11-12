package slimlink

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// The bridge (runtime/slimbridge, its own module) writes the same contract and
// reads these same examples; both sides decode them strictly and write them
// back unchanged.
func TestTheBridgeContractIsTheSameOnBothSides(t *testing.T) {
	raw, err := os.ReadFile("testdata/contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]json.RawMessage
	if err = json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	var paths map[string]string
	var codes []string
	var namespace string
	_ = json.Unmarshal(c["paths"], &paths)
	_ = json.Unmarshal(c["codes"], &codes)
	_ = json.Unmarshal(c["platform_namespace"], &namespace)
	if !reflect.DeepEqual(paths, map[string]string{"serve": ServePath, "send": SendPath, "health": HealthPath, "deliver": DeliverPath}) ||
		!reflect.DeepEqual(codes, []string{CodeUnreachable, CodeRefused, CodeFailed, CodeInvalid, CodeUnavailable}) || namespace != PlatformNamespace {
		t.Fatal("paths, codes or namespace differ", paths, codes, namespace)
	}
	for name, v := range map[string]any{"serve": &ServeRequest{}, "send": &SendRequest{}, "deliver": &DeliverRequest{}, "receipt": &Receipt{}, "health": &Health{}, "failure": &Failure{}} {
		d := json.NewDecoder(bytes.NewReader(c[name]))
		d.DisallowUnknownFields()
		if err = d.Decode(v); err != nil {
			t.Fatal(name, err)
		}
		again, _ := json.Marshal(v)
		var want, got any
		_ = json.Unmarshal(c[name], &want)
		_ = json.Unmarshal(again, &got)
		if !reflect.DeepEqual(want, got) {
			t.Fatal(name, string(again))
		}
	}
}
