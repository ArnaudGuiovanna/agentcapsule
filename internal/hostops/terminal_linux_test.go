package hostops

import (
	"bytes"
	"os"
	"testing"
)

func TestTerminalDetection(t *testing.T) {
	// A PTY and /dev/null are both character devices, but only the PTY
	// can prompt the operator. CI and redirected scripts must never prompt.
	pty, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("PTY unavailable: %v", err)
	}
	defer pty.Close()
	if !isTerminal(pty) {
		t.Fatal("expected a real terminal")
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if isTerminal(null) || isTerminal(&bytes.Buffer{}) {
		t.Fatal("redirected streams must disable prompts")
	}
}
