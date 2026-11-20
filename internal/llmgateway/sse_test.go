package llmgateway

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type sseEvent struct{ name, data string }

func readAll(t *testing.T, text string) ([]sseEvent, int, error) {
	t.Helper()
	comments := 0
	r := newSSEReader(strings.NewReader(text), func() { comments++ })
	var out []sseEvent
	for {
		name, data, err := r.next()
		if err != nil {
			return out, comments, err
		}
		out = append(out, sseEvent{name, string(data)})
	}
}

// The reader follows the SSE format: fields, comments, the three line ends,
// data lines joined by a newline, an event dispatched at a blank line only.
func TestSSEReaderFollowsTheFormat(t *testing.T) {
	text := ": opening comment\n" +
		"retry: 3000\n" +
		"event: message_start\ndata: {\"a\":1}\n\n" +
		"id: 7\r\ndata:{\"b\":2}\r\n\r\n" +
		"data: {\"c\":\r" + "data: 3}\r\r" +
		"event: ping\n\n" + // no data: not an event
		": keep-alive\n" +
		"event: tail\ndata: {}\n" // no blank line before the end: dropped
	got, comments, err := readAll(t, text)
	if !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	want := []sseEvent{{"message_start", `{"a":1}`}, {"", `{"b":2}`}, {"", "{\"c\":\n3}"}}
	if len(got) != len(want) {
		t.Fatalf("%q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event %d: %q, want %q", i, got[i], want[i])
		}
	}
	if comments != 2 {
		t.Fatal("comment lines", comments)
	}
}

// A line is at most 64 KiB and an event's data at most 60 KiB, its lines
// joined: past either the stream is cut, so that one event always fits in a
// channel frame.
func TestSSEReaderBoundsLinesAndEvents(t *testing.T) {
	pad := func(n int) string { return strings.Repeat("x", n) }
	// A comment line of exactly 64 KiB is read; one byte more is a cut.
	if _, _, err := readAll(t, ":"+pad(maxSSELine-1)+"\n"); !errors.Is(err, io.EOF) {
		t.Fatal("a line at the bound was refused", err)
	}
	for _, end := range []string{"\n", "\r\n", "\r", ""} {
		if _, _, err := readAll(t, ":"+pad(maxSSELine)+end); !errors.Is(err, errSSELine) {
			t.Fatalf("a line past the bound (end %q) was read: %v", end, err)
		}
	}
	// Data of exactly 60 KiB, in one line or in two, is one event.
	at := `{"t":"` + pad(maxSSEData-8) + `"}`
	if got, _, err := readAll(t, "data: "+at+"\n\n"); !errors.Is(err, io.EOF) || len(got) != 1 || len(got[0].data) != maxSSEData {
		t.Fatal("data at the bound", len(got), err)
	}
	half := pad(maxSSEData/2 - 1)
	if got, _, err := readAll(t, "data: "+half+"\ndata: "+half+"\n\n"); !errors.Is(err, io.EOF) || len(got) != 1 || len(got[0].data) != maxSSEData-1 {
		t.Fatal("joined data", len(got), err)
	}
	if _, _, err := readAll(t, "data: "+half+"\ndata: "+half+"xx\n\n"); !errors.Is(err, errSSEData) {
		t.Fatal("joined data past the bound", err)
	}
	if _, _, err := readAll(t, "data: "+pad(maxSSEData+1)+"\n\n"); !errors.Is(err, errSSEData) {
		t.Fatal("data past the bound", err)
	}
	// An event's name is a short token: it goes into the frame too.
	if _, _, err := readAll(t, "event: "+pad(65)+"\ndata: {}\n\n"); !errors.Is(err, errSSEName) {
		t.Fatal("a long event name", err)
	}
	if _, _, err := readAll(t, "event: a\"b\ndata: {}\n\n"); !errors.Is(err, errSSEName) {
		t.Fatal("an event name with a quote", err)
	}
}
