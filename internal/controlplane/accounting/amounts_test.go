package accounting

import "testing"

func TestOperationAmountsAndCosts(t *testing.T) {
	for i, c := range []struct {
		q           Amounts
		reservation bool
		ok          bool
	}{
		{Amounts{Operation: Chat, Input: 1}, true, true},
		{Amounts{Operation: Chat}, true, false},
		{Amounts{Operation: Chat}, false, true},
		{Amounts{Operation: Chat, Input: 1, Pages: 1}, true, false},
		{Amounts{Operation: Embed, Input: 1, Output: 1}, true, false},
		{Amounts{Operation: Transcribe, AudioSeconds: 1}, true, true},
		{Amounts{Operation: Transcribe, AudioSeconds: 1, Input: 1}, true, false},
		{Amounts{Operation: Transcribe}, false, true},
		{Amounts{Operation: OCR, Pages: 1}, true, true},
		{Amounts{Operation: OCR, Pages: 2e9}, false, false},
		{Amounts{Operation: Vision, Input: 1}, true, false},
		{Amounts{Operation: Chat, Input: -1}, false, false},
	} {
		if c.q.Valid(c.reservation) != c.ok {
			t.Fatal(i, c)
		}
	}
	p := Prices{InputPerMillion: 1_000_000, OutputPerMillion: 3_000_000, AudioPerMinute: 7, PerPage: 11}
	for q, want := range map[Amounts]int64{
		{Operation: Embed, Input: 5}:              5,
		{Operation: Chat, Input: 1, Output: 1}:    4,
		{Operation: Transcribe, AudioSeconds: 1}:  1, // 7/60 rounded up
		{Operation: Transcribe, AudioSeconds: 60}: 7,
		{Operation: Transcribe, AudioSeconds: 61}: 8,
		{Operation: OCR, Pages: 3}:                33,
	} {
		if got, ok := p.Cost(q); !ok || got != want {
			t.Fatal(q, got, want)
		}
	}
	if _, ok := (Prices{AudioPerMinute: 1e12}).Cost(Amounts{Operation: Transcribe, AudioSeconds: 1e12}); ok {
		t.Fatal("an overflow was priced")
	}
}
