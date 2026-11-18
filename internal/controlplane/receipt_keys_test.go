package controlplane

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorization"
)

// The daily receipt keys (docs/adr/006-authority-service.md §7, wave 6).

// daySource stands for the authority service: one key per day, which it
// can lose or give again under another value, and which it can stop giving.
type daySource struct {
	mu    sync.Mutex
	keys  map[time.Time][]byte
	gone  map[time.Time]bool
	down  bool
	asked int
}

func newDaySource() *daySource {
	return &daySource{keys: map[time.Time][]byte{}, gone: map[time.Time]bool{}}
}

func (d *daySource) fetch(_ context.Context, day time.Time) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked++
	switch {
	case d.down:
		return nil, errors.New("the authority service does not answer")
	case d.gone[day]:
		return nil, errors.Join(ErrReceiptKeyGone, errors.New("key_revoked"))
	}
	k, ok := d.keys[day]
	if !ok {
		k = make([]byte, 32)
		_, _ = rand.Read(k)
		d.keys[day] = k
	}
	return bytes.Clone(k), nil
}

func (d *daySource) key(day time.Time) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return bytes.Clone(d.keys[day])
}

func (d *daySource) set(f func(*daySource)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f(d)
}

func (d *daySource) questions() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.asked
}

// apiClock is the API's clock of days.
type apiClock struct {
	mu sync.Mutex
	t  time.Time
}

func (k *apiClock) now() time.Time {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.t
}

func (k *apiClock) set(t time.Time) {
	k.mu.Lock()
	k.t = t
	k.mu.Unlock()
}

var receiptDay16 = time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)

// withDailyKeys gives a an authority service of daily keys, on k's days.
func withDailyKeys(t *testing.T, a *Accounts, src *daySource, k *apiClock) {
	t.Helper()
	if err := a.useDailyReceiptKeys(src.fetch, k.now); err != nil {
		t.Fatal(err)
	}
}

func open(t *testing.T, key, ciphertext, aad []byte) ([]byte, error) {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	n := c.NonceSize()
	return c.Open(nil, ciphertext[:n], ciphertext[n:], aad)
}

// The ring holds today's and yesterday's keys: it asks the service once per
// day, forgets older days, and treats them as gone without asking. A key
// the service does not give is unavailable; one it lost is gone.
func TestReceiptKeyRingKeepsTodayAndYesterday(t *testing.T) {
	src := newDaySource()
	k := &apiClock{t: receiptDay16.Add(10 * time.Hour)}
	ring := &receiptKeyRing{fetch: src.fetch, now: k.now, keys: map[time.Time]cipher.AEAD{}}
	ctx := t.Context()
	first, err := ring.aead(ctx, receiptDay16.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if again, err := ring.aead(ctx, receiptDay16.Add(20*time.Hour)); err != nil || again != first || src.questions() != 1 {
		t.Fatal("the same day asked again", err, src.questions())
	}
	k.set(receiptDay16.AddDate(0, 0, 1).Add(time.Hour))
	if again, err := ring.aead(ctx, receiptDay16); err != nil || again != first || src.questions() != 1 {
		t.Fatal("yesterday's key", err, src.questions())
	}
	k.set(receiptDay16.AddDate(0, 0, 2))
	if _, err = ring.aead(ctx, receiptDay16); !errors.Is(err, ErrReceiptKeyGone) || src.questions() != 1 {
		t.Fatal("a key older than yesterday", err, src.questions())
	}
	ring.mu.Lock()
	kept := len(ring.keys)
	ring.mu.Unlock()
	if kept != 0 {
		t.Fatal("the ring keeps an old key in memory")
	}
	today := receiptDay16.AddDate(0, 0, 2)
	src.set(func(d *daySource) { d.down = true })
	if _, err = ring.aead(ctx, today); !errors.Is(err, ErrReceiptKeyUnavailable) || !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatal("a service that does not answer", err)
	}
	src.set(func(d *daySource) { d.down, d.gone[today] = false, true })
	if _, err = ring.aead(ctx, today); !errors.Is(err, ErrReceiptKeyGone) {
		t.Fatal("a key the service lost", err)
	}
}

// Every new receipt is encrypted with the key of its day, and names that
// day: the installation's key cannot read it. A replay decrypts it with
// that day's key, held in memory.
func TestReceiptsUseTheKeyOfTheirDay(t *testing.T) {
	s, a, p := accountLab(t)
	src, k := newDaySource(), &apiClock{t: receiptDay16.Add(10 * time.Hour)}
	withDailyKeys(t, a, src, k)
	u := createAccount(t, a, p, "user", "Ada")
	in := IssueTokenInput{ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
	r, err := a.IssueUserToken(t.Context(), p, u.ID, "token", in)
	if err != nil {
		t.Fatal(err)
	}
	var day *time.Time
	var ciphertext []byte
	if err = s.pool.QueryRow(t.Context(), "SELECT key_day,response_ciphertext FROM http_receipts WHERE key='token'").Scan(&day, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if day == nil || !day.Equal(receiptDay16) {
		t.Fatal("the receipt names the day", day)
	}
	aad, _ := json.Marshal(scope(p, "POST", "/v1/users/"+u.ID+"/tokens", "token"))
	if plain, err := open(t, src.key(receiptDay16), ciphertext, aad); err != nil || !bytes.Equal(plain, r.Body) {
		t.Fatal("the day's key does not open the receipt", err)
	}
	if _, err = a.cipher.Open(nil, ciphertext[:12], ciphertext[12:], aad); err == nil {
		t.Fatal("the installation's key opens a daily receipt")
	}
	// The next day, the API still holds yesterday's key: the replay gives
	// the first answer, secret included, without asking the service.
	k.set(receiptDay16.AddDate(0, 0, 1).Add(9 * time.Hour))
	again, err := a.IssueUserToken(t.Context(), p, u.ID, "token", in)
	if err != nil || !again.Replayed || !bytes.Equal(again.Body, r.Body) {
		t.Fatal("the replay", err)
	}
	if src.questions() != 1 {
		t.Fatal("the API asked the service", src.questions(), "times")
	}
	// A new receipt of the new day takes the new day's key.
	createAccount(t, a, p, "user-2", "Grace")
	if err = s.pool.QueryRow(t.Context(), "SELECT key_day FROM http_receipts WHERE key='user-2'").Scan(&day); err != nil || !day.Equal(receiptDay16.AddDate(0, 0, 1)) {
		t.Fatal("the new day's receipt names", day, err)
	}
}

// The tenant receipts, a service token's secret included, take the daily
// key too.
func TestTenantReceiptsUseTheKeyOfTheirDay(t *testing.T) {
	l, _, owner := agentLab(t)
	src, k := newDaySource(), &apiClock{t: receiptDay16.Add(10 * time.Hour)}
	withDailyKeys(t, l.a, src, k)
	account := newServiceAccount(t, l, owner, "bot", "bot", authorization.AgentOperator)
	token := issueServiceToken(t, l, owner, account.ID, "token", "org:read", "agent:read")
	var day *time.Time
	var ciphertext []byte
	if err := l.s.pool.QueryRow(t.Context(), "SELECT key_day,response_ciphertext FROM tenant_http_receipts WHERE key='token'").Scan(&day, &ciphertext); err != nil {
		t.Fatal(err)
	}
	if day == nil || !day.Equal(receiptDay16) || bytes.Contains(ciphertext, []byte(token.Token)) {
		t.Fatal("the tenant receipt's day", day)
	}
	r, err := l.a.IssueServiceToken(t.Context(), owner, account.ID, "token", IssueServiceTokenInput{Scopes: []string{"org:read", "agent:read"}, ExpiresAt: token.ExpiresAt})
	var again IssuedServiceToken
	if err != nil || !r.Replayed || json.Unmarshal(r.Body, &again) != nil || again.Token != token.Token {
		t.Fatal("the tenant replay", err)
	}
}

// A receipt whose day's key is gone cannot be replayed: the replay is
// refused with ErrReceiptUnreadable, and the request does not run again.
// Gone: older than yesterday for the API, destroyed or lost by the service,
// or given again under another value after a failover lost the first.
func TestReceiptOfAGoneDayKeyIsNotReplayed(t *testing.T) {
	s, a, p := accountLab(t)
	src, k := newDaySource(), &apiClock{t: receiptDay16.Add(23 * time.Hour)}
	withDailyKeys(t, a, src, k)
	u := createAccount(t, a, p, "user", "Ada")
	in := IssueTokenInput{ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
	if _, err := a.IssueUserToken(t.Context(), p, u.ID, "token", in); err != nil {
		t.Fatal(err)
	}
	tokens := count(t, s, "api_tokens")
	replay := func(name string, a *Accounts) {
		t.Helper()
		if _, err := a.IssueUserToken(t.Context(), p, u.ID, "token", in); !errors.Is(err, ErrReceiptUnreadable) {
			t.Fatal(name, err)
		}
		if count(t, s, "api_tokens") != tokens {
			t.Fatal(name, "issued the token again")
		}
	}
	// Another API process, whose service lost the day's key.
	fresh := func(src *daySource) *Accounts {
		other, err := NewAccounts(s, bytes.Repeat([]byte{0x42}, 32))
		if err != nil {
			t.Fatal(err)
		}
		withDailyKeys(t, other, src, &apiClock{t: receiptDay16.Add(23 * time.Hour)})
		return other
	}
	lost := newDaySource()
	lost.gone[receiptDay16] = true
	replay("a key the service lost", fresh(lost))
	replay("a key given again under another value", fresh(newDaySource()))
	// Two midnights later, for the API holding it: the receipt is still in
	// the database here, as with a clock behind, and nothing reads it.
	k.set(receiptDay16.AddDate(0, 0, 2))
	replay("a key older than yesterday", a)
}

// Without the day's key the API writes nothing: the request fails before
// it runs, and says the authority service is unavailable.
func TestNewReceiptWaitsForTheKeyOfItsDay(t *testing.T) {
	s, a, p := accountLab(t)
	src, k := newDaySource(), &apiClock{t: receiptDay16}
	src.down = true
	withDailyKeys(t, a, src, k)
	if _, err := a.CreateUser(t.Context(), p, "user", CreateUserInput{DisplayName: "Ada"}); !errors.Is(err, ErrReceiptKeyUnavailable) || !errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatal("a receipt without its day's key", err)
	}
	if count(t, s, "users") != 0 || count(t, s, "http_receipts") != 0 {
		t.Fatal("the request ran without its receipt key")
	}
	src.set(func(d *daySource) { d.down = false })
	createAccount(t, a, p, "user", "Ada")
}

// The receipts written with the installation's key, before the daily keys
// or by an API without the authority service, name no day and stay
// readable until they expire. A daily receipt needs the service.
func TestReceiptsOfTheInstallationKeyStayReadable(t *testing.T) {
	s, a, p := accountLab(t)
	u := createAccount(t, a, p, "before", "Ada")
	var day *time.Time
	if err := s.pool.QueryRow(t.Context(), "SELECT key_day FROM http_receipts WHERE key='before'").Scan(&day); err != nil || day != nil {
		t.Fatal("a receipt of the installation's key names a day", day, err)
	}
	daily, err := NewAccounts(s, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	withDailyKeys(t, daily, newDaySource(), &apiClock{t: receiptDay16})
	r, err := daily.CreateUser(t.Context(), p, "before", CreateUserInput{DisplayName: "Ada"})
	var again User
	if err != nil || !r.Replayed || json.Unmarshal(r.Body, &again) != nil || again.ID != u.ID {
		t.Fatal("a receipt of the installation's key after the daily keys", err)
	}
	createAccount(t, daily, p, "after", "Grace")
	if _, err = a.CreateUser(t.Context(), p, "after", CreateUserInput{DisplayName: "Grace"}); !errors.Is(err, ErrReceiptKeyUnavailable) {
		t.Fatal("an API without the authority service read a daily receipt", err)
	}
	if err = daily.UseDailyReceiptKeys(newDaySource().fetch); !errors.Is(err, ErrConflict) {
		t.Fatal("the daily keys were replaced", err)
	}
}
