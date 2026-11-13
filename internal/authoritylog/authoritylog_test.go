package authoritylog

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	testRestore = "restoreauth_" + strings.Repeat("1", 32)
	testKeys    = "keyauth_" + strings.Repeat("2", 32)
	testAgent   = "agt_" + strings.Repeat("a", 32)
	testVolume  = "vol_" + strings.Repeat("b", 32)
)

func sampleRecord() Record {
	return Record{Version: Version, Epoch: 1, Seq: 7, Prev: Origin(), Ops: []Op{
		{Kind: OpStatement, Statement: 7, Rows: 1, Args: []Arg{{Type: "s", Text: "event-1"}, {Type: "i", Int: 0}, {Type: "b", Bytes: bytes.Repeat([]byte{9}, 32)}}},
		{Kind: OpKeyCreate, Agent: testAgent, Volume: testVolume, Commitment: make([]byte, 32), Wrapped: []byte{1, 2, 3}},
		{Kind: OpKeyRevoke, Agent: testAgent, Volume: testVolume},
	}}
}

func TestRecordsAreCanonical(t *testing.T) {
	b, err := sampleRecord().Encode()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Decode(b)
	if err != nil || r.Seq != 7 || len(r.Ops) != 3 || !r.HasSecret() {
		t.Fatal(r, err)
	}
	again, _ := r.Encode()
	if !bytes.Equal(again, b) || !bytes.Equal(Digest(again), Digest(b)) {
		t.Fatal("encoding is not stable")
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"space":         func(b []byte) []byte { return append([]byte(" "), b...) },
		"trailing":      func(b []byte) []byte { return append(slices.Clone(b), []byte("{}")...) },
		"unknown field": func(b []byte) []byte { return bytes.Replace(b, []byte(`{"v":1`), []byte(`{"x":0,"v":1`), 1) },
		"empty":         func([]byte) []byte { return nil },
	} {
		if _, err = Decode(mutate(b)); !errors.Is(err, ErrRecord) {
			t.Fatal(name, err)
		}
	}
	for name, mutate := range map[string]func(*Record){
		"seq 0":            func(r *Record) { r.Seq = 0 },
		"epoch 0":          func(r *Record) { r.Epoch = 0 },
		"short prev":       func(r *Record) { r.Prev = r.Prev[:31] },
		"no ops":           func(r *Record) { r.Ops = nil },
		"zero rows":        func(r *Record) { r.Ops[0].Rows = 0 },
		"key on statement": func(r *Record) { r.Ops[0].Wrapped = []byte{1} },
		"bad agent":        func(r *Record) { r.Ops[1].Agent = "agent" },
		"unwrapped key":    func(r *Record) { r.Ops[1].Wrapped = nil },
		"revoke with key":  func(r *Record) { r.Ops[2].Wrapped = []byte{1} },
		"unknown op":       func(r *Record) { r.Ops[2].Kind = "drop" },
		"newline":          func(r *Record) { r.Ops[0].Args[0].Text = "a\nb" },
		"mixed arg":        func(r *Record) { r.Ops[0].Args[1].Text = "x" },
	} {
		r := sampleRecord()
		mutate(&r)
		if _, err = r.Encode(); !errors.Is(err, ErrRecord) {
			t.Fatal(name, err)
		}
	}
	for _, v := range []any{"s", 1, int64(-2), uint64(3), []byte{4}} {
		a, err := ArgOf(v)
		if err != nil {
			t.Fatal(v, err)
		}
		if got := a.Value(); got == nil {
			t.Fatal(v)
		}
	}
	if _, err = ArgOf(uint64(1 << 63)); err == nil {
		t.Fatal("overflowing integer accepted")
	}
	if _, err = ArgOf(1.5); err == nil {
		t.Fatal("float accepted")
	}
}

func TestWrappedSecretsOpenOnlyWithTheUnlockKeyInTheirContext(t *testing.T) {
	text, recipient, err := GenerateUnlockKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseUnlockKey(text)
	if err != nil || key.Recipient() != recipient {
		t.Fatal(err)
	}
	parsed, err := ParseRecipient(recipient.String())
	if err != nil || parsed != recipient {
		t.Fatal(err)
	}
	if strings.Contains(recipient.String(), string(bytes.TrimSpace(text))) {
		t.Fatal("recipient text holds the unlock key")
	}
	secret := bytes.Repeat([]byte{7}, 32)
	context := KeyContext(testKeys, testAgent, testVolume)
	wrapped, err := Seal(recipient, context, secret)
	if err != nil || bytes.Contains(wrapped, secret) || len(wrapped) != 32+32+16 {
		t.Fatal(len(wrapped), err)
	}
	got, err := key.Open(context, wrapped)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatal(err)
	}
	other, _, _ := GenerateUnlockKey()
	otherKey, _ := ParseUnlockKey(other)
	if _, err = otherKey.Open(context, wrapped); !errors.Is(err, ErrWrap) {
		t.Fatal("opened with another unlock key", err)
	}
	if _, err = key.Open(KeyContext(testKeys, testAgent, "vol_"+strings.Repeat("c", 32)), wrapped); !errors.Is(err, ErrWrap) {
		t.Fatal("opened for another volume", err)
	}
	wrapped[len(wrapped)-1] ^= 1
	if _, err = key.Open(context, wrapped); !errors.Is(err, ErrWrap) {
		t.Fatal("opened a damaged copy", err)
	}
	for _, bad := range []string{"", "agentcapsule-unlock-key-v1:AAAA", string(recipient.String())} {
		if _, err = ParseUnlockKey([]byte(bad)); !errors.Is(err, ErrWrap) {
			t.Fatal("bad unlock key accepted", bad)
		}
	}
	if _, err = ParseRecipient(string(text)); !errors.Is(err, ErrWrap) {
		t.Fatal("unlock key accepted as a recipient")
	}
	a := KeyCommitment(testKeys, testAgent, testVolume, secret)
	if bytes.Equal(a, KeyCommitment(testKeys, testAgent, testVolume, bytes.Repeat([]byte{8}, 32))) ||
		bytes.Equal(a, KeyCommitment(testKeys, testAgent, "vol_"+strings.Repeat("c", 32), secret)) {
		t.Fatal("commitments collide")
	}
}

// writeSide writes one side's certificate and key, and returns their paths.
func writeSide(t *testing.T, dir, role, restore string) (string, string) {
	t.Helper()
	certificate, key, err := GenerateCertificate(role, restore, testKeys)
	if err != nil {
		t.Fatal(err)
	}
	c, k := filepath.Join(dir, role+".crt"), filepath.Join(dir, role+".key")
	if err = os.WriteFile(c, certificate, 0644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(k, key, 0600); err != nil {
		t.Fatal(err)
	}
	return c, k
}

type fixedReplica struct {
	mu       sync.Mutex
	requests []Request
	refuse   string
}

func (f *fixedReplica) Sync(_ context.Context, r Request) (Position, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
	p := Position{Epoch: r.Epoch, Seq: uint64(len(r.Records)), Digest: Origin()}
	if f.refuse != "" {
		return p, &Refusal{Kind: f.refuse, Position: p}
	}
	return p, nil
}

func TestTheLinkIsMutualTLSWithPinnedCertificates(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	primaryCrt, primaryKey := writeSide(t, dir, RolePrimary, testRestore)
	replicaCrt, replicaKey := writeSide(t, dir, RoleReplica, testRestore)
	impostorCrt, impostorKey := writeSide(t, other, RolePrimary, testRestore)
	impostorReplica, _ := writeSide(t, other, RoleReplica, testRestore)
	serverTLS, err := TLSFiles{Certificate: replicaCrt, Key: replicaKey, PeerCertificate: primaryCrt, RestoreAuthority: testRestore, KeyAuthority: testKeys}.ServerTLS()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	replica := &fixedReplica{}
	var observed []error
	var mu sync.Mutex
	server := &Server{Replica: replica, Config: serverTLS, Observe: func(err error) { mu.Lock(); observed = append(observed, err); mu.Unlock() }}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	defer func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	}()
	client := func(certificate, key, peer string) *Client {
		config, err := TLSFiles{Certificate: certificate, Key: key, PeerCertificate: peer, RestoreAuthority: testRestore, KeyAuthority: testKeys}.ClientTLS()
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewClient(listener.Addr().String(), config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	record, _ := sampleRecord().Encode()
	good := client(primaryCrt, primaryKey, replicaCrt)
	for range 3 {
		position, err := good.Sync(t.Context(), Request{RestoreAuthority: testRestore, KeyAuthority: testKeys, Epoch: 4, Records: [][]byte{record}})
		if err != nil || position.Epoch != 4 || position.Seq != 1 {
			t.Fatal(position, err)
		}
	}
	if len(replica.requests) != 3 || !bytes.Equal(replica.requests[0].Records[0], record) {
		t.Fatal("records changed on the way", replica.requests)
	}
	replica.mu.Lock()
	replica.refuse = RefusedGap
	replica.mu.Unlock()
	if _, err = good.Sync(t.Context(), Request{Epoch: 1}); ErrorKind(err) != "refused_gap" {
		t.Fatal("refusal lost on the way", err)
	}
	// Another primary's certificate is refused, and so is a replica that is
	// not the pinned one.
	if _, err = client(impostorCrt, impostorKey, replicaCrt).Sync(t.Context(), Request{Epoch: 1}); err == nil {
		t.Fatal("unpinned primary accepted")
	}
	if _, err = client(primaryCrt, primaryKey, impostorReplica).Sync(t.Context(), Request{Epoch: 1}); err == nil {
		t.Fatal("unpinned replica accepted")
	}
	// A certificate for other authorities, or the wrong role, does not load.
	otherCrt, otherKey := writeSide(t, t.TempDir(), RolePrimary, "restoreauth_"+strings.Repeat("3", 32))
	for _, files := range []TLSFiles{
		{Certificate: otherCrt, Key: otherKey, PeerCertificate: replicaCrt, RestoreAuthority: testRestore, KeyAuthority: testKeys},
		{Certificate: replicaCrt, Key: replicaKey, PeerCertificate: replicaCrt, RestoreAuthority: testRestore, KeyAuthority: testKeys},
	} {
		if _, err = files.ClientTLS(); err == nil {
			t.Fatal("certificate for another side accepted", files)
		}
	}
	if err = os.Chmod(primaryKey, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = (TLSFiles{Certificate: primaryCrt, Key: primaryKey, PeerCertificate: replicaCrt, RestoreAuthority: testRestore, KeyAuthority: testKeys}).ClientTLS(); err == nil {
		t.Fatal("readable private key accepted")
	}
	// A dead replica is unreachable, within the context's deadline.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	address := dead.Addr().String()
	dead.Close()
	unreachable, _ := NewClient(address, good.config)
	short, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if _, err = unreachable.Sync(short, Request{Epoch: 1}); ErrorKind(err) != ErrorUnreachable {
		t.Fatal(ErrorKind(err), err)
	}
}

func TestErrorKindsAreClosed(t *testing.T) {
	for _, err := range []error{nil, &Refusal{Kind: RefusedGap}, ErrBehind, ErrDiverged, context.DeadlineExceeded, ErrProtocol, ErrRecord, errors.New("disk")} {
		if !slices.Contains(ErrorKinds(), ErrorKind(err)) {
			t.Fatal(err, ErrorKind(err))
		}
	}
	if ErrorKind(errors.Join(errors.New("x"), &Refusal{Kind: RefusedOlderEpoch})) != "refused_older_epoch" {
		t.Fatal("joined refusal lost")
	}
}
