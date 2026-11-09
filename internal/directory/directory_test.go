package directory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	corev1 "github.com/agntcy/dir/api/core/v1"
	searchv1 "github.com/agntcy/dir/api/search/v1"
	storev1 "github.com/agntcy/dir/api/store/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func TestRecordPublishesOnlyTheDescribedFields(t *testing.T) {
	created := time.Date(2026, 11, 9, 10, 0, 0, 0, time.FixedZone("x", 3600))
	raw, err := Record(RecordInput{Tenant: "org_1", Agent: "agt_2", Revision: 3, Description: "Summarizes documents.",
		Skills: []int{10301, 10302}, CreatedAt: created})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"schema_version": "1.1.0", "name": "agentcapsule/org_1/agt_2", "version": "1.0.3",
		"description": "Summarizes documents.", "authors": []any{"Agent Capsule"}, "created_at": "2026-11-09T09:00:00Z",
		"skills": []any{map[string]any{"id": float64(10301)}, map[string]any{"id": float64(10302)}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("record\n got %v\nwant %v", got, want)
	}
	raw, _ = Record(RecordInput{Tenant: "org_1", Agent: "agt_2", Revision: 1, Description: "d", Skills: []int{1}, Domains: []int{111}, CreatedAt: created})
	got = nil
	if err = json.Unmarshal(raw, &got); err != nil || !reflect.DeepEqual(got["domains"], []any{map[string]any{"id": float64(111)}}) {
		t.Fatal("record with domains", got, err)
	}
	if _, err = corev1.UnmarshalRecord(raw); err != nil {
		t.Fatal("the Directory types cannot decode the record", err)
	}
	for _, bad := range []RecordInput{
		{Tenant: "org/1", Agent: "a", Revision: 1, Skills: []int{1}},
		{Tenant: "org", Agent: "a/b", Revision: 1, Skills: []int{1}},
		{Tenant: "org", Agent: "a", Revision: 0, Skills: []int{1}},
		{Tenant: "org", Agent: "a", Revision: 1},
	} {
		if _, err = Record(bad); err == nil {
			t.Fatal("incomplete record accepted", bad)
		}
	}
}

// ---------------------------------------------------------------- TLS lab

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newAuthority(t *testing.T, cn string) authority {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return authority{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (a authority) issue(t *testing.T, cn string, server bool) (certPEM, keyPEM []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// fakeDirectory answers like the Directory API server behind its edge.
type fakeDirectory struct {
	storev1.UnimplementedStoreServiceServer
	searchv1.UnimplementedSearchServiceServer
	mu      sync.Mutex
	records map[string]*corev1.Record
	queries []*searchv1.RecordQuery
	down    bool
}

func (f *fakeDirectory) Push(s storev1.StoreService_PushServer) error {
	r, err := s.Recv()
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return status.Error(codes.Unavailable, "down")
	}
	if r.GetData().GetFields()["description"].GetStringValue() == "refuse me" {
		return status.Error(codes.InvalidArgument, `record validation failed: [ERROR: Unknown "id" value]`)
	}
	f.records[r.GetCid()] = r
	return s.Send(&corev1.RecordRef{Cid: r.GetCid()})
}

func (f *fakeDirectory) Delete(s storev1.StoreService_DeleteServer) error {
	ref, err := s.Recv()
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return status.Error(codes.Unavailable, "down")
	}
	if _, ok := f.records[ref.GetCid()]; !ok {
		return status.Error(codes.NotFound, "record not found")
	}
	delete(f.records, ref.GetCid())
	return s.SendAndClose(nil)
}

func (f *fakeDirectory) SearchCIDs(req *searchv1.SearchCIDsRequest, s searchv1.SearchService_SearchCIDsServer) error {
	f.mu.Lock()
	f.queries = req.GetQueries()
	cids := make([]string, 0, len(f.records))
	for cid := range f.records {
		cids = append(cids, cid)
	}
	f.mu.Unlock()
	slices.Sort(cids)
	for _, cid := range cids {
		if err := s.Send(&searchv1.SearchCIDsResponse{RecordCid: cid}); err != nil {
			return err
		}
	}
	return nil
}

// startDirectory serves fake on loopback with mutual TLS and returns its
// address and a client identity signed by the same authority.
func startDirectory(t *testing.T, fake *fakeDirectory) (string, Credentials) {
	ca := newAuthority(t, "test Directory CA")
	serverCert, serverKey := ca.issue(t, "directory", true)
	pair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.pem)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{pair}, ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12})))
	storev1.RegisterStoreServiceServer(srv, fake)
	searchv1.RegisterSearchServiceServer(srv, fake)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	clientCert, clientKey := ca.issue(t, "agentcapsule-control-plane", false)
	return l.Addr().String(), Credentials{CA: ca.pem, Cert: clientCert, Key: clientKey}
}

func TestClientPublishesSearchesAndDeletesOverMutualTLS(t *testing.T) {
	fake := &fakeDirectory{records: map[string]*corev1.Record{}}
	address, creds := startDirectory(t, fake)
	c, err := Dial(address, creds)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := t.Context()
	raw, _ := Record(RecordInput{Tenant: "org_1", Agent: "agt_1", Revision: 1, Description: "d", Skills: []int{10302}, CreatedAt: time.Now()})
	cid, err := c.Push(ctx, raw)
	want, _ := corev1.UnmarshalRecord(raw)
	if err != nil || cid != want.GetCid() {
		t.Fatal("push", cid, err)
	}
	if again, err := c.Push(ctx, raw); err != nil || again != cid {
		t.Fatal("the same record must keep its content ID", again, err)
	}
	refused, _ := Record(RecordInput{Tenant: "org_1", Agent: "agt_1", Revision: 2, Description: "refuse me", Skills: []int{1}, CreatedAt: time.Now()})
	var invalid *InvalidRecordError
	if _, err = c.Push(ctx, refused); !errors.As(err, &invalid) || invalid.Message != `record validation failed: [ERROR: Unknown "id" value]` {
		t.Fatal("refusal", err)
	}
	cids, err := c.Search(ctx, "org_1", []int{10302, 10301}, 10)
	if err != nil || !reflect.DeepEqual(cids, []string{cid}) {
		t.Fatal("search", cids, err)
	}
	var queries []string
	for _, q := range fake.queries {
		queries = append(queries, q.GetType().String()+"="+q.GetValue())
	}
	if !reflect.DeepEqual(queries, []string{"RECORD_QUERY_TYPE_NAME=agentcapsule/org_1/*", "RECORD_QUERY_TYPE_SKILL_ID=10302", "RECORD_QUERY_TYPE_SKILL_ID=10301"}) {
		t.Fatal("queries", queries)
	}
	for _, bad := range []string{"", "org/1", "org*"} {
		if _, err = c.Search(ctx, bad, []int{1}, 10); err == nil {
			t.Fatal("search scope accepted", bad)
		}
	}
	if err = c.Delete(ctx, cid); err != nil {
		t.Fatal("delete", err)
	}
	if err = c.Delete(ctx, cid); err != nil {
		t.Fatal("a record already gone is not an error", err)
	}
	fake.down = true
	if _, err = c.Push(ctx, raw); !errors.Is(err, ErrUnavailable) {
		t.Fatal("outage", err)
	}
	if err = c.Delete(ctx, cid); !errors.Is(err, ErrUnavailable) {
		t.Fatal("outage on delete", err)
	}
}

func TestClientRefusesAnotherAuthority(t *testing.T) {
	address, creds := startDirectory(t, &fakeDirectory{records: map[string]*corev1.Record{}})
	other := newAuthority(t, "other CA")
	creds.Cert, creds.Key = other.issue(t, "agentcapsule-control-plane", false)
	c, err := Dial(address, creds)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err = c.Search(ctx, "org_1", []int{1}, 1); !errors.Is(err, ErrUnavailable) {
		t.Fatal("a certificate of another authority was accepted", err)
	}
	if _, err = Dial(address, Credentials{CA: creds.CA}); err == nil {
		t.Fatal("a client without certificate was configured")
	}
}
