// Package directory publishes organization agents to the private AGNTCY
// Directory (v1.8.0, OASF schema 1.1.0) and searches it. The Directory is an
// index: PostgreSQL stays the source of truth, and every search hit is checked
// there again (controlplane.FindDirectoryAgentsFromVM).
//
// The Directory API server has no authentication of its own in the supported
// profile; it is reached through the mutual-TLS edge of deploy/interop, with the
// control plane's client certificate. Only the generated gRPC stubs of
// github.com/agntcy/dir/api are used.
package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	corev1 "github.com/agntcy/dir/api/core/v1"
	searchv1 "github.com/agntcy/dir/api/search/v1"
	storev1 "github.com/agntcy/dir/api/store/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// SchemaVersion is the OASF schema of every record (profile agentcapsule-int-1).
const SchemaVersion = "1.1.0"

// ErrUnavailable means the Directory could not be reached or did not answer;
// the same call may be retried later.
var ErrUnavailable = errors.New("directory unavailable")

// InvalidRecordError is the schema's refusal of a record. Message is the
// schema server's explanation, meant for the organization that described the
// agent.
type InvalidRecordError struct{ Message string }

func (e *InvalidRecordError) Error() string { return "directory record refused: " + e.Message }

// Name is the record name of an agent. The organization segment confines a
// search to one organization on the server (the platform filters again).
func Name(tenant, agent string) string { return "agentcapsule/" + tenant + "/" + agent }

// RecordInput is what a record says about an agent.
type RecordInput struct {
	Tenant, Agent   string
	Revision        int64
	Description     string
	Skills, Domains []int
	CreatedAt       time.Time
}

// Record builds the OASF 1.1.0 record of an agent. Skills and domains carry
// their class IDs only; the schema server checks they exist. Nothing else about
// the agent or its organization is published.
func Record(in RecordInput) ([]byte, error) {
	if in.Tenant == "" || in.Agent == "" || strings.ContainsRune(in.Tenant+in.Agent, '/') || in.Revision < 1 || len(in.Skills) == 0 {
		return nil, errors.New("directory: incomplete record")
	}
	classes := func(ids []int) []map[string]int {
		out := make([]map[string]int, len(ids))
		for i, id := range ids {
			out[i] = map[string]int{"id": id}
		}
		return out
	}
	record := map[string]any{
		"schema_version": SchemaVersion,
		"name":           Name(in.Tenant, in.Agent),
		"version":        "1.0." + strconv.FormatInt(in.Revision, 10),
		"description":    in.Description,
		"authors":        []string{"Agent Capsule"},
		"created_at":     in.CreatedAt.UTC().Format(time.RFC3339),
		"skills":         classes(in.Skills),
	}
	if len(in.Domains) > 0 {
		record["domains"] = classes(in.Domains)
	}
	return json.Marshal(record)
}

// Credentials are the PEM material of the control plane's identity: the
// Directory authority, and the client certificate and key the edge admits.
type Credentials struct{ CA, Cert, Key []byte }

// Client talks to the Directory over mutual TLS.
type Client struct {
	conn   *grpc.ClientConn
	store  storev1.StoreServiceClient
	search searchv1.SearchServiceClient
}

// Dial prepares a client for the edge at address (host:port); the connection
// itself is made on first use.
func Dial(address string, c Credentials) (*Client, error) {
	if address == "" {
		return nil, errors.New("directory: address required")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.CA) {
		return nil, errors.New("directory: no certificate in the CA")
	}
	pair, err := tls.X509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, fmt.Errorf("directory: client certificate: %w", err)
	}
	creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{pair}})
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	return &Client{conn: conn, store: storev1.NewStoreServiceClient(conn), search: searchv1.NewSearchServiceClient(conn)}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func unavailable(err error) error {
	return fmt.Errorf("%w (%s)", ErrUnavailable, status.Code(err))
}

// Push stores a record and returns its content ID. The same record always has
// the same ID, so pushing it again is harmless.
func (c *Client) Push(ctx context.Context, raw []byte) (string, error) {
	record, err := corev1.UnmarshalRecord(raw)
	if err != nil {
		return "", &InvalidRecordError{Message: "not an OASF record"}
	}
	stream, err := c.store.Push(ctx)
	if err == nil {
		err = stream.Send(record)
	}
	if err == nil {
		err = stream.CloseSend()
	}
	var ref *corev1.RecordRef
	if err == nil {
		ref, err = stream.Recv()
	}
	if status.Code(err) == codes.InvalidArgument {
		return "", &InvalidRecordError{Message: status.Convert(err).Message()}
	}
	if err != nil {
		return "", unavailable(err)
	}
	if ref.GetCid() == "" {
		return "", fmt.Errorf("%w (empty content ID)", ErrUnavailable)
	}
	return ref.GetCid(), nil
}

// Delete removes a record; a record already gone is not an error.
func (c *Client) Delete(ctx context.Context, cid string) error {
	stream, err := c.store.Delete(ctx)
	if err == nil {
		err = stream.Send(&corev1.RecordRef{Cid: cid})
	}
	if err == nil {
		_, err = stream.CloseAndRecv()
	}
	if err == nil || status.Code(err) == codes.NotFound {
		return nil
	}
	return unavailable(err)
}

// Search returns the content IDs of the records of one organization that have
// any of the skills, at most limit of them.
func (c *Client) Search(ctx context.Context, tenant string, skills []int, limit uint32) ([]string, error) {
	if tenant == "" || strings.ContainsAny(tenant, "/*") || len(skills) == 0 || limit < 1 || limit > 100 {
		return nil, errors.New("directory: invalid search")
	}
	// Queries of one type match any value; different types must all match.
	queries := []*searchv1.RecordQuery{{Type: searchv1.RecordQueryType_RECORD_QUERY_TYPE_NAME, Value: Name(tenant, "*")}}
	for _, s := range skills {
		queries = append(queries, &searchv1.RecordQuery{Type: searchv1.RecordQueryType_RECORD_QUERY_TYPE_SKILL_ID, Value: strconv.Itoa(s)})
	}
	stream, err := c.search.SearchCIDs(ctx, &searchv1.SearchCIDsRequest{Queries: queries, Limit: &limit})
	if err != nil {
		return nil, unavailable(err)
	}
	var cids []string
	for {
		r, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return cids, nil
		}
		if err != nil {
			return nil, unavailable(err)
		}
		if len(cids) == int(limit) {
			return cids, nil
		}
		cids = append(cids, r.GetRecordCid())
	}
}
