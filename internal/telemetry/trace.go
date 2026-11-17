package telemetry

// Traces (OPR-3). A span records one step of the platform's work: an API
// request, an invocation's admission, a worker job, a delivery, a wake, a
// boot, a model call, a call to the authority service. Like metrics and
// events, a span cannot carry content: its name and its code attributes come
// from declared vocabularies, its other attributes are numbers, and every
// identifier is a pseudonym, a keyed hash of the installation (Pseudonym).
// The operator, who holds the key, can correlate; an export of the traces
// names no organization, agent or person.
//
// A trace is the work one API request starts: its ID is the request's
// X-Request-ID, which the operation the request creates keeps in PostgreSQL
// (migration 0027), so the worker continues the same trace for every job the
// request causes. The IDs follow W3C Trace Context: a 16-byte trace ID and
// 8-byte span IDs, in lowercase hex.
//
// The Tracer writes finished spans as OTLP/JSON lines: each line is one
// ExportTraceServiceRequest of the OpenTelemetry protocol, the format of the
// OpenTelemetry Collector's otlpjsonfile receiver and file exporter. Spans
// wait in a bounded queue for a background writer; when it is full, a span is
// dropped and counted, so tracing never blocks or slows the work beyond the
// cost of recording.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// SpanKind is the OpenTelemetry kind of a span.
type SpanKind int

const (
	SpanInternal SpanKind = 1
	SpanServer   SpanKind = 2
	SpanClient   SpanKind = 3
	SpanConsumer SpanKind = 5
)

// Bounds of the tracer.
const (
	// TraceQueue is how many finished spans wait for the writer at most.
	TraceQueue = 4096
	// traceBatch is how many spans one line carries at most.
	traceBatch = 256
	// maxAttributes bounds the attributes of one span; more are dropped.
	maxAttributes = 32
	// PseudonymLength is the length of a pseudonym, in hex digits (64 bits).
	PseudonymLength = 16
)

var attributePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,5}$`)

func validAttribute(key string) bool { return len(key) <= 100 && attributePattern.MatchString(key) }

// validCode accepts printable ASCII without quote or backslash: a declared
// value is encoded as is.
func validCode(v string) bool {
	if v == "" || len(v) > 200 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// SpanType declares a span: its name, its kind and its attributes. Declare
// each once, like a metric.
type SpanType struct {
	name  string
	kind  SpanKind
	codes map[string][]string
	ints  []string
	ids   []string
}

// SpanAttributes declares the attributes of a span type: the code
// attributes with the closed list of their values, the integer attributes,
// and the identifier attributes, which are written as pseudonyms. A key
// that is not declared is written "invalid_key".
type SpanAttributes struct {
	Codes []Label
	Ints  []string
	IDs   []string
}

// NewSpanType declares a span type. The name and the attribute keys are
// dotted lowercase words (api.request, agentcapsule.job.kind); it panics on
// an invalid declaration, as Registry does.
func NewSpanType(name string, kind SpanKind, a SpanAttributes) *SpanType {
	if !validAttribute(name) || kind < SpanInternal || kind > SpanConsumer {
		panic("telemetry: invalid span type " + name)
	}
	d := &SpanType{name: name, kind: kind, codes: map[string][]string{}, ints: slices.Clone(a.Ints), ids: slices.Clone(a.IDs)}
	for _, l := range a.Codes {
		if !validAttribute(l.Name) || len(l.Values) == 0 {
			panic("telemetry: invalid span attribute " + l.Name)
		}
		for _, v := range l.Values {
			if !validCode(v) {
				panic("telemetry: invalid value of span attribute " + l.Name)
			}
		}
		d.codes[l.Name] = slices.Clone(l.Values)
	}
	for _, key := range append(slices.Clone(a.Ints), a.IDs...) {
		if !validAttribute(key) {
			panic("telemetry: invalid span attribute " + key)
		}
	}
	return d
}

// Tracer pseudonymizes identifiers and writes finished spans. It is safe for
// concurrent use.
type Tracer struct {
	service string
	key     []byte
	w       io.Writer
	queue   chan *Span
	done    chan struct{}
	mu      sync.RWMutex
	closed  bool
	dropped atomic.Uint64
	counter atomic.Pointer[Counter]
	// file is the trace file NewFileTracer opened, closed by Close.
	file *os.File
}

// ErrTraceKey refuses a pseudonym key shorter than 16 bytes.
var ErrTraceKey = errors.New("telemetry: the trace pseudonym key needs at least 16 bytes")

// NewTracer writes the spans of service (agentcapsule-api,
// agentcapsule-worker) to w, one OTLP/JSON line per batch. key is the
// installation's pseudonym key (controlplane's TraceKey). Close flushes.
func NewTracer(w io.Writer, service string, key []byte) (*Tracer, error) {
	if len(key) < 16 {
		return nil, ErrTraceKey
	}
	if !validAttribute(strings.ReplaceAll(service, "-", "_")) {
		return nil, errors.New("telemetry: invalid service name")
	}
	t := &Tracer{service: service, key: slices.Clone(key), w: w, queue: make(chan *Span, TraceQueue), done: make(chan struct{})}
	go t.write()
	return t, nil
}

// ErrTraceFile refuses a trace file that is not an absolute path to a
// regular file.
var ErrTraceFile = errors.New("telemetry: the trace file must be an absolute path to a regular file")

// OpenTraceFile opens path for appending spans, creating it with mode 0640:
// the collector that reads it may run in the file's group. It never follows
// a symbolic link. Rotate it by copying and truncating (logrotate's
// copytruncate): the tracer keeps appending to the same file.
func OpenTraceFile(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrTraceFile
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o640)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, ErrTraceFile
	}
	return f, nil
}

// NewFileTracer is NewTracer on the trace file at path (OpenTraceFile),
// which Close closes.
func NewFileTracer(path, service string, key []byte) (*Tracer, error) {
	f, err := OpenTraceFile(path)
	if err != nil {
		return nil, err
	}
	t, err := NewTracer(f, service, key)
	if err != nil {
		f.Close()
		return nil, err
	}
	t.file = f
	return t, nil
}

// Count serves the spans the tracer dropped as
// agentcapsule_telemetry_spans_dropped_total: a full queue or a failed write.
func (t *Tracer) Count(r *Registry) {
	c := r.Counter("agentcapsule_telemetry_spans_dropped_total", "Spans dropped: the queue to the trace file was full, or a write failed.")
	c.Add(float64(t.dropped.Load()))
	t.counter.Store(c)
}

// Dropped returns how many spans were dropped.
func (t *Tracer) Dropped() uint64 { return t.dropped.Load() }

func (t *Tracer) drop(n int) {
	t.dropped.Add(uint64(n))
	if c := t.counter.Load(); c != nil {
		c.Add(float64(n))
	}
}

// Close stops accepting spans and waits, at most 5 seconds, for the writer
// to write those queued.
func (t *Tracer) Close() {
	t.mu.Lock()
	if !t.closed {
		t.closed = true
		close(t.queue)
	}
	t.mu.Unlock()
	select {
	case <-t.done:
		if t.file != nil {
			t.file.Close()
		}
	case <-time.After(5 * time.Second):
	}
}

// Pseudonym is the installation's pseudonym of an identifier: the first 64
// bits of HMAC-SHA256(key, id), in hex. The same identifier has the same
// pseudonym in every process and every span; without the key, a pseudonym
// says nothing of the identifier.
func Pseudonym(key []byte, id string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(id))
	return hex.EncodeToString(m.Sum(nil))[:PseudonymLength]
}

func (t *Tracer) write() {
	defer close(t.done)
	batch := make([]*Span, 0, traceBatch)
	var line []byte
	for s := range t.queue {
		batch = append(batch[:0], s)
	fill:
		for len(batch) < traceBatch {
			select {
			case next, ok := <-t.queue:
				if !ok {
					break fill
				}
				batch = append(batch, next)
			default:
				break fill
			}
		}
		line = t.encode(line[:0], batch)
		if _, err := t.w.Write(line); err != nil {
			t.drop(len(batch))
		}
	}
}

// traceContext is what a context carries: the tracer, the trace, and the
// span that new spans are children of (none for a new trace's first span).
type traceContext struct {
	tracer *Tracer
	trace  [16]byte
	parent [8]byte
	span   *Span
}

type traceKey struct{}

func from(ctx context.Context) *traceContext {
	c, _ := ctx.Value(traceKey{}).(*traceContext)
	return c
}

// WithTracer makes the spans started under ctx write to t; the first begins
// a new trace. A nil t leaves ctx as it is.
func WithTracer(ctx context.Context, t *Tracer) context.Context {
	if t == nil {
		return ctx
	}
	return context.WithValue(ctx, traceKey{}, &traceContext{tracer: t})
}

// ContinueTrace makes the spans started under ctx join the trace of the API
// request requestID, as children of that request's span. Without a valid
// request ID (work no API request started), they begin a new trace.
func ContinueTrace(ctx context.Context, t *Tracer, requestID string) context.Context {
	if t == nil {
		return ctx
	}
	c := &traceContext{tracer: t}
	if trace, ok := parseTraceID(requestID); ok {
		c.trace, c.parent = trace, RootSpanID(trace)
	}
	return context.WithValue(ctx, traceKey{}, c)
}

// WithParent makes the spans started under ctx children of parent, in its
// trace, even when parent belongs to another goroutine's work; a nil parent
// leaves ctx as it is.
func WithParent(ctx context.Context, parent *Span) context.Context {
	if parent == nil {
		return ctx
	}
	return context.WithValue(ctx, traceKey{}, &traceContext{tracer: parent.tracer, trace: parent.trace, parent: parent.id, span: parent})
}

func parseTraceID(s string) ([16]byte, bool) {
	var id [16]byte
	if !requestIDPattern.MatchString(s) {
		return id, false
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil || id == [16]byte{} {
		return id, false
	}
	return id, true
}

// RootSpanID is the span ID of the API request whose X-Request-ID is trace:
// derived from it, so that the worker can name that span as the parent of a
// job's span with nothing more than the request ID PostgreSQL keeps.
func RootSpanID(trace [16]byte) [8]byte {
	h := sha256.Sum256(append([]byte("agentcapsule root span\x00"), trace[:]...))
	var id [8]byte
	copy(id[:], h[:8])
	if id == [8]byte{} {
		id[7] = 1
	}
	return id
}

func randomSpanID() [8]byte {
	var id [8]byte
	for id == [8]byte{} {
		v := rand.Uint64()
		for i := range id {
			id[i] = byte(v >> (8 * i))
		}
	}
	return id
}

func randomTraceID() [16]byte {
	var id [16]byte
	for id == [16]byte{} {
		a, b := rand.Uint64(), rand.Uint64()
		for i := range 8 {
			id[i], id[8+i] = byte(a>>(8*i)), byte(b>>(8*i))
		}
	}
	return id
}

// Span is one recorded step. Its methods do nothing on a nil span, so code
// that is traced only sometimes needs no condition.
type Span struct {
	typ    *SpanType
	tracer *Tracer
	trace  [16]byte
	id     [8]byte
	parent [8]byte
	start  time.Time
	mu     sync.Mutex
	end    time.Time
	attrs  []attribute
	failed bool
	ended  bool
}

type attribute struct {
	key   string
	value string // the OTLP AnyValue, encoded
}

// Start begins a span of this type under ctx: a child of ctx's span, or the
// first span of ctx's trace. Without a tracer in ctx it returns ctx and nil.
func (d *SpanType) Start(ctx context.Context) (context.Context, *Span) {
	c := from(ctx)
	if c == nil {
		return ctx, nil
	}
	s := &Span{typ: d, tracer: c.tracer, trace: c.trace, parent: c.parent, id: randomSpanID(), start: time.Now()}
	if s.trace == [16]byte{} {
		s.trace = randomTraceID()
	}
	return context.WithValue(ctx, traceKey{}, &traceContext{tracer: c.tracer, trace: s.trace, parent: s.id, span: s}), s
}

// StartRequest begins the span of the API request requestID, the root of its
// trace: the trace ID is the request ID, the span ID RootSpanID. Without a
// tracer, or with an invalid request ID, it returns ctx and nil.
func (d *SpanType) StartRequest(ctx context.Context, t *Tracer, requestID string) (context.Context, *Span) {
	trace, ok := parseTraceID(requestID)
	if t == nil || !ok {
		return ctx, nil
	}
	s := &Span{typ: d, tracer: t, trace: trace, id: RootSpanID(trace), start: time.Now()}
	return context.WithValue(ctx, traceKey{}, &traceContext{tracer: t, trace: trace, parent: s.id, span: s}), s
}

// SpanFrom returns the span ctx is in, or nil.
func SpanFrom(ctx context.Context) *Span {
	if c := from(ctx); c != nil {
		return c.span
	}
	return nil
}

func (s *Span) set(key, value string, declared bool) {
	if s == nil {
		return
	}
	if !declared {
		key = "invalid_key"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	for i := range s.attrs {
		if s.attrs[i].key == key {
			s.attrs[i].value = value
			return
		}
	}
	if len(s.attrs) < maxAttributes {
		s.attrs = append(s.attrs, attribute{key, value})
	}
}

// Code sets a code attribute: a value of its declared list, or "invalid".
func (s *Span) Code(key, value string) {
	if s == nil {
		return
	}
	values, declared := s.typ.codes[key]
	if !slices.Contains(values, value) {
		value = Invalid
	}
	s.set(key, `{"stringValue":"`+value+`"}`, declared)
}

// Int sets an integer attribute.
func (s *Span) Int(key string, v int64) {
	if s == nil {
		return
	}
	s.set(key, `{"intValue":"`+strconv.FormatInt(v, 10)+`"}`, slices.Contains(s.typ.ints, key))
}

// ID sets the pseudonym of an identifier (Pseudonym); never the identifier.
// An empty identifier sets nothing.
func (s *Span) ID(key, id string) {
	if s == nil || id == "" {
		return
	}
	s.set(key, `{"stringValue":"`+Pseudonym(s.tracer.key, id)+`"}`, slices.Contains(s.typ.ids, key))
}

// Fail marks the span as failed: the OTLP status ERROR, without a message.
func (s *Span) Fail() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.ended {
		s.failed = true
	}
	s.mu.Unlock()
}

// End records the span. A full queue drops it; a second End does nothing.
func (s *Span) End() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended, s.end = true, time.Now()
	s.mu.Unlock()
	t := s.tracer
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		t.drop(1)
		return
	}
	select {
	case t.queue <- s:
	default:
		t.drop(1)
	}
}

// encode appends one ExportTraceServiceRequest, in the OTLP/JSON encoding,
// and a newline.
func (t *Tracer) encode(b []byte, spans []*Span) []byte {
	b = append(b, `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"`...)
	b = append(b, t.service...)
	b = append(b, `"}}]},"scopeSpans":[{"scope":{"name":"agentcapsule"},"spans":[`...)
	for i, s := range spans {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"traceId":"`...)
		b = hex.AppendEncode(b, s.trace[:])
		b = append(b, `","spanId":"`...)
		b = hex.AppendEncode(b, s.id[:])
		if s.parent != [8]byte{} {
			b = append(b, `","parentSpanId":"`...)
			b = hex.AppendEncode(b, s.parent[:])
		}
		b = append(b, `","name":"`...)
		b = append(b, s.typ.name...)
		b = append(b, `","kind":`...)
		b = strconv.AppendInt(b, int64(s.typ.kind), 10)
		b = append(b, `,"startTimeUnixNano":"`...)
		b = strconv.AppendInt(b, s.start.UnixNano(), 10)
		b = append(b, `","endTimeUnixNano":"`...)
		b = strconv.AppendInt(b, s.end.UnixNano(), 10)
		b = append(b, `","attributes":[`...)
		for j, a := range s.attrs {
			if j > 0 {
				b = append(b, ',')
			}
			b = append(b, `{"key":"`...)
			b = append(b, a.key...)
			b = append(b, `","value":`...)
			b = append(b, a.value...)
			b = append(b, '}')
		}
		b = append(b, `],"status":{"code":`...)
		if s.failed {
			b = append(b, '2')
		} else {
			b = append(b, '0')
		}
		b = append(b, "}}"...)
	}
	return append(b, "]}]}]}\n"...)
}
