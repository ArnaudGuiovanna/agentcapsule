// Package telemetry gives the platform's processes metrics, in the Prometheus
// text exposition format, and structured event logs (OPS-02). Both are built
// so that they cannot carry content, secrets or tenant data: each label and
// each log code declares the exact list of its values, and anything else is
// written as "other" (metrics) or "invalid" (logs). A filter on characters
// would not do: a token is made of ordinary characters. The other fields are
// numbers, durations and random request IDs. Metrics carry no organization,
// agent or member identifier: operators see technical metrics only, and the
// number of series stays bounded.
package telemetry

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,99}$`)

const (
	// Other replaces a label value outside the label's declared values.
	Other = "other"
	// Invalid replaces a log code outside its key's declared values.
	Invalid = "invalid"
)

// maxSeries bounds the series of one metric; more are dropped and counted.
const maxSeries = 512

// Label declares a label and the closed list of its values.
type Label struct {
	Name   string
	Values []string
}

type kind string

const (
	counter   kind = "counter"
	gauge     kind = "gauge"
	histogram kind = "histogram"
)

type series struct {
	labels  []string
	value   float64   // counter, gauge
	buckets []float64 // histogram: cumulative counts per bound
	sum     float64
	count   float64
}

type family struct {
	mu      sync.Mutex
	name    string
	help    string
	kind    kind
	labels  []Label
	names   []string
	bounds  []float64
	series  map[string]*series
	dropped *Counter
}

func (f *family) get(values []string) *series {
	clean := make([]string, len(f.labels))
	for i, l := range f.labels {
		clean[i] = Other
		if len(values) == len(f.labels) && slices.Contains(l.Values, values[i]) {
			clean[i] = values[i]
		}
	}
	key := strings.Join(clean, "\x00")
	if s := f.series[key]; s != nil {
		return s
	}
	if len(f.series) >= maxSeries {
		return nil
	}
	s := &series{labels: clean}
	if f.kind == histogram {
		s.buckets = make([]float64, len(f.bounds))
	}
	f.series[key] = s
	return s
}

// Registry holds a process's metrics. It is safe for concurrent use.
type Registry struct {
	mu         sync.Mutex
	families   map[string]*family
	collectors []func(context.Context) error
	dropped    *Counter
	collectErr *Counter
}

// NewRegistry returns a registry with its own bookkeeping metrics.
func NewRegistry() *Registry {
	r := &Registry{families: map[string]*family{}}
	r.dropped = r.Counter("agentcapsule_telemetry_series_dropped_total", "Samples dropped because a metric reached its series limit.")
	r.collectErr = r.Counter("agentcapsule_telemetry_collect_errors_total", "Scrapes whose collection of current values failed.")
	return r
}

func (r *Registry) register(name, help string, k kind, bounds []float64, labels []Label) *family {
	if !namePattern.MatchString(name) {
		panic("telemetry: invalid metric name " + name)
	}
	names := make([]string, len(labels))
	for i, l := range labels {
		if !namePattern.MatchString(l.Name) || l.Name == "le" || len(l.Values) == 0 {
			panic("telemetry: invalid label " + l.Name)
		}
		for _, v := range l.Values {
			if v == "" || strings.ContainsAny(v, "\"\n\\") {
				panic("telemetry: invalid value of label " + l.Name)
			}
		}
		names[i] = l.Name
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.families[name]; ok {
		panic("telemetry: metric registered twice: " + name)
	}
	f := &family{name: name, help: help, kind: k, labels: labels, names: names, bounds: bounds, series: map[string]*series{}, dropped: r.dropped}
	r.families[name] = f
	return f
}

// Counter is a monotonically increasing value, per label set.
type Counter struct{ f *family }

// Counter registers a counter. Names and labels follow Prometheus rules.
func (r *Registry) Counter(name, help string, labels ...Label) *Counter {
	return &Counter{r.register(name, help, counter, nil, labels)}
}

// Add adds n (non-negative) to the series of the given label values.
func (c *Counter) Add(n float64, values ...string) {
	if n < 0 || math.IsNaN(n) {
		return
	}
	c.f.mu.Lock()
	s := c.f.get(values)
	if s != nil {
		s.value += n
	}
	c.f.mu.Unlock()
	if s == nil && c.f.dropped != nil {
		c.f.dropped.Inc()
	}
}

// Inc adds one.
func (c *Counter) Inc(values ...string) { c.Add(1, values...) }

// Gauge is a value that goes up and down, per label set.
type Gauge struct{ f *family }

// Gauge registers a gauge.
func (r *Registry) Gauge(name, help string, labels ...Label) *Gauge {
	return &Gauge{r.register(name, help, gauge, nil, labels)}
}

// Set sets the series of the given label values.
func (g *Gauge) Set(v float64, values ...string) {
	if math.IsNaN(v) {
		return
	}
	g.f.mu.Lock()
	s := g.f.get(values)
	if s != nil {
		s.value = v
	}
	g.f.mu.Unlock()
	if s == nil && g.f.dropped != nil {
		g.f.dropped.Inc()
	}
}

// Reset forgets every series, before a collection sets the current ones.
func (g *Gauge) Reset() {
	g.f.mu.Lock()
	g.f.series = map[string]*series{}
	g.f.mu.Unlock()
}

// Histogram counts observations in fixed buckets, per label set.
type Histogram struct{ f *family }

// Histogram registers a histogram with increasing upper bounds (+Inf is added).
func (r *Registry) Histogram(name, help string, bounds []float64, labels ...Label) *Histogram {
	if len(bounds) == 0 || !sort.Float64sAreSorted(bounds) {
		panic("telemetry: histogram bounds must be increasing")
	}
	return &Histogram{r.register(name, help, histogram, slices.Clone(bounds), labels)}
}

// Observe records v in the series of the given label values.
func (h *Histogram) Observe(v float64, values ...string) {
	if math.IsNaN(v) {
		return
	}
	h.f.mu.Lock()
	s := h.f.get(values)
	if s != nil {
		for i, b := range h.f.bounds {
			if v <= b {
				s.buckets[i]++
			}
		}
		s.sum += v
		s.count++
	}
	h.f.mu.Unlock()
	if s == nil && h.f.dropped != nil {
		h.f.dropped.Inc()
	}
}

// Since observes the seconds elapsed since start.
func (h *Histogram) Since(start time.Time, values ...string) {
	h.Observe(time.Since(start).Seconds(), values...)
}

// Collect adds a function run at each scrape, before the exposition, to set
// gauges from current state (queue depth, disk usage). It gets a bounded
// context; a failure is counted and the previous values are kept.
func (r *Registry) Collect(fn func(context.Context) error) {
	r.mu.Lock()
	r.collectors = append(r.collectors, fn)
	r.mu.Unlock()
}

func format(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func labelText(names, values []string, extra ...string) string {
	if len(names) == 0 && len(extra) == 0 {
		return ""
	}
	parts := make([]string, 0, len(names)+1)
	for i, n := range names {
		parts = append(parts, n+`="`+values[i]+`"`)
	}
	parts = append(parts, extra...)
	return "{" + strings.Join(parts, ",") + "}"
}

// WriteTo writes every metric in the Prometheus text exposition format 0.0.4,
// sorted by name and label values.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	names := make([]string, 0, len(r.families))
	for n := range r.families {
		names = append(names, n)
	}
	r.mu.Unlock()
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		r.mu.Lock()
		f := r.families[n]
		r.mu.Unlock()
		f.mu.Lock()
		keys := make([]string, 0, len(f.series))
		for k := range f.series {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", f.name, strings.ReplaceAll(f.help, "\n", " "), f.name, f.kind)
		for _, k := range keys {
			s := f.series[k]
			if f.kind != histogram {
				fmt.Fprintf(&b, "%s%s %s\n", f.name, labelText(f.names, s.labels), format(s.value))
				continue
			}
			for i, bound := range f.bounds {
				fmt.Fprintf(&b, "%s_bucket%s %s\n", f.name, labelText(f.names, s.labels, `le="`+format(bound)+`"`), format(s.buckets[i]))
			}
			fmt.Fprintf(&b, "%s_bucket%s %s\n", f.name, labelText(f.names, s.labels, `le="+Inf"`), format(s.count))
			fmt.Fprintf(&b, "%s_sum%s %s\n", f.name, labelText(f.names, s.labels), format(s.sum))
			fmt.Fprintf(&b, "%s_count%s %s\n", f.name, labelText(f.names, s.labels), format(s.count))
		}
		f.mu.Unlock()
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// Handler serves GET /metrics. Collections run first, bounded by timeout.
func (r *Registry) Handler(timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/metrics" {
			http.NotFound(w, req)
			return
		}
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.mu.Lock()
		collectors := slices.Clone(r.collectors)
		r.mu.Unlock()
		for _, fn := range collectors {
			ctx, cancel := context.WithTimeout(req.Context(), timeout)
			if err := fn(ctx); err != nil {
				r.collectErr.Inc()
			}
			cancel()
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = r.WriteTo(w)
	})
}

// Field is one field of a log event: a code from its key's declared values,
// an integer, a duration or a request ID. There is no free-text field.
type Field struct {
	key   string
	value string // already JSON-encoded, except for a code
	code  bool
}

func field(key, encoded string) Field {
	if !namePattern.MatchString(key) || key == "time" || key == "event" {
		key = "invalid_key"
	}
	return Field{key: key, value: encoded}
}

// Code is a value of the logger's vocabulary for key (an outcome, a kind, a
// route); any other value is written "invalid".
func Code(key, value string) Field {
	f := field(key, value)
	f.code = true
	return f
}

// Int is an integer.
func Int(key string, v int64) Field { return field(key, strconv.FormatInt(v, 10)) }

// Seconds is a duration, in seconds.
func Seconds(key string, d time.Duration) Field {
	return field(key, strconv.FormatFloat(d.Seconds(), 'f', 6, 64))
}

var requestIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// RequestID is the random ID an API response carries in X-Request-ID; it
// correlates a person's report with the log line of their request.
func RequestID(v string) Field {
	if !requestIDPattern.MatchString(v) {
		v = Invalid
	}
	return field("request_id", strconv.Quote(v))
}

// Logger writes one JSON object per line: time, event, then the fields in
// order. It is safe for concurrent use; a write error is dropped.
type Logger struct {
	mu    sync.Mutex
	w     io.Writer
	now   func() time.Time
	vocab map[string][]string
}

// NewLogger writes events to w. vocabulary lists, per code key, the values a
// Code field may take, and under "event" the names of the events.
func NewLogger(w io.Writer, vocabulary map[string][]string) *Logger {
	return &Logger{w: w, now: time.Now, vocab: vocabulary}
}

// Event writes the event; a name the vocabulary does not list is "invalid".
func (l *Logger) Event(name string, fields ...Field) {
	if l == nil {
		return
	}
	if !slices.Contains(l.vocab["event"], name) || !namePattern.MatchString(name) {
		name = Invalid
	}
	var b strings.Builder
	b.WriteString(`{"time":`)
	b.WriteString(strconv.Quote(l.now().UTC().Format(time.RFC3339Nano)))
	b.WriteString(`,"event":`)
	b.WriteString(strconv.Quote(name))
	for _, f := range fields {
		value := f.value
		if f.code {
			value = strconv.Quote(Invalid)
			if slices.Contains(l.vocab[f.key], f.value) && !strings.ContainsAny(f.value, "\"\n\\") {
				value = strconv.Quote(f.value)
			}
		}
		b.WriteString(`,"` + f.key + `":` + value)
	}
	b.WriteString("}\n")
	l.mu.Lock()
	_, _ = io.WriteString(l.w, b.String())
	l.mu.Unlock()
}

type requestIDKey struct{}

// WithRequestID carries an API request's ID with its context, so that what
// the request starts (operations, then the worker's jobs) can be correlated
// with it. An ID that is not 32 lowercase hex digits is not carried.
func WithRequestID(ctx context.Context, id string) context.Context {
	if !requestIDPattern.MatchString(id) {
		return ctx
	}
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFrom returns the request ID the context carries, or "".
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}
