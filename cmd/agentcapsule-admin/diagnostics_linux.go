//go:build linux

package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

// diagnostics writes an archive of redacted operator data for a support
// request (API-02, ADR 014): versions, the worker's configuration without its
// secrets, the migrations, the queues, the recent failures, the alerts and the
// authorities' replication. It never holds content, a token, a key or
// personal data: the database part is counts only, the configuration keeps
// only numbers, durations and digests, the metrics only the platform's own
// series, and the alerts only their name, state and declared labels.
func diagnostics(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("diagnostics", flag.ContinueOnError)
	output := f.String("output", "", "new archive file (.tar.gz), written with mode 0600")
	workerConfig := f.String("worker-config", "", "the worker's JSON configuration, redacted into the archive")
	workerMetrics := f.String("worker-metrics", "", "the worker's metrics URL, e.g. http://127.0.0.1:9465/metrics")
	apiMetrics := f.String("api-metrics", "", "the API's metrics URL, e.g. http://127.0.0.1:9464/metrics")
	replicaMetrics := f.String("replica-metrics", "", "the authorities' replica metrics URL (standby)")
	prometheus := f.String("prometheus", "", "Prometheus base URL, for the alerts, e.g. http://127.0.0.1:9090")
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *output == "" {
		return fail("configuration_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	files := map[string][]byte{}
	unavailable := map[string]string{}
	add := func(name string, v any) {
		if b, err := json.MarshalIndent(v, "", "  "); err == nil {
			files[name] = append(b, '\n')
		}
	}
	add("versions.json", versions())
	if *workerConfig != "" {
		if cfg, err := redactedConfig(*workerConfig); err != nil {
			unavailable["worker_config"] = "unreadable"
		} else {
			add("worker-config.json", cfg)
		}
	}
	if dsn := os.Getenv("AGENTCAPSULE_DATABASE_URL"); dsn == "" {
		unavailable["database"] = "not_configured"
	} else if s, code := openOperatorStore(ctx, func(string) int { return 1 }); s == nil || code != 0 {
		unavailable["database"] = "unreachable"
	} else {
		d, err := s.Diagnostics(ctx)
		s.Close()
		if err != nil {
			unavailable["database"] = "unreadable"
		} else {
			add("database.json", d)
		}
	}
	for _, m := range []struct{ name, url string }{{"worker", *workerMetrics}, {"api", *apiMetrics}, {"replica", *replicaMetrics}} {
		if m.url == "" {
			continue
		}
		body, err := fetch(ctx, m.url)
		if err != nil {
			unavailable[m.name+"_metrics"] = "unreachable"
			continue
		}
		series := platformSeries(body)
		files["metrics/"+m.name+".prom"] = series
		if m.name != "api" {
			add(m.name+"-authority-replication.json", replication(series))
		}
	}
	if *prometheus != "" {
		if alerts, err := firingAlerts(ctx, *prometheus); err != nil {
			unavailable["alerts"] = "unreachable"
		} else {
			add("alerts.json", alerts)
		}
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	add("manifest.json", struct {
		CreatedAt   time.Time         `json:"created_at"`
		Files       []string          `json:"files"`
		Unavailable map[string]string `json:"unavailable"`
	}{time.Now().UTC(), names, unavailable})
	if err := writeArchive(*output, files); err != nil {
		return fail("diagnostics_output_failed")
	}
	fmt.Fprintln(os.Stdout, "diagnostics_written")
	return 0
}

func versions() map[string]string {
	v := map[string]string{"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH}
	if info, ok := debug.ReadBuildInfo(); ok {
		v["module"] = info.Main.Version
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" || s.Key == "vcs.modified" || s.Key == "vcs.time" {
				v[s.Key] = s.Value
			}
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		v["kernel"] = strings.TrimSpace(string(b))
	}
	return v
}

var (
	digest   = regexp.MustCompile(`^(sha256:)?[0-9a-f]{64}$`)
	duration = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h)([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))*$`)
	// keptStrings are the configuration's string settings that say nothing
	// about a person or a secret: the host's name, durations, the loopback
	// metrics address.
	keptStrings = map[string]bool{"host_id": true, "metrics_listen": true}
)

// redactedConfig keeps the configuration's shape, its numbers and booleans,
// durations, digests and a few named settings. Every other string (paths,
// addresses, names, anything that could hold a secret) becomes "redacted".
func redactedConfig(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v any
	if err = json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	var walk func(key string, v any) any
	walk = func(key string, v any) any {
		switch t := v.(type) {
		case map[string]any:
			out := map[string]any{}
			for k, x := range t {
				out[k] = walk(k, x)
			}
			return out
		case []any:
			out := make([]any, len(t))
			for i, x := range t {
				out[i] = walk(key, x)
			}
			return out
		case string:
			if keptStrings[key] && validLabel(t) || digest.MatchString(t) || duration.MatchString(t) {
				return t
			}
			if t == "" {
				return ""
			}
			return "redacted"
		default:
			return t
		}
	}
	return walk("", v), nil
}

var client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func fetch(ctx context.Context, raw string) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.User != nil {
		return nil, errors.New("invalid URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("unexpected status")
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

var (
	sample    = regexp.MustCompile(`^(agentcapsule_[a-z0-9_]+)(\{([^}]*)\})? (\S+)$`)
	comment   = regexp.MustCompile(`^# (HELP|TYPE) agentcapsule_[a-z0-9_]+ `)
	labelPair = regexp.MustCompile(`^([a-z_]+)="([^"]*)"$`)
)

// validLabel accepts the values the platform's labels declare: short words,
// numbers, and API route patterns. A longer value without a path, the shape
// of a token, is refused.
func validLabel(v string) bool {
	if len(v) > 100 || len(v) > 32 && !strings.HasPrefix(v, "/") {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:/{}-+", c)) {
			return false
		}
	}
	return true
}

// platformSeries keeps the platform's own series (agentcapsule_*), whose
// labels take declared values only, and drops anything else the endpoint
// serves. A sample with an unexpected label value is dropped too.
func platformSeries(body []byte) []byte {
	var out bytes.Buffer
	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 64<<10), 64<<10)
	for scan.Scan() {
		line := scan.Text()
		if comment.MatchString(line) {
			out.WriteString(line + "\n")
			continue
		}
		m := sample.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ok := true
		if m[3] != "" {
			for _, pair := range strings.Split(m[3], ",") {
				p := labelPair.FindStringSubmatch(pair)
				ok = ok && p != nil && validLabel(p[2])
			}
		}
		if ok {
			out.WriteString(line + "\n")
		}
	}
	return out.Bytes()
}

// replication picks the authorities' replication status out of the series.
func replication(series []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(series), "\n") {
		if strings.HasPrefix(line, "agentcapsule_authority_") {
			if name, value, ok := strings.Cut(line, " "); ok {
				out[name] = value
			}
		}
	}
	return out
}

// alertLabels are the labels an alert may carry into the archive: those the
// rules and the metrics declare. Annotations are left out.
var alertLabels = map[string]bool{"alertname": true, "severity": true, "job": true, "kind": true, "reason": true, "outcome": true,
	"repo": true, "store": true, "type": true, "filesystem": true}

type alert struct {
	Labels   map[string]string `json:"labels"`
	State    string            `json:"state"`
	ActiveAt string            `json:"active_at,omitempty"`
}

func firingAlerts(ctx context.Context, base string) ([]alert, error) {
	body, err := fetch(ctx, strings.TrimRight(base, "/")+"/api/v1/alerts")
	if err != nil {
		return nil, err
	}
	var r struct {
		Data struct {
			Alerts []struct {
				Labels   map[string]string `json:"labels"`
				State    string            `json:"state"`
				ActiveAt string            `json:"activeAt"`
			} `json:"alerts"`
		} `json:"data"`
	}
	if err = json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	out := []alert{}
	for _, a := range r.Data.Alerts {
		labels := map[string]string{}
		for k, v := range a.Labels {
			if alertLabels[k] && validLabel(v) {
				labels[k] = v
			}
		}
		state := a.State
		if !validLabel(state) {
			state = "unknown"
		}
		at := a.ActiveAt
		if _, err := time.Parse(time.RFC3339Nano, at); err != nil {
			at = ""
		}
		out = append(out, alert{Labels: labels, State: state, ActiveAt: at})
	}
	return out, nil
}

func writeArchive(path string, files map[string][]byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(file)
	tw := tar.NewWriter(zw)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	now := time.Now().UTC()
	for _, name := range names {
		if err = tw.WriteHeader(&tar.Header{Name: "agentcapsule-diagnostics/" + name, Mode: 0o600, Size: int64(len(files[name])), ModTime: now}); err == nil {
			_, err = tw.Write(files[name])
		}
		if err != nil {
			break
		}
	}
	err = errors.Join(err, tw.Close(), zw.Close(), file.Sync(), file.Close())
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}
