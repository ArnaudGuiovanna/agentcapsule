//go:build linux

package worker

// The capacity benchmark's measurements (DEP-5, OPS-03). The benchmark itself
// boots real VMs (TestCapacityBenchmark, KVM); what it reads of the host and
// how it summarizes are here, tested without KVM.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// capacitySchema names the report's format; scripts/verify-product-guest.py
// checks it.
const capacitySchema = "agentcapsule-capacity-benchmark/1"

// capacitySizes parses AGENTCAPSULE_KVM_CAPACITY_AGENTS: the numbers of
// agents to boot, in increasing order, 1 to 64 each; "1,5,10,20" when empty.
func capacitySizes(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		s = "1,5,10,20"
	}
	var sizes []int
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 1 || n > 64 {
			return nil, fmt.Errorf("agents %q: a number from 1 to 64", part)
		}
		sizes = append(sizes, n)
	}
	slices.Sort(sizes)
	return slices.Compact(sizes), nil
}

// summary describes a set of durations or sizes.
type summary struct {
	Count int     `json:"count"`
	Min   float64 `json:"min"`
	P50   float64 `json:"p50"`
	P90   float64 `json:"p90"`
	Max   float64 `json:"max"`
	Mean  float64 `json:"mean"`
	Sum   float64 `json:"sum"`
}

func round(v float64) float64 { return math.Round(v*1000) / 1000 }

// summarize gives the nearest-rank percentiles of values; none for none.
func summarize(values []float64) *summary {
	if len(values) == 0 {
		return nil
	}
	v := slices.Clone(values)
	slices.Sort(v)
	rank := func(p float64) float64 { return v[max(int(math.Ceil(p*float64(len(v))))-1, 0)] }
	s := &summary{Count: len(v), Min: round(v[0]), P50: round(rank(0.5)), P90: round(rank(0.9)), Max: round(v[len(v)-1])}
	for _, x := range v {
		s.Sum += x
	}
	s.Mean, s.Sum = round(s.Sum/float64(len(v))), round(s.Sum)
	return s
}

// memInfo reads MemTotal and MemAvailable, in MiB, from /proc/meminfo.
func memInfo(r io.Reader) (total, available float64, err error) {
	fields := map[string]float64{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 2 {
			if v, err := strconv.ParseFloat(parts[1], 64); err == nil {
				fields[strings.TrimSuffix(parts[0], ":")] = v / 1024
			}
		}
	}
	total, ok1 := fields["MemTotal"]
	available, ok2 := fields["MemAvailable"]
	if !ok1 || !ok2 || scanner.Err() != nil {
		return 0, 0, errors.New("meminfo without MemTotal or MemAvailable")
	}
	return total, available, nil
}

// cpuTimes reads the host's idle and total CPU ticks from /proc/stat.
func cpuTimes(r io.Reader) (idle, total uint64, err error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	parts := strings.Fields(line)
	if (err != nil && err != io.EOF) || len(parts) < 5 || parts[0] != "cpu" {
		return 0, 0, errors.New("stat without its cpu line")
	}
	for i, p := range parts[1:] {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return 0, 0, err
		}
		total += v
		if i == 3 || i == 4 { // idle, iowait
			idle += v
		}
	}
	return idle, total, nil
}

// processRSS reads VmRSS, in MiB, from /proc/<pid>/status.
func processRSS(r io.Reader) (float64, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if parts := strings.Fields(scanner.Text()); len(parts) == 3 && parts[0] == "VmRSS:" && parts[2] == "kB" {
			v, err := strconv.ParseFloat(parts[1], 64)
			return v / 1024, err
		}
	}
	return 0, errors.New("status without VmRSS")
}

// processCPU reads utime+stime, in clock ticks, from /proc/<pid>/stat. The
// command name, in parentheses, may hold spaces.
func processCPU(stat string) (uint64, error) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, errors.New("stat without a command")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 13 {
		return 0, errors.New("stat too short")
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	return utime + stime, errors.Join(err1, err2)
}

// cgroupPath reads a process's cgroup v2 path from /proc/<pid>/cgroup.
func cgroupPath(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if path, ok := strings.CutPrefix(scanner.Text(), "0::"); ok {
			return path, nil
		}
	}
	return "", errors.New("no cgroup v2 path")
}

// capacityHeadroomMiB is kept free beside the VMs' memory: a step whose VMs
// could exhaust the host is recorded as not run rather than started.
const capacityHeadroomMiB = 1024

// enoughMemory reports whether n VMs of memoryMiB each fit in available
// MiB with the headroom, as if each touched all its memory.
func enoughMemory(available float64, n, memoryMiB int) bool {
	return available >= float64(n*memoryMiB+capacityHeadroomMiB)
}

// bootSeconds returns the durations of the successful boots for work that
// the worker's trace recorded (worker.boot spans, OTLP/JSON lines) and that
// started within [from, to]; a zero time leaves that side open.
func bootSeconds(raw []byte, from, to time.Time) ([]float64, error) {
	var out []float64
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(nil, 16<<20)
	for scanner.Scan() {
		var line struct {
			ResourceSpans []struct {
				ScopeSpans []struct {
					Spans []struct {
						Name       string `json:"name"`
						Start      string `json:"startTimeUnixNano"`
						End        string `json:"endTimeUnixNano"`
						Attributes []struct {
							Key   string `json:"key"`
							Value struct {
								StringValue string `json:"stringValue"`
							} `json:"value"`
						} `json:"attributes"`
					} `json:"spans"`
				} `json:"scopeSpans"`
			} `json:"resourceSpans"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			return nil, err
		}
		for _, r := range line.ResourceSpans {
			for _, scope := range r.ScopeSpans {
				for _, s := range scope.Spans {
					attrs := map[string]string{}
					for _, a := range s.Attributes {
						attrs[a.Key] = a.Value.StringValue
					}
					if s.Name != "worker.boot" || attrs["agentcapsule.outcome"] != "started" || attrs["agentcapsule.boot.purpose"] != "work" {
						continue
					}
					start, err1 := strconv.ParseInt(s.Start, 10, 64)
					end, err2 := strconv.ParseInt(s.End, 10, 64)
					if err := errors.Join(err1, err2); err != nil {
						return nil, err
					}
					began := time.Unix(0, start)
					if (!from.IsZero() && began.Before(from)) || (!to.IsZero() && began.After(to)) {
						continue
					}
					out = append(out, time.Duration(end-start).Seconds())
				}
			}
		}
	}
	return out, scanner.Err()
}

// capacityReport is the benchmark's JSON report.
type capacityReport struct {
	Schema   string         `json:"schema"`
	Started  time.Time      `json:"started_at"`
	Finished *time.Time     `json:"finished_at,omitempty"`
	Host     capacityHost   `json:"host"`
	Config   capacityConfig `json:"config"`
	Steps    []capacityStep `json:"steps"`
}

type capacityHost struct {
	CPUs        int     `json:"cpus"`
	MemTotalMiB float64 `json:"mem_total_mib"`
	Kernel      string  `json:"kernel"`
}

type capacityConfig struct {
	Sizes         []int  `json:"agents"`
	VCPUs         int    `json:"vcpus_per_vm"`
	MemoryMiB     int    `json:"memory_mib_per_vm"`
	DataVolumeMiB int    `json:"data_volume_mib_per_vm"`
	Harness       string `json:"harness"`
	IdleWindow    string `json:"idle_window"`
}

// capacityStep is the measurement of one number of agents. Seconds and MiB.
type capacityStep struct {
	Agents int    `json:"agents"`
	Status string `json:"status"` // measured, not_run
	Reason string `json:"reason,omitempty"`
	// Provision is the creation of the agents this step added, each until
	// its first boot (volume encryption included).
	Provision *summary `json:"provision_seconds,omitempty"`
	// Boot is the duration of each VM's boot, from the worker's spans;
	// WakeToRunning, from each wake request to its operation's success,
	// all requested at once; AllRunning, until the last.
	Boot          *summary `json:"boot_seconds,omitempty"`
	WakeToRunning *summary `json:"wake_to_running_seconds,omitempty"`
	AllRunning    float64  `json:"all_running_seconds,omitempty"`
	// VMMRSS is each running VMM's resident memory; CgroupMemory, each
	// VM's cgroup charge (the VMM and its page cache).
	VMMRSS       *summary `json:"vmm_rss_mib,omitempty"`
	CgroupMemory *summary `json:"vm_cgroup_memory_mib,omitempty"`
	// The host, with every agent asleep, then with the step's VMs
	// running and idle after their first answer.
	HostAvailableAsleepMiB  float64 `json:"host_available_asleep_mib,omitempty"`
	HostAvailableRunningMiB float64 `json:"host_available_running_mib,omitempty"`
	HostUsedByVMsMiB        float64 `json:"host_used_by_vms_mib,omitempty"`
	// Over the idle window: the host's busy share of all CPUs, and the
	// VMMs' CPU time per second.
	HostCPUBusyRatio *float64 `json:"host_cpu_busy_ratio_idle,omitempty"`
	VMMCPUPerSecond  *float64 `json:"vmm_cpu_seconds_per_second_idle,omitempty"`
	// FirstAnswer: from each invocation, all sent at once to the freshly
	// booted VMs, to its answer. WakeFromStopped: from an invocation to a
	// stopped agent, one at a time, to its answer.
	FirstAnswer     *summary `json:"first_answer_seconds,omitempty"`
	WakeFromStopped *summary `json:"wake_from_stopped_answer_seconds,omitempty"`
}

// hostSample reads the host's memory and CPU counters.
type hostSample struct {
	available     float64
	idle, total   uint64
	at            time.Time
	totalMemoryMB float64
}

func readHostSample() (hostSample, error) {
	mem, err := os.Open("/proc/meminfo")
	if err != nil {
		return hostSample{}, err
	}
	defer mem.Close()
	total, available, err := memInfo(mem)
	if err != nil {
		return hostSample{}, err
	}
	stat, err := os.Open("/proc/stat")
	if err != nil {
		return hostSample{}, err
	}
	defer stat.Close()
	idle, all, err := cpuTimes(stat)
	return hostSample{available: available, idle: idle, total: all, at: time.Now(), totalMemoryMB: total}, err
}

// writeCapacityReport replaces the report at path, so that a step that
// fails leaves the earlier steps' numbers.
func writeCapacityReport(path string, r capacityReport) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// The host readings parse what Linux writes, and the summaries are
// nearest-rank percentiles.
func TestCapacityMeasurementsReadTheHost(t *testing.T) {
	if sizes, err := capacitySizes(""); err != nil || !slices.Equal(sizes, []int{1, 5, 10, 20}) {
		t.Fatal(sizes, err)
	}
	if sizes, err := capacitySizes("10, 1,10"); err != nil || !slices.Equal(sizes, []int{1, 10}) {
		t.Fatal(sizes, err)
	}
	for _, bad := range []string{"0", "65", "1,x", "-3"} {
		if _, err := capacitySizes(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	s := summarize([]float64{4, 1, 3, 2, 10})
	if s.Count != 5 || s.Min != 1 || s.P50 != 3 || s.P90 != 10 || s.Max != 10 || s.Mean != 4 || s.Sum != 20 || summarize(nil) != nil {
		t.Fatal(s)
	}
	total, available, err := memInfo(strings.NewReader("MemTotal:       16303428 kB\nMemFree:  100 kB\nMemAvailable:   12582912 kB\n"))
	if err != nil || math.Abs(total-15921.316) > 0.01 || available != 12288 {
		t.Fatal(total, available, err)
	}
	if _, _, err = memInfo(strings.NewReader("MemTotal: 1 kB\n")); err == nil {
		t.Fatal("MemAvailable is required")
	}
	idle, all, err := cpuTimes(strings.NewReader("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n"))
	if err != nil || idle != 850 || all != 1000 {
		t.Fatal(idle, all, err)
	}
	rss, err := processRSS(strings.NewReader("Name:\tfirecracker\nVmRSS:\t   65536 kB\n"))
	if err != nil || rss != 64 {
		t.Fatal(rss, err)
	}
	ticks, err := processCPU("4242 (fire cracker) S 1 4242 4242 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 3 0 99 0 0")
	if err != nil || ticks != 300 {
		t.Fatal(ticks, err)
	}
	path, err := cgroupPath(strings.NewReader("0::/acp-runtime-0123/vm-1\n"))
	if err != nil || path != "/acp-runtime-0123/vm-1" {
		t.Fatal(path, err)
	}
	if !enoughMemory(1024+20*256, 20, 256) || enoughMemory(1024+20*256-1, 20, 256) {
		t.Fatal("memory guard")
	}
	// The host this test runs on can be read as the benchmark reads it.
	if h, err := readHostSample(); err != nil || h.available <= 0 || h.total == 0 || h.totalMemoryMB < h.available {
		t.Fatal(h, err)
	}
	if rss, err := os.Open("/proc/self/status"); err == nil {
		v, err := processRSS(rss)
		rss.Close()
		if err != nil || v <= 0 {
			t.Fatal("own RSS", v, err)
		}
	}
}

// The boot durations come from the worker's own spans: successful boots for
// work only, not fences or failures.
func TestBootSecondsComeFromTheWorkersSpans(t *testing.T) {
	var file traceFile
	tracer, err := telemetry.NewTracer(&file, "agentcapsule-worker", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := telemetry.WithTracer(context.Background(), tracer)
	for _, c := range []struct {
		fence bool
		err   error
	}{{false, nil}, {true, nil}, {false, errors.New("boot failed")}, {false, nil}} {
		_, span := bootSpan.Start(ctx)
		time.Sleep(2 * time.Millisecond)
		endBoot(span, c.fence, c.err)
	}
	tracer.Close()
	seconds, err := bootSeconds(file.b.Bytes(), time.Time{}, time.Time{})
	if err != nil || len(seconds) != 2 || seconds[0] < 0.002 || seconds[1] < 0.002 {
		t.Fatal(seconds, err)
	}
	if later, err := bootSeconds(file.b.Bytes(), time.Now(), time.Time{}); err != nil || len(later) != 0 {
		t.Fatal("boots before the window are left out", later, err)
	}
	dir := t.TempDir()
	report := capacityReport{Schema: capacitySchema, Steps: []capacityStep{{Agents: 1, Status: "measured", Boot: summarize(seconds)}}}
	if err = writeCapacityReport(dir+"/capacity.json", report); err != nil {
		t.Fatal(err)
	}
	var back capacityReport
	if raw, err := os.ReadFile(dir + "/capacity.json"); err != nil || json.Unmarshal(raw, &back) != nil || back.Steps[0].Boot.Count != 2 {
		t.Fatal("report", err)
	}
}
