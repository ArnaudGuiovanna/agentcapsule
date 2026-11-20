package worker

import (
	"fmt"
	"maps"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Both series are host observations. The device includes every user of the
// filesystem's block device. PSI totals cover all tasks visible to the kernel.
type deploymentIOSample struct {
	At       time.Time
	Device   string
	Block    map[string]uint64
	Pressure map[string]uint64
}

func readDeploymentIO(volumeDir string) deploymentIOSample {
	s := deploymentIOSample{At: time.Now()}
	var stat unix.Stat_t
	if unix.Stat(volumeDir, &stat) == nil {
		s.Device = fmt.Sprintf("%d:%d", unix.Major(uint64(stat.Dev)), unix.Minor(uint64(stat.Dev)))
		data, err := os.ReadFile("/sys/dev/block/" + s.Device + "/stat")
		// Linux block-stat sectors are always 512 bytes, including on 4K drives.
		fields := strings.Fields(string(data))
		if err == nil && len(fields) >= 11 {
			counters := map[string]uint64{}
			for _, f := range []struct {
				name string
				pos  int
				unit uint64
			}{
				{"reads_completed", 0, 1}, {"read_bytes", 2, 512}, {"read_ms", 3, 1},
				{"writes_completed", 4, 1}, {"written_bytes", 6, 512}, {"write_ms", 7, 1},
				{"io_busy_ms", 9, 1}, {"weighted_io_ms", 10, 1},
			} {
				v, err := strconv.ParseUint(fields[f.pos], 10, 64)
				if err != nil {
					counters = nil
					break
				}
				counters[f.name] = v * f.unit
			}
			s.Block = counters
		}
	}
	data, err := os.ReadFile("/proc/pressure/io")
	if err == nil {
		s.Pressure = make(map[string]uint64)
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || (fields[0] != "some" && fields[0] != "full") {
				continue
			}
			for _, value := range fields[1:] {
				if total, ok := strings.CutPrefix(value, "total="); ok {
					if us, err := strconv.ParseUint(total, 10, 64); err == nil {
						s.Pressure[fields[0]+"_us"] = us
					}
				}
			}
		}
	}
	return s
}

// Omit a delta if either sample is unavailable or the counter reset.
func deploymentIODeltas(before, after map[string]uint64) map[string]uint64 {
	delta := make(map[string]uint64)
	for name, value := range after {
		if previous, ok := before[name]; ok && value >= previous {
			delta[name] = value - previous
		}
	}
	return delta
}

func logDeploymentIO(t *testing.T, batch int, start, end deploymentIOSample) {
	t.Helper()
	for _, point := range []struct {
		name   string
		sample deploymentIOSample
	}{{"start", start}, {"end", end}} {
		s := point.sample
		t.Logf("batch_io_sample batch=%d boundary=%s time_utc=%s volume_fs_device=%q all_device_traffic=%v host_io_pressure=%v",
			batch, point.name, s.At.UTC().Format(time.RFC3339Nano), s.Device, s.Block, s.Pressure)
	}
	var block map[string]uint64
	if start.Device != "" && start.Device == end.Device {
		block = deploymentIODeltas(start.Block, end.Block)
	}
	t.Logf("batch_io batch=%d start_utc=%s end_utc=%s elapsed_s=%.6f volume_fs_device_start=%q volume_fs_device_end=%q all_device_traffic_delta=%v host_io_pressure_delta=%v",
		batch, start.At.UTC().Format(time.RFC3339Nano), end.At.UTC().Format(time.RFC3339Nano),
		end.At.Sub(start.At).Seconds(), start.Device, end.Device, block, deploymentIODeltas(start.Pressure, end.Pressure))
}

func TestDeploymentIOCounters(t *testing.T) {
	dir := t.TempDir()
	before := readDeploymentIO(dir)
	f, err := os.CreateTemp(dir, "sample")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(make([]byte, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	after := readDeploymentIO(dir)
	logDeploymentIO(t, 0, before, after)
	if before.Device == "" || before.Device != after.Device {
		t.Fatal("test directory changed device")
	}
	if len(before.Block) != 0 && len(deploymentIODeltas(before.Block, after.Block)) != len(before.Block) {
		t.Fatal("device counters disappeared or reset")
	}
	if len(before.Pressure) != 0 && len(deploymentIODeltas(before.Pressure, after.Pressure)) != len(before.Pressure) {
		t.Fatal("host pressure counters disappeared or reset")
	}
}

func TestDeploymentIODeltasIgnoreMissingAndResetCounters(t *testing.T) {
	before := map[string]uint64{"read_bytes": 512, "written_bytes": 2048, "some_us": 17, "full_us": 3}
	after := map[string]uint64{"read_bytes": 1536, "written_bytes": 128, "some_us": 17, "busy_ms": 42}
	want := map[string]uint64{"read_bytes": 1024, "some_us": 0}
	if got := deploymentIODeltas(before, after); !maps.Equal(got, want) {
		t.Fatalf("deltas %v, want %v", got, want)
	}
}
