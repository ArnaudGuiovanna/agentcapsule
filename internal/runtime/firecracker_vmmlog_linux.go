//go:build linux

package runtime

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// The VMM's standard output and error, and the guest's serial console when
// the operator enables it for debugging, go to <root>/logs/<run>.log (S-20).
// The file is opened for appending, so the host can cut it without the VMM:
// the host's monitor empties it once it passes VMMLogCap, at most one
// monitorPeriod late. It goes with its run's cleanup, and the census removes
// a log whose run is gone; a debugging host keeps the newest debugLogsKept
// of those, and -collect-garbage removes them. A pipe would bound it exactly,
// but a VMM must outlive the worker process, which would close the pipe's
// reading end.

// VMMLogCap bounds each VMM's log, give or take one monitorPeriod of output.
var VMMLogCap int64 = 1 << 20

// monitorPeriod is how often the host's monitor bounds the logs and ends
// the platform listeners of boots another worker process retired.
var monitorPeriod = time.Second

func (h *FirecrackerHost) logPath(vmID string) string {
	return filepath.Join(h.root, "logs", vmID+".log")
}

func (h *FirecrackerHost) openLog(vmID string) (*os.File, error) {
	return os.OpenFile(h.logPath(vmID), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
}

const logCut = "agentcapsule: earlier VMM output dropped at the log's size limit\n"

// boundLog empties the log of vmID once it passes VMMLogCap. The VMM appends,
// so its next write lands after the note this leaves.
func (h *FirecrackerHost) boundLog(vmID string) error {
	f, err := os.OpenFile(h.logPath(vmID), os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() <= VMMLogCap {
		return err
	}
	if err = f.Truncate(0); err != nil {
		return err
	}
	_, err = f.WriteAt([]byte(logCut), 0)
	return err
}

// validRunID: a run's ID, 16 lowercase hex digits.
func validRunID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 8 && strings.ToLower(id) == id
}

// listLogs names the VMM logs present now: a census lists them before it
// reads the registry, so that a log created after that read, by a boot that
// recorded its run first, is never taken for a stale one.
func (h *FirecrackerHost) listLogs() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(h.root, "logs"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if id, ok := strings.CutSuffix(e.Name(), ".log"); ok && validRunID(id) && e.Type().IsRegular() {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// debugLogsKept is how many logs of ended runs a debugging host keeps.
const debugLogsKept = 16

// removeStaleLogs removes the logs listed whose run is in no agent's record;
// a debugging host (SerialConsole) keeps the newest debugLogsKept of them.
func (h *FirecrackerHost) removeStaleLogs(ctx context.Context, listed []string) error {
	if h.opts.SerialConsole {
		listed = olderLogs(h, listed, debugLogsKept)
	}
	_, err := h.staleLogs(ctx, listed, false)
	return err
}

// olderLogs drops the keep newest of the logs listed.
func olderLogs(h *FirecrackerHost, listed []string, keep int) []string {
	type stamped struct {
		id string
		at time.Time
	}
	logs := make([]stamped, 0, len(listed))
	for _, id := range listed {
		if st, err := os.Lstat(h.logPath(id)); err == nil {
			logs = append(logs, stamped{id, st.ModTime()})
		}
	}
	slices.SortFunc(logs, func(a, b stamped) int { return b.at.Compare(a.at) })
	var older []string
	for i, l := range logs {
		if i >= keep {
			older = append(older, l.id)
		}
	}
	return older
}

// staleLogs counts, and unless dryRun removes, the logs listed whose run is
// in no agent's record.
func (h *FirecrackerHost) staleLogs(ctx context.Context, listed []string, dryRun bool) (int, error) {
	if len(listed) == 0 {
		return 0, nil
	}
	live := map[string]bool{}
	if err := h.locked(ctx, func(r *hostRegistry) error {
		for _, a := range r.Agents {
			if a.Run != nil {
				live[a.Run.ID] = true
			}
		}
		return nil
	}); err != nil {
		return 0, err
	}
	stale := 0
	var failures []error
	for _, id := range listed {
		if live[id] {
			continue
		}
		stale++
		if dryRun {
			continue
		}
		if err := os.Remove(h.logPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	return stale, errors.Join(failures...)
}

// CollectStaleLogsAt counts, and unless dryRun removes, for a command that
// runs beside the worker (agentcapsule-worker -collect-garbage), the VMM logs
// of runtime root root whose run is gone. A root without a registry has none.
func CollectStaleLogsAt(ctx context.Context, root string, dryRun bool) (int, error) {
	h, err := registeredHost(root)
	if h == nil || err != nil {
		return 0, err
	}
	listed, err := h.listLogs()
	if err != nil {
		return 0, err
	}
	return h.staleLogs(ctx, listed, dryRun)
}

// hostMonitor is one goroutine per host driver, replacing a ticker per VM
// that took host.lock five times a second (P-09). It reads the registry
// without host.lock: unchanged, that is one stat.
type hostMonitor struct {
	stop chan struct{}
	done chan struct{}
}

// watch starts the monitor if it does not run. It stops once this process
// has no platform listener and the registry no run, and at Close.
func (h *FirecrackerHost) watch() {
	h.platformMu.Lock()
	defer h.platformMu.Unlock()
	if h.monitor != nil || h.platformClosed {
		return
	}
	m := &hostMonitor{stop: make(chan struct{}), done: make(chan struct{})}
	h.monitor = m
	go func() {
		defer close(m.done)
		t := time.NewTicker(monitorPeriod)
		defer t.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-t.C:
			}
			if !h.monitorPass(m) {
				return
			}
		}
	}()
}

// monitorPass ends the listeners of boots that are gone and bounds the logs.
// It returns false once there is nothing left to watch, having removed m.
func (h *FirecrackerHost) monitorPass(m *hostMonitor) bool {
	r, err := h.view()
	runs := map[string]bool{}
	if err == nil {
		for _, a := range r.Agents {
			if a.Run != nil {
				if !a.Fenced {
					runs[a.Run.ID] = true
				}
				_ = h.boundLog(a.Run.ID)
			}
		}
	}
	h.platformMu.Lock()
	var gone []*platformService
	if err == nil {
		for id, s := range h.platform {
			if !runs[id] {
				gone = append(gone, s)
			}
		}
	}
	idle := err == nil && len(h.platform) == len(gone) && !anyRun(r)
	if idle && h.monitor == m {
		h.monitor = nil
	}
	h.platformMu.Unlock()
	for _, s := range gone {
		s.cancel()
	}
	return !idle
}

func anyRun(r *hostRegistry) bool {
	for _, a := range r.Agents {
		if a.Run != nil {
			return true
		}
	}
	return false
}
