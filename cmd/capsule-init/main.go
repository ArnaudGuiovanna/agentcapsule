//go:build linux && amd64

// capsule-init is PID 1 inside the microVM. It keeps boot credentials and volume
// unlock secrets out of the independent unprivileged harness process.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/guestinit"
)

func mount(source, target, kind string, flags uintptr, data string) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	return syscall.Mount(source, target, kind, flags, data)
}

func readPrivateJSON(path string, out any) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Sys().(*syscall.Stat_t).Uid != 0 || st.Size() > 65536 {
		return guestinit.ErrGuest
	}
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		return guestinit.ErrGuest
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return guestinit.ErrGuest
	}
	return nil
}

func run() error {
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		return guestinit.ErrGuest
	}
	syscall.Umask(0077)
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return err
	}
	for _, m := range []struct {
		source, target, kind, data string
		flags                      uintptr
	}{
		{"proc", "/proc", "proc", "", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC},
		{"sysfs", "/sys", "sysfs", "", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC},
		{"devtmpfs", "/dev", "devtmpfs", "mode=0755", syscall.MS_NOSUID},
		{"tmpfs", "/run", "tmpfs", "mode=0711", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC},
		{"tmpfs", "/tmp", "tmpfs", "mode=1777", syscall.MS_NOSUID | syscall.MS_NODEV},
		{"cgroup2", "/sys/fs/cgroup", "cgroup2", "", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC},
	} {
		if err := mount(m.source, m.target, m.kind, m.flags, m.data); err != nil {
			return err
		}
	}
	for _, dir := range []string{"/run/capsule", "/run/cryptsetup", "/dev/mapper", "/sys/fs/cgroup/capsule-harness"} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	if err := os.WriteFile("/sys/fs/cgroup/cgroup.subtree_control", []byte("+pids"), 0600); err != nil {
		return err
	}
	group := "/sys/fs/cgroup/capsule-harness"
	if err := os.WriteFile(filepath.Join(group, "pids.max"), []byte("256"), 0600); err != nil {
		return err
	}
	var credentials capsuleprotocol.Credentials
	if err := readPrivateJSON(capsuleprotocol.BootConfigPath, &credentials); err != nil {
		return err
	}
	var config struct {
		Entrypoint []string `json:"entrypoint"`
	}
	if err := readPrivateJSON("/etc/capsule/runtime.json", &config); err != nil {
		return err
	}
	if len(config.Entrypoint) == 0 || !filepath.IsAbs(config.Entrypoint[0]) {
		return guestinit.ErrGuest
	}
	var platform *capsuleprotocol.PlatformClient
	platformPath := ""
	if !credentials.Identity.FenceOnly && credentials.Platform != nil {
		var err error
		platform, err = capsuleprotocol.NewPlatformClient(*credentials.Platform, capsuleprotocol.DialPlatform)
		if err != nil {
			return err
		}
		if err = os.Mkdir("/run/capsule-platform", 0711); err != nil {
			return err
		}
		// Umask 0077 above deliberately protects all other supervisor paths.
		if err = os.Chmod("/run/capsule-platform", 0711); err != nil {
			return err
		}
		platformPath = "/run/capsule-platform/api.sock"
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	var mu sync.Mutex
	var process *guestinit.Process
	var volume *guestinit.MountedVolume
	var quiescing bool
	var shutdownMu sync.Mutex
	closeGuest := func(ctx context.Context) error {
		shutdownMu.Lock()
		defer shutdownMu.Unlock()
		mu.Lock()
		quiescing = true
		p, m := process, volume
		mu.Unlock()
		if p != nil {
			if err := p.Stop(ctx); err != nil {
				return err
			}
		}
		if m != nil {
			return m.Close(ctx)
		}
		return nil
	}
	server, err := capsuleprotocol.NewQuiescingVolumeServer(credentials, func(ready context.Context, v capsuleprotocol.VolumeBoot, key []byte) (http.Handler, error) {
		m, err := guestinit.OpenVolume(ready, v, key)
		if err != nil {
			cancel()
			return nil, err
		}
		p, err := guestinit.StartHarness(ctx, ready, guestinit.ProcessOptions{
			Boot:       guestinit.HarnessBoot{Protocol: capsuleprotocol.Version, Identity: credentials.Identity, DataDirectory: guestinit.DataDirectory, SupervisorUID: 0, PlatformSocket: platformPath, PreviousShutdown: v.PreviousShutdown},
			Entrypoint: config.Entrypoint, SocketPath: "/run/capsule/harness.sock", UID: 1000, GID: 1000, Cgroup: group,
			Platform: platform,
		})
		if err != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			err = errors.Join(err, m.Close(cleanup))
			stop()
			cancel()
			return nil, err
		}
		mu.Lock()
		volume, process = m, p
		mu.Unlock()
		go func() {
			<-p.Done()
			mu.Lock()
			intentional := quiescing
			mu.Unlock()
			if !intentional {
				cancel()
			}
		}()
		return p.Proxy(), nil
	}, closeGuest)
	if err != nil {
		return err
	}
	l, err := capsuleprotocol.ListenControl()
	if err != nil {
		return err
	}
	err = capsuleprotocol.ServeAuthenticated(ctx, l, credentials, server)
	cancel()
	cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	if e := server.StopPreparation(cleanup); e != nil {
		return e
	}
	if e := closeGuest(cleanup); e != nil {
		return e
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func main() {
	// Never mount or reboot when this guest binary is invoked on the host.
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		os.Exit(1)
	}
	if run() != nil {
		fmt.Println("CAPSULE_INIT_FAILED")
	}
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	for {
		_ = syscall.Pause()
	}
}
