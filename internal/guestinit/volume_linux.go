//go:build linux

package guestinit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

const mountRoot = "/mnt/capsule"
const DataDirectory = "/var/lib/agent"
const mappingName = "capsule-data"
const mappedDevice = "/dev/mapper/" + mappingName

type toolOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (b *toolOutput) Write(p []byte) (int, error) {
	n := len(p)
	room := 4096 - b.buffer.Len()
	if len(p) > room {
		b.overflow = true
		p = p[:room]
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}

// runTool never puts a key in argv/environment/a file or returns diagnostics.
// Wait also joins os/exec's stdin copy goroutine before the caller clears key.
func runTool(ctx context.Context, key []byte, path string, args ...string) (string, int, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/sbin:/usr/sbin:/bin:/usr/bin", "LANG=C", "LC_ALL=C"}
	if key != nil {
		cmd.Stdin = bytes.NewReader(key)
	}
	var output toolOutput
	cmd.Stdout = &output // stderr is discarded; it can include filesystem data.
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", -1, ctx.Err()
	}
	if output.overflow {
		return "", -1, ErrGuest
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", exit.ExitCode(), nil
		}
		return "", -1, ErrGuest
	}
	return strings.TrimSpace(output.buffer.String()), 0, nil
}

type MountedVolume struct{ opened, mounted, bound bool }

// OpenVolume can run only as the guest's root PID 1. The host never calls mount
// or opens a dm-crypt mapping. A subsequent boot with Initialize=false cannot
// format a filesystem or manufacture a missing durable volume marker.
func OpenVolume(ctx context.Context, v capsuleprotocol.VolumeBoot, key []byte) (m *MountedVolume, err error) {
	if os.Getpid() != 1 || os.Geteuid() != 0 || v.Validate() != nil || len(key) != 32 {
		return nil, ErrGuest
	}
	uuid, code, err := runTool(ctx, nil, "/sbin/cryptsetup", "luksUUID", "/dev/vda")
	if err != nil || code != 0 || uuid != v.UUID {
		return nil, ErrGuest
	}
	m = &MountedVolume{}
	defer func() {
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err = errors.Join(err, m.Close(cleanup))
		}
	}()
	_, code, err = runTool(ctx, key, "/sbin/cryptsetup", "open", "--type", "luks2", "--disable-external-tokens", "--disable-keyring", "--key-file", "-", "--keyfile-size", "32", "/dev/vda", mappingName)
	if err != nil || code != 0 {
		return m, ErrGuest
	}
	m.opened = true
	for _, device := range []string{"/dev/vda", mappedDevice} {
		if err = os.Chmod(device, 0600); err != nil {
			return m, ErrGuest
		}
	}
	kind, code, err := runTool(ctx, nil, "/sbin/blkid", "-p", "-s", "TYPE", "-o", "value", mappedDevice)
	if err != nil {
		return m, ErrGuest
	}
	if code == 2 && v.Initialize {
		// Formatting the private filesystem never replaces the LUKS header.
		_, code, err = runTool(ctx, nil, "/sbin/mkfs.ext4", "-q", "-F", "-U", v.UUID, "-E", "lazy_itable_init=0,lazy_journal_init=0", mappedDevice)
		if err != nil || code != 0 {
			return m, ErrGuest
		}
	} else if code != 0 || kind != "ext4" {
		return m, ErrGuest
	}
	uuid, code, err = runTool(ctx, nil, "/sbin/blkid", "-p", "-s", "UUID", "-o", "value", mappedDevice)
	if err != nil || code != 0 || uuid != v.UUID {
		return m, ErrGuest
	}
	_, code, err = runTool(ctx, nil, "/sbin/e2fsck", "-p", "-f", mappedDevice)
	if err != nil || (code != 0 && code != 1) {
		return m, ErrGuest
	}
	for _, dir := range []string{mountRoot, DataDirectory} {
		if err = os.MkdirAll(dir, 0700); err != nil {
			return m, ErrGuest
		}
	}
	if err = syscall.Mount(mappedDevice, mountRoot, "ext4", syscall.MS_NOATIME|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return m, ErrGuest
	}
	m.mounted = true
	if v.Initialize {
		if err = os.Chmod(mountRoot, 0700); err != nil {
			return m, ErrGuest
		}
	}
	rootInfo, err := os.Stat(mountRoot)
	if err != nil || rootInfo.Mode().Perm() != 0700 || rootInfo.Sys().(*syscall.Stat_t).Uid != 0 {
		return m, ErrGuest
	}
	if err = volumeMarker(v); err != nil {
		return m, err
	}
	dir := filepath.Join(mountRoot, "harness")
	if v.Initialize {
		if err = os.MkdirAll(dir, 0700); err != nil {
			return m, ErrGuest
		}
		if err = os.Chown(dir, 1000, 1000); err != nil {
			return m, ErrGuest
		}
		if err = os.Chmod(dir, 0700); err != nil {
			return m, ErrGuest
		}
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != 1000 || st.Sys().(*syscall.Stat_t).Gid != 1000 {
		return m, ErrGuest
	}
	if err = syncDirectory(mountRoot); err != nil {
		return m, err
	}
	if err = syncDirectory(dir); err != nil {
		return m, err
	}
	if err = syscall.Mount(dir, DataDirectory, "", syscall.MS_BIND, ""); err != nil {
		return m, ErrGuest
	}
	m.bound = true
	if err = syscall.Mount("", DataDirectory, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return m, ErrGuest
	}
	return m, nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

type volumeIdentity struct {
	Incarnation uint64 `json:"incarnation"`
	VolumeID    string `json:"volume_id"`
	UUID        string `json:"uuid"`
}

func checkVolumeIdentity(r io.Reader, want volumeIdentity) error {
	var have volumeIdentity
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if want.Incarnation == 0 || d.Decode(&have) != nil || have != want {
		return ErrGuest
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrGuest
	}
	return nil
}

func volumeMarker(v capsuleprotocol.VolumeBoot) error {
	// The marker is outside the unprivileged harness's bind mount and directory.
	path := filepath.Join(mountRoot, "volume.json")
	want := volumeIdentity{v.Incarnation, v.VolumeID, v.UUID}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0400 || st.Size() > 512 || st.Sys().(*syscall.Stat_t).Uid != 0 {
			return ErrGuest
		}
		return checkVolumeIdentity(f, want)
	}
	if !errors.Is(err, os.ErrNotExist) || !v.Initialize {
		return ErrGuest
	}
	b, err := json.Marshal(want)
	if err != nil {
		return ErrGuest
	}
	f, err = os.CreateTemp(mountRoot, ".volume-")
	if err != nil {
		return ErrGuest
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0400); err != nil {
		return ErrGuest
	}
	if _, err = f.Write(b); err != nil {
		return ErrGuest
	}
	if err = f.Sync(); err != nil {
		return ErrGuest
	}
	if err = f.Close(); err != nil {
		return ErrGuest
	}
	if err = os.Link(f.Name(), path); err != nil {
		return ErrGuest
	}
	return syncDirectory(mountRoot)
}

// Close is called only after the harness cgroup has been retired. An unmount
// failure is surfaced; forced/lazy unmount would not establish safe shutdown.
func (m *MountedVolume) Close(ctx context.Context) error {
	if m.mounted {
		// Unlike sync(2), syncfs reports writeback errors. Never turn a failed
		// filesystem synchronization into a clean-shutdown acknowledgment.
		f, err := os.OpenFile(mountRoot, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return ErrGuest
		}
		synced := syncFilesystem(f)
		closed := f.Close()
		if synced != nil || closed != nil {
			return ErrGuest
		}
	}
	if m.bound {
		if err := syscall.Unmount(DataDirectory, 0); err != nil {
			return ErrGuest
		}
		m.bound = false
	}
	if m.mounted {
		if err := syscall.Unmount(mountRoot, 0); err != nil {
			return ErrGuest
		}
		m.mounted = false
	}
	if m.opened {
		_, code, err := runTool(ctx, nil, "/sbin/cryptsetup", "close", mappingName)
		if err != nil || code != 0 {
			return ErrGuest
		}
		m.opened = false
	}
	return nil
}
