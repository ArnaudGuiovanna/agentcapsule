package capsuleprotocol

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
)

// HarnessLaunch tells capsule-init to run a harness from the read-only drive
// HarnessDevice instead of the harness built into the platform image. The
// entrypoint is a path inside that filesystem, which becomes the harness root.
type HarnessLaunch struct {
	Entrypoint []string `json:"entrypoint"`
}

const (
	HarnessConfigPath = "/etc/capsule/harness.json"
	// HarnessDevice is the second virtio drive; the first is the data volume.
	HarnessDevice = "/dev/vdb"
)

// HarnessMountPoints must exist as directories in every harness filesystem of
// base agentcapsule-guest/1; capsule-init mounts the guest's runtime there.
var HarnessMountPoints = []string{"/dev", "/proc", "/run", "/tmp", "/var/lib/agent"}

func (h HarnessLaunch) Validate() error {
	if len(h.Entrypoint) < 1 || len(h.Entrypoint) > 32 || !strings.HasPrefix(h.Entrypoint[0], "/") || path.Clean(h.Entrypoint[0]) != h.Entrypoint[0] || h.Entrypoint[0] == "/" {
		return ErrProtocol
	}
	for _, a := range h.Entrypoint {
		if a == "" || len(a) > 256 || strings.ContainsRune(a, 0) {
			return ErrProtocol
		}
	}
	return nil
}

// AppendBootConfig adds a newc archive to an existing initramfs. Linux supports
// concatenated archives; the pinned base image is unchanged. This boot-specific
// file contains only guest credentials and must never be archived or logged.
// harness, when set, adds HarnessConfigPath for a harness on its own drive.
// See https://www.kernel.org/doc/html/latest/driver-api/early-userspace/buffer-format.html.
func AppendBootConfig(out io.WriteSeeker, guest Credentials, harness *HarnessLaunch) error {
	if err := guest.Identity.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(guest)
	if err != nil {
		return err
	}
	var launch []byte
	if harness != nil {
		if err = harness.Validate(); err != nil {
			return err
		}
		if launch, err = json.Marshal(harness); err != nil {
			return err
		}
	}
	pad := func() error {
		offset, err := out.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		_, err = out.Write(make([]byte, (4-offset%4)%4))
		return err
	}
	entry := func(name string, mode uint32, data []byte) error {
		if err := pad(); err != nil {
			return err
		}
		fields := []uint32{1, mode, 0, 0, 1, 0, uint32(len(data)), 0, 0, 0, 0, uint32(len(name) + 1), 0}
		header := "070701"
		for _, v := range fields {
			header += fmt.Sprintf("%08x", v)
		}
		if _, err := io.WriteString(out, header+name+"\x00"); err != nil {
			return err
		}
		if err := pad(); err != nil {
			return err
		}
		_, err := out.Write(data)
		return err
	}
	for _, dir := range []string{"etc", "etc/capsule"} {
		if err := entry(dir, 0040700, nil); err != nil {
			return err
		}
	}
	if err := entry("etc/capsule/boot.json", 0100400, b); err != nil {
		return err
	}
	if launch != nil {
		if err := entry("etc/capsule/harness.json", 0100400, launch); err != nil {
			return err
		}
	}
	if err := entry("TRAILER!!!", 0, nil); err != nil {
		return err
	}
	return pad()
}
