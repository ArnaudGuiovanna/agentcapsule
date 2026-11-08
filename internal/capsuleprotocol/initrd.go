package capsuleprotocol

import (
	"encoding/json"
	"fmt"
	"io"
)

// AppendBootConfig adds a newc archive to an existing initramfs. Linux supports
// concatenated archives; the pinned base image is unchanged. This boot-specific
// file contains only guest credentials and must never be archived or logged.
// See https://www.kernel.org/doc/html/latest/driver-api/early-userspace/buffer-format.html.
func AppendBootConfig(out io.WriteSeeker, guest Credentials) error {
	if err := guest.Identity.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(guest)
	if err != nil {
		return err
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
	if err := entry("TRAILER!!!", 0, nil); err != nil {
		return err
	}
	return pad()
}
