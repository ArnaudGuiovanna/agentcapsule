//go:build linux

package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// A jail's root directory belongs to its VMM's user, who can put a link, a
// FIFO or a large file under any name in it. Root works there without
// following a link and without waiting on what it opens (L-15): the PID
// file, the platform socket and the jail's removal are workerhelper's.

// shareBootFile makes a cached kernel or initrd readable by the VMMs, which
// reach it only through a jail's hard link: the bin directory stays private.
func shareBootFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("boot image is not a regular file")
	}
	if st.Mode().Perm() == 0444 {
		return nil
	}
	return os.Chmod(path, 0444)
}

// bootImage names the cached kernel or initrd of a.
func (h *FirecrackerHost) bootImage(a *HostAgent, name string) (string, error) {
	artifact := name
	if a.SystemImage != nil {
		digest := a.SystemImage.Kernel
		if name == "initrd" {
			digest = a.SystemImage.Initrd
		}
		if raw, err := hex.DecodeString(digest); err != nil || len(raw) != sha256.Size {
			return "", errors.New("invalid system image digest")
		}
		artifact += "-" + digest
	}
	return filepath.Join(h.root, "bin", artifact), nil
}
