//go:build unix

package corpuspkg

import (
	"io/fs"
	"syscall"
)

// inodeKey identifies a regular file that has other links: its device and
// inode.
func inodeKey(info fs.FileInfo) ([2]uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink < 2 {
		return [2]uint64{}, false
	}
	return [2]uint64{uint64(st.Dev), uint64(st.Ino)}, true
}
