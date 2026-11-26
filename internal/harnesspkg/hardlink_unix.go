//go:build unix

package harnesspkg

import (
	"io/fs"
	"syscall"
)

func hardlinkID(info fs.FileInfo) ([2]uint64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink < 2 {
		return [2]uint64{}, false
	}
	return [2]uint64{uint64(stat.Dev), uint64(stat.Ino)}, true
}
