//go:build !unix

package harnesspkg

import "io/fs"

func hardlinkID(fs.FileInfo) ([2]uint64, bool) {
	return [2]uint64{}, false
}
