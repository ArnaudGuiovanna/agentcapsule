//go:build !unix

package corpuspkg

import "io/fs"

// inodeKey: elsewhere than on Unix, links are not looked for.
func inodeKey(fs.FileInfo) ([2]uint64, bool) { return [2]uint64{}, false }
