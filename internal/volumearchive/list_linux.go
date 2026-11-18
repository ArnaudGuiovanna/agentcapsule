//go:build linux && cgo

package volumearchive

import (
	"os"
	"slices"
)

// List names the published archives of the root, in order: the directories
// named by a valid archive ID. A capture or a removal in progress has another
// name. It reads no manifest; Manifest tells whose archive each one is.
func (s *Store) List() ([]string, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() && ValidID(e.Name()) {
			ids = append(ids, e.Name())
		}
	}
	slices.Sort(ids)
	return ids, nil
}
