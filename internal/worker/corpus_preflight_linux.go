//go:build linux

package worker

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
)

// CorpusFilesystemCheck is the preflight check corpus_cache_filesystem
// (ADR 023 §5.1): each directory (the corpus cache, the build staging) must
// be on the file system of root/jails, since its images and drives are hard
// linked into each VM's jail and never copied. A directory not created yet
// is checked through its nearest existing parent. The worker's start refuses
// a failure, so that no boot fails later on a link it cannot make.
func CorpusFilesystemCheck(root string, dirs ...string) preflight.Result {
	const check = "corpus_cache_filesystem"
	jails := nearestDir(filepath.Join(root, "jails"))
	probes := make([]string, 0, len(dirs))
	for _, d := range dirs {
		probes = append(probes, nearestDir(d))
	}
	err := runtime.CheckLinkable(jails, probes...)
	switch {
	case err == nil:
		return preflight.Result{Check: check, Status: preflight.OK, Detail: "the corpus cache and staging are on the jails' file system"}
	case errors.Is(err, runtime.ErrCorpusFilesystem):
		return preflight.Result{Check: check, Status: preflight.Fail, Detail: "the corpus cache or staging is on another file system or mount than " + filepath.Join(root, "jails"),
			Fix: "put corpus.cache and corpus.staging on the file system and mount of the runtime root: corpus images are hard linked into each VM's jail, never copied"}
	}
	return preflight.Result{Check: check, Status: preflight.Fail, Detail: "the corpus cache's file system cannot be checked", Fix: "create the runtime root and the corpus directories' parents"}
}

// nearestDir is path, or its nearest existing parent.
func nearestDir(path string) string {
	for {
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			return path
		}
		path = parent
	}
}
