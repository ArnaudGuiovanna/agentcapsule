package corpuspkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/ext4image"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// MaxDirectories bounds the directories InspectImage lists: each costs one
// confined debugfs run (about 15 ms).
const MaxDirectories = 100000

// CheckImage reads only the superblock of an image of size bytes: an ext4
// filesystem that fills the file exactly, of 4 KiB blocks, labelled corpus,
// whose UUID is uuid, cleanly made, with the features of Features and no
// other (no journal to replay). It mounts nothing; the guest kernel mounts
// the image read-only.
func CheckImage(f io.ReaderAt, size, max int64, uuid string) error {
	if size < MinImageBytes || size > max || size%BlockSize != 0 {
		return invalid("corpus.ext4 size")
	}
	s, err := ext4image.ReadSuperblock(f, size)
	if err != nil {
		return invalid("corpus.ext4 %s", err.(*ext4image.SuperblockError).Reason)
	}
	switch {
	case s.BlockSize != BlockSize || s.Blocks*s.BlockSize != size:
		return invalid("corpus.ext4 does not fill its file with 4 KiB blocks")
	case s.UUID != uuid:
		return invalid("corpus.ext4 UUID is not the build's")
	case s.Label != Label:
		return invalid("corpus.ext4 label")
	case s.State != 1:
		return invalid("corpus.ext4 was not cleanly made")
	case s.Compat&^allowedCompat != 0 || s.Incompat&^allowedIncompat != 0 || s.ROCompat&^allowedROCompat != 0:
		return invalid("corpus.ext4 has features a corpus image does not use")
	}
	return nil
}

// InspectImage checks, without mounting, that an image holds the published
// layout: the required files are regular files, INDEX.md is at most 64 KiB,
// ext/ is absent or empty, and the image holds only directories and regular
// files, none setuid or setgid, each directory reached once. It lists every
// directory with debugfs (e2fsprogs), read-only, confined by sb: debugfs
// parses an image a builder VM made, and a flaw of e2fsprogs must not reach
// the host (package sandbox).
func InspectImage(ctx context.Context, image string, sb sandbox.Options) error {
	debugfs, err := ext4image.Debugfs()
	if err != nil {
		return err
	}
	for _, f := range RequiredFiles {
		e, found, err := ext4image.Stat(ctx, sb, debugfs, image, "/"+f)
		if err != nil {
			return err
		}
		if !found || !e.IsRegular() {
			return invalid("corpus.ext4 lacks %s", f)
		}
		if f == IndexFile && e.Size > MaxIndexBytes {
			return invalid("INDEX.md is larger than %d bytes", MaxIndexBytes)
		}
	}
	queue := []string{"/"}
	seen := map[uint64]bool{2: true} // the root directory's inode
	for listed := 0; len(queue) > 0; listed++ {
		if listed == MaxDirectories {
			return invalid("corpus.ext4 has more than %d directories", MaxDirectories)
		}
		dir := queue[0]
		queue = queue[1:]
		entries, err := ext4image.List(ctx, sb, debugfs, image, dir)
		if err != nil {
			return invalid("corpus.ext4 has a directory debugfs cannot list: %v", err)
		}
		if dir == "/"+ExtDir && len(entries) > 0 {
			return invalid("ext/ is reserved for enrichers and must be empty")
		}
		for _, e := range entries {
			switch {
			case len(e.Name) > MaxNameBytes:
				return invalid("corpus.ext4 has a name longer than %d bytes", MaxNameBytes)
			case e.Mode&ext4image.SetID != 0:
				return invalid("corpus.ext4 has a setuid or setgid file")
			case e.IsDir():
				if seen[e.Inode] {
					return invalid("corpus.ext4 reaches a directory twice")
				}
				seen[e.Inode] = true
				queue = append(queue, path.Join(dir, e.Name))
			case !e.IsRegular():
				return invalid("corpus.ext4 holds a symbolic link or a special file")
			}
		}
	}
	return nil
}

// digestOf is "sha256:" and the hex sha256 of the whole file.
func digestOf(f *os.File) (string, error) {
	h := sha256.New()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if _, err = io.Copy(h, io.NewSectionReader(f, 0, st.Size())); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
