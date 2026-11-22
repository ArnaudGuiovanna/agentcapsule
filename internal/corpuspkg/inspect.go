package corpuspkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ext4image"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// MaxDirectories bounds the directories InspectImage lists. One confined
// debugfs run (about 15 ms to start) lists up to ext4image.ListBatch of them
// (v0.1.0 audit, P-12): 100,000 directories take about 200 runs, no longer
// 100,000.
const MaxDirectories = 100000

// CheckImage reads only the superblock of an image of size bytes: an ext4
// filesystem that fills the file exactly, of 4 KiB blocks, labelled corpus,
// whose UUID is uuid, cleanly made, with the features of Features and no
// other (no journal to replay). It mounts nothing; the guest kernel mounts
// the image read-only.
func CheckImage(f io.ReaderAt, size, max int64, uuid string) error {
	if size < MinImageBytes || size > max || size%BlockSize != 0 {
		return corpusmeta.Invalid("corpus.ext4 size")
	}
	s, err := ext4image.ReadSuperblock(f, size)
	if err != nil {
		return corpusmeta.Invalid("corpus.ext4 %s", err.(*ext4image.SuperblockError).Reason)
	}
	switch {
	case s.BlockSize != BlockSize || s.Blocks*s.BlockSize != size:
		return corpusmeta.Invalid("corpus.ext4 does not fill its file with 4 KiB blocks")
	case s.UUID != uuid:
		return corpusmeta.Invalid("corpus.ext4 UUID is not the build's")
	case s.Label != Label:
		return corpusmeta.Invalid("corpus.ext4 label")
	case s.State != 1:
		return corpusmeta.Invalid("corpus.ext4 was not cleanly made")
	case s.Compat&^allowedCompat != 0 || s.Incompat&^allowedIncompat != 0 || s.ROCompat&^allowedROCompat != 0:
		return corpusmeta.Invalid("corpus.ext4 has features a corpus image does not use")
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
	return inspectImage(ctx, image, sb, true)
}

// InspectExtension verifies every entry of an enrichment image without mounting it.
func InspectExtension(ctx context.Context, image string, sb sandbox.Options) error {
	return inspectImage(ctx, image, sb, false)
}

func inspectImage(ctx context.Context, image string, sb sandbox.Options, base bool) error {
	debugfs, err := ext4image.Debugfs()
	if err != nil {
		return err
	}
	type directory struct {
		path  string
		inode uint64
	}
	// The required files, as the walk finds them.
	required := map[string]*ext4image.Entry{}
	if base {
		for _, f := range corpusmeta.RequiredFiles {
			required["/"+f] = nil
		}
	}
	queue := []directory{{"/", 2}} // the root directory's inode
	seen := map[uint64]bool{2: true}
	for listed := 0; len(queue) > 0; {
		// One level of the walk at a time, a run per ListBatch directories.
		level := queue
		queue = nil
		if listed += len(level); listed > MaxDirectories {
			return corpusmeta.Invalid("corpus.ext4 has more than %d directories", MaxDirectories)
		}
		inodes := make([]uint64, len(level))
		for i, d := range level {
			inodes[i] = d.inode
		}
		listings, err := ext4image.ListInodes(ctx, sb, debugfs, image, inodes)
		if err != nil {
			return fmt.Errorf("%w: corpus.ext4 has a directory debugfs cannot list: %w", corpusmeta.ErrInvalid, err)
		}
		for i, entries := range listings {
			dir := level[i].path
			if base && dir == "/"+corpusmeta.ExtDir && len(entries) > 0 {
				return corpusmeta.Invalid("ext/ is reserved for enrichers and must be empty")
			}
			names := make(map[string]bool, len(entries))
			for _, e := range entries {
				switch {
				case len(e.Name) > MaxNameBytes:
					return corpusmeta.Invalid("corpus.ext4 has a name longer than %d bytes", MaxNameBytes)
				case names[e.Name]:
					// The kernel would find one of them: two are a crafted image.
					return corpusmeta.Invalid("corpus.ext4 has two entries of one name in a directory")
				case e.Mode&ext4image.SetID != 0:
					return corpusmeta.Invalid("corpus.ext4 has a setuid or setgid file")
				case e.IsDir():
					if seen[e.Inode] {
						return corpusmeta.Invalid("corpus.ext4 reaches a directory twice")
					}
					seen[e.Inode] = true
					queue = append(queue, directory{path.Join(dir, e.Name), e.Inode})
				case !e.IsRegular():
					return corpusmeta.Invalid("corpus.ext4 holds a symbolic link or a special file")
				}
				names[e.Name] = true
				if _, wanted := required[path.Join(dir, e.Name)]; wanted {
					required[path.Join(dir, e.Name)] = &e
				}
			}
		}
	}
	for _, f := range corpusmeta.RequiredFiles {
		e, wanted := required["/"+f]
		if !wanted {
			continue
		}
		if e == nil || !e.IsRegular() {
			return corpusmeta.Invalid("corpus.ext4 lacks %s", f)
		}
		if f == corpusmeta.IndexFile && e.Size > corpusmeta.MaxIndexBytes {
			return corpusmeta.Invalid("INDEX.md is larger than %d bytes", corpusmeta.MaxIndexBytes)
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
