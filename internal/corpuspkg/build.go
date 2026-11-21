package corpuspkg

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/ext4image"
)

const (
	// MinImageBytes is the smallest image size.
	MinImageBytes = 1 << 20
	// Label is the filesystem label of every corpus image.
	Label = "corpus"
	// BlockSize and InodeSize of every corpus image.
	BlockSize = 4096
	InodeSize = 256
	// MaxNameBytes bounds a file name of the layout (ext4's limit).
	MaxNameBytes = 255
)

// Features are the only ext4 features of a corpus image: no journal, no
// inline data, no encryption or case folding. CheckImage refuses any other.
var Features = []string{"ext_attr", "dir_index", "filetype", "extent", "flex_bg", "sparse_super", "large_file",
	"huge_file", "dir_nlink", "extra_isize", "64bit", "metadata_csum"}

const (
	allowedCompat   = ext4image.CompatExtAttr | ext4image.CompatDirIndex
	allowedIncompat = ext4image.IncompatFiletype | ext4image.IncompatExtents | ext4image.Incompat64Bit | ext4image.IncompatFlexBG
	allowedROCompat = ext4image.ROCompatSparseSuper | ext4image.ROCompatLargeFile | ext4image.ROCompatHugeFile |
		ext4image.ROCompatDirNlink | ext4image.ROCompatExtraIsize | ext4image.ROCompatMetadataCsum
)

// tree is a layout read from a directory.
type tree struct {
	paths  []string          // image paths, lexical order
	modes  map[string]uint32 // the mode each gets
	files  int64
	blocks int64 // data and directory blocks
}

// BuildImage builds out, a corpus image, from dir, a tree in the published
// layout, and returns the image's size. dir must hold only directories and
// regular files, each path once (no hard link between two of its paths),
// with printable names of at most 255 bytes, the required files
// (RequiredFiles, INDEX.md at most 64 KiB) and an empty or absent ext/. The
// image is reproducible: every directory gets mode 0755, every file 0644,
// owner root and the times 1; its UUID and directory hash seed are uuid
// (ImageUUID); its size, block size, inode count and features are functions
// of the tree. The same tree and uuid give the same image, byte for byte,
// with the same e2fsprogs, provided out starts as zeros (a new file, or a
// new sparse file of the output drive): mkfs.ext4 leaves unused blocks as
// they are. out may be a block device. maxBytes bounds the image.
//
// It runs mkfs.ext4 and debugfs -w, as the harness build does: on the
// builder's own output, in its VM. The worker never calls it.
func BuildImage(ctx context.Context, dir, out, uuid string, maxBytes int64) (int64, error) {
	return buildImage(ctx, dir, out, uuid, maxBytes, true)
}

// BuildExtensionImage creates a data-only ext4 image for a reviewed corpus.
// Its directory contents are defined by the authorized enrichment harness.
func BuildExtensionImage(ctx context.Context, dir, out, uuid string, maxBytes int64) (int64, error) {
	return buildImage(ctx, dir, out, uuid, maxBytes, false)
}

func buildImage(ctx context.Context, dir, out, uuid string, maxBytes int64, base bool) (int64, error) {
	if !ValidUUID(uuid) {
		return 0, invalid("the image UUID")
	}
	t, err := readTree(dir, base)
	if err != nil {
		return 0, err
	}
	size := t.size()
	for attempt := 0; ; attempt++ {
		if size > maxBytes {
			return 0, fmt.Errorf("%w: the image needs %d bytes, past %d", ErrTooLarge, size, maxBytes)
		}
		inodes := len(t.paths) + 64
		err = ext4image.Build(ctx, ext4image.Spec{Kind: "a corpus image", Dir: dir, Out: out, SizeMiB: int(size >> 20),
			Label: Label, UUID: uuid, Paths: t.paths, Modes: t.modes,
			Options: []string{"-b", strconv.Itoa(BlockSize), "-I", strconv.Itoa(InodeSize), "-N", strconv.Itoa(inodes),
				"-m", "0", "-O", "none," + strings.Join(Features, ",")},
			Extended: []string{"lazy_itable_init=0", "nodiscard"}})
		// The estimate leaves room; should mkfs still want more, a quarter
		// more, at most twice: the same tree takes the same steps.
		if errors.Is(err, ext4image.ErrFull) && attempt < 2 {
			size = roundMiB(size + size/4)
			continue
		}
		if err != nil {
			return 0, err
		}
		return size, nil
	}
}

// ErrTooLarge: the layout does not fit in the bytes allowed.
var ErrTooLarge = errors.New("corpus image too large")

func readTree(dir string, base bool) (tree, error) {
	t := tree{modes: map[string]uint32{}}
	links := map[[2]uint64]bool{}
	entries := map[string]int64{} // directory path to its entries' bytes
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			if !d.IsDir() {
				return invalid("the layout must be a directory")
			}
			return nil
		}
		name := d.Name()
		if !ext4image.Printable(name) || len(name) > MaxNameBytes {
			return invalid("a file name of the layout is not printable UTF-8 of at most 255 bytes")
		}
		ip := "/" + filepath.ToSlash(rel)
		parent := filepath.ToSlash(filepath.Dir(ip))
		entries[parent] += 8 + int64(len(name)+3)/4*4
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if base && ip == "/"+ExtDir {
				if list, err := os.ReadDir(p); err != nil || len(list) > 0 {
					return invalid("ext/ is reserved for enrichers and must be empty")
				}
			}
			t.modes[ip] = ext4image.TypeDir | 0o755
		case d.Type().IsRegular():
			if key, linked := inodeKey(info); linked {
				if links[key] {
					return invalid("two paths of the layout are the same file (a hard link)")
				}
				links[key] = true
			}
			t.modes[ip] = ext4image.TypeRegular | 0o644
			t.files++
			blocks := (info.Size() + BlockSize - 1) / BlockSize
			t.blocks += blocks
			if blocks > 2*32768 { // more extents than the inode holds: index blocks
				t.blocks += 1 + blocks/(32768*340)
			}
		default:
			return invalid("the layout holds a symbolic link or a special file; it may hold only directories and regular files")
		}
		t.paths = append(t.paths, ip)
		return nil
	})
	if err != nil {
		return tree{}, err
	}
	for _, n := range entries {
		t.blocks += (n+24)/(BlockSize-12) + 2 // entries, '.' and '..', checksum tails, an htree index
	}
	t.blocks += 2 // the root
	if !base {
		return t, nil
	}
	for _, f := range RequiredFiles {
		info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(f)))
		if err != nil || !info.Mode().IsRegular() {
			return tree{}, invalid("the layout lacks %s", f)
		}
		if f == IndexFile && info.Size() > MaxIndexBytes {
			return tree{}, invalid("INDEX.md is larger than %d bytes", MaxIndexBytes)
		}
	}
	return t, nil
}

// size estimates the image's bytes: data and directory blocks, inode
// tables, then for each 128 MiB block group its bitmaps, descriptors and
// superblock backups, with room to spare, in whole MiB.
func (t tree) size() int64 {
	inodes := int64(len(t.paths) + 64)
	blocks := t.blocks + (inodes*InodeSize+BlockSize-1)/BlockSize + 64 // lost+found, reserved inodes
	groups := blocks/32768 + 1
	blocks += groups * (2 + 2 + 1) // bitmaps, descriptors, a backup superblock at most
	return roundMiB(blocks*BlockSize + blocks*BlockSize/20 + 4<<20)
}

func roundMiB(n int64) int64 { return max((n+1<<20-1)>>20<<20, MinImageBytes) }
