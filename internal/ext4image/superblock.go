package ext4image

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Superblock holds the fields of an ext4 superblock the host reads before it
// lets anything else parse the image.
type Superblock struct {
	BlockSize int64
	Blocks    int64
	Inodes    uint32
	// State is s_state: 1 cleanly unmounted, 2 errors, 4 orphans.
	State    uint16
	Compat   uint32
	Incompat uint32
	ROCompat uint32
	UUID     string
	Label    string
}

// Feature bits of the superblock (linux/fs/ext4/ext4.h).
const (
	CompatHasJournal = 0x4
	CompatExtAttr    = 0x8
	CompatDirIndex   = 0x20

	IncompatFiletype = 0x2
	IncompatRecover  = 0x4
	IncompatExtents  = 0x40
	Incompat64Bit    = 0x80
	IncompatFlexBG   = 0x200

	ROCompatSparseSuper  = 0x1
	ROCompatLargeFile    = 0x2
	ROCompatHugeFile     = 0x8
	ROCompatDirNlink     = 0x20
	ROCompatExtraIsize   = 0x40
	ROCompatMetadataCsum = 0x400
)

// SuperblockError is why ReadSuperblock refused an image. Reason names the
// failed check, never the image's bytes.
type SuperblockError struct{ Reason string }

func (e *SuperblockError) Error() string { return "ext4 image " + e.Reason }

func refused(reason string) error { return &SuperblockError{reason} }

// ReadSuperblock reads only the ext4 superblock of an image of size bytes:
// its magic, its block size and the filesystem fitting in the image. The
// reasons it gives are "superblock unreadable", "is not an ext4 filesystem",
// "block size" and "is larger than its file".
func ReadSuperblock(r io.ReaderAt, size int64) (Superblock, error) {
	sb := make([]byte, 1024)
	if _, err := r.ReadAt(sb, 1024); err != nil {
		return Superblock{}, refused("superblock unreadable")
	}
	if binary.LittleEndian.Uint16(sb[0x38:]) != 0xEF53 {
		return Superblock{}, refused("is not an ext4 filesystem")
	}
	logBlock := binary.LittleEndian.Uint32(sb[0x18:])
	if logBlock > 6 {
		return Superblock{}, refused("block size")
	}
	s := Superblock{
		BlockSize: int64(1024) << logBlock,
		Blocks:    int64(binary.LittleEndian.Uint32(sb[0x04:])),
		Inodes:    binary.LittleEndian.Uint32(sb[0x00:]),
		State:     binary.LittleEndian.Uint16(sb[0x3A:]),
		Compat:    binary.LittleEndian.Uint32(sb[0x5C:]),
		Incompat:  binary.LittleEndian.Uint32(sb[0x60:]),
		ROCompat:  binary.LittleEndian.Uint32(sb[0x64:]),
	}
	if s.Incompat&Incompat64Bit != 0 { // the high half is meaningful
		s.Blocks |= int64(binary.LittleEndian.Uint32(sb[0x150:])) << 32
	}
	if s.Blocks < 1 || s.Blocks > size/s.BlockSize {
		return Superblock{}, refused("is larger than its file")
	}
	u := sb[0x68:0x78]
	s.UUID = fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	label := sb[0x78:0x88]
	for i, c := range label {
		if c == 0 {
			label = label[:i]
			break
		}
	}
	s.Label = string(label)
	return s, nil
}
