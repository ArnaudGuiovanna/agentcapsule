package ext4image

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// File type bits of an inode's mode (st_mode).
const (
	TypeMask    = 0o170000
	TypeDir     = 0o040000
	TypeRegular = 0o100000
	TypeSymlink = 0o120000
	SetID       = 0o6000 // setuid and setgid
)

// Entry is an inode as debugfs shows it: in a directory listing, Name is the
// entry's name; Mode is st_mode, type and permission bits.
type Entry struct {
	Name  string
	Inode uint64
	Mode  uint32
	Size  int64
}

func (e Entry) IsDir() bool     { return e.Mode&TypeMask == TypeDir }
func (e Entry) IsRegular() bool { return e.Mode&TypeMask == TypeRegular }

// ErrUnreadable: debugfs's answer does not have the expected form. A valid
// image never gives one; a crafted or damaged one may.
var ErrUnreadable = errors.New("unexpected debugfs output")

// Debugfs is the absolute path of debugfs on PATH.
func Debugfs() (string, error) {
	p, err := exec.LookPath("debugfs")
	if err != nil {
		return "", fmt.Errorf("debugfs (e2fsprogs) is required to inspect images: %w", err)
	}
	return filepath.Abs(p)
}

var (
	statType = regexp.MustCompile(`(?m)^Inode: (\d+)\s+Type: (\S+)\s+Mode:\s+([0-7]+)\s`)
	statSize = regexp.MustCompile(`(?m)^User:.*\sSize: (\d+)$`)
	types    = map[string]uint32{"regular": TypeRegular, "directory": TypeDir, "symlink": TypeSymlink,
		"FIFO": 0o010000, "socket": 0o140000, "character": 0o020000, "block": 0o060000}
)

// Stat runs debugfs -R 'stat "P"' on image, confined by sb (package
// sandbox): debugfs parses an image that came from outside, and a flaw of
// e2fsprogs must not reach the host. found is false when the image has no
// such path.
func Stat(ctx context.Context, sb sandbox.Options, debugfs, image, p string) (e Entry, found bool, err error) {
	if !Quotable(p) {
		return Entry{}, false, fmt.Errorf("path %q cannot be named to debugfs", p)
	}
	out, err := sb.Run(ctx, image, debugfs, "-R", "stat \""+p+"\"", sandbox.ImagePath)
	if err != nil {
		return Entry{}, false, fmt.Errorf("debugfs: %w", err)
	}
	m := statType.FindSubmatch(out)
	if m == nil {
		return Entry{}, false, nil
	}
	kind, ok := types[string(m[2])]
	inode, err1 := strconv.ParseUint(string(m[1]), 10, 32)
	perm, err2 := strconv.ParseUint(string(m[3]), 8, 32)
	s := statSize.FindSubmatch(out)
	if !ok || err1 != nil || err2 != nil || perm > 0o7777 || s == nil {
		return Entry{}, false, ErrUnreadable
	}
	size, err := strconv.ParseInt(string(s[1]), 10, 64)
	if err != nil {
		return Entry{}, false, ErrUnreadable
	}
	return Entry{Name: p, Inode: inode, Mode: kind | uint32(perm), Size: size}, true, nil
}

// lsLine is one entry of debugfs's parseable listing (ls -p):
// /inode/mode/uid/gid/name/size/, size empty for a directory. A name holding
// '/' or a newline breaks the form and is refused.
var lsLine = regexp.MustCompile(`^/(\d+)/([0-7]{6})/(\d+)/(\d+)/([^/\n]*)/(\d*)/$`)

// List runs debugfs -R 'ls -p "DIR"' on image, confined by sb, and returns
// the directory's entries but "." and "..". A listing as long as the
// sandbox keeps (sandbox.MaxOutput) may have been cut: it is refused, as is
// any line out of form or a name that is not printable UTF-8.
func List(ctx context.Context, sb sandbox.Options, debugfs, image, dir string) ([]Entry, error) {
	if !Quotable(dir) {
		return nil, fmt.Errorf("path %q cannot be named to debugfs", dir)
	}
	out, err := sb.Run(ctx, image, debugfs, "-R", "ls -p \""+dir+"\"", sandbox.ImagePath)
	if err != nil {
		return nil, fmt.Errorf("debugfs: %w", err)
	}
	if len(out) >= sandbox.MaxOutput {
		return nil, fmt.Errorf("%w: the listing of %s is too long", ErrUnreadable, dir)
	}
	return parseListing(strings.Split(strings.TrimSuffix(string(out), "\n"), "\n"))
}

// ListBatch bounds the directories one ListInodes run lists: their commands,
// at most 57 bytes each, fit sandbox.MaxProgramInput.
const ListBatch = 512

// ListInodes lists the directories of inodes, each by its inode number
// (debugfs's <N>, as a listing gave it), in as few confined debugfs runs as
// their listings allow (v0.1.0 audit, P-12): one run reads its commands on
// its standard input (debugfs -f -) and lists up to ListBatch directories,
// as many as fit sandbox.MaxOutput. Before each command the run echoes a
// comment line that holds a nonce drawn for the run: an image cannot forge
// it, so a name cannot pass one directory's lines off as another's. Only a
// listing followed by the next one's comment is complete; the listing the
// output limit cut is listed again in the next run, and one that alone does
// not fit is refused, as List refuses it. Each listing is List's, in order.
func ListInodes(ctx context.Context, sb sandbox.Options, debugfs, image string, inodes []uint64) ([][]Entry, error) {
	out := make([][]Entry, 0, len(inodes))
	for len(out) < len(inodes) {
		batch := inodes[len(out):min(len(inodes), len(out)+ListBatch)]
		listings, err := listRun(ctx, sb, debugfs, image, batch)
		if err != nil {
			return nil, err
		}
		if len(listings) == 0 {
			return nil, fmt.Errorf("%w: the listing of inode %d is too long", ErrUnreadable, batch[0])
		}
		out = append(out, listings...)
	}
	return out, nil
}

// listRun lists batch in one confined run and returns the complete listings,
// in order: all of them, or those before the one the output limit cut.
func listRun(ctx context.Context, sb sandbox.Options, debugfs, image string, batch []uint64) ([][]Entry, error) {
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	mark := "#" + hex.EncodeToString(nonce[:]) + " "
	var commands strings.Builder
	for i, inode := range batch {
		fmt.Fprintf(&commands, "%s%d\nls -p <%d>\n", mark, i, inode)
	}
	raw, err := sb.RunInput(ctx, image, []byte(commands.String()), debugfs, "-f", "-", sandbox.ImagePath)
	if err != nil {
		return nil, fmt.Errorf("debugfs: %w", err)
	}
	cut := len(raw) >= sandbox.MaxOutput
	lines := strings.Split(string(raw), "\n")
	if cut {
		lines = lines[:len(lines)-1] // the line the limit cut
	}
	// sections[i] holds the lines of batch[i]'s listing, its command's echo
	// first.
	var sections [][]string
	for _, line := range lines {
		if rest, ok := strings.CutPrefix(line, mark); ok {
			if rest != strconv.Itoa(len(sections)) || len(sections) == len(batch) {
				return nil, ErrUnreadable
			}
			sections = append(sections, nil)
			continue
		}
		if len(sections) == 0 {
			if line != "" {
				return nil, ErrUnreadable
			}
			continue
		}
		sections[len(sections)-1] = append(sections[len(sections)-1], line)
	}
	if cut && len(sections) > 0 {
		sections = sections[:len(sections)-1]
	} else if !cut && len(sections) != len(batch) {
		return nil, ErrUnreadable
	}
	listings := make([][]Entry, 0, len(sections))
	for i, section := range sections {
		if len(section) == 0 || section[0] != fmt.Sprintf("debugfs: ls -p <%d>", batch[i]) {
			return nil, ErrUnreadable
		}
		entries, err := parseListing(section[1:])
		if err != nil {
			return nil, err
		}
		listings = append(listings, entries)
	}
	return listings, nil
}

// parseListing reads the lines of one ls -p.
func parseListing(lines []string) ([]Entry, error) {
	var entries []Entry
	var err error
	for _, line := range lines {
		if line == "" {
			continue
		}
		m := lsLine.FindStringSubmatch(line)
		if m != nil && m[1] == "0" {
			continue // an unused entry, which the kernel skips too (lost+found's empty blocks)
		}
		if m == nil || !Printable(m[5]) {
			return nil, ErrUnreadable
		}
		if m[5] == "." || m[5] == ".." {
			continue
		}
		inode, err1 := strconv.ParseUint(m[1], 10, 32)
		mode, err2 := strconv.ParseUint(m[2], 8, 32)
		e := Entry{Name: m[5], Inode: inode, Mode: uint32(mode)}
		if err1 != nil || err2 != nil || (m[6] == "") != e.IsDir() {
			return nil, ErrUnreadable
		}
		if m[6] != "" {
			if e.Size, err = strconv.ParseInt(m[6], 10, 64); err != nil {
				return nil, ErrUnreadable
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// Printable reports whether a file name is valid UTF-8 without control
// characters and can be named to debugfs.
func Printable(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsControl) < 0 && Quotable(name)
}
