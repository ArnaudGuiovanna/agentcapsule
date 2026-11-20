package source

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// MaxPointerBytes bounds a Git LFS pointer file (the LFS specification:
// pointers are smaller than 1,024 bytes).
const MaxPointerBytes = 1024

// Pointer is a Git LFS pointer: the object a file of the repository stands
// for, by its sha256 and size. The worker downloads the object by that
// digest (ADR 023 §4).
type Pointer struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

const lfsVersion = "version https://git-lfs.github.com/spec/v1"

// ParsePointer reads a Git LFS pointer file: the version line, then
// "oid sha256:<64 lowercase hex>" and "size <bytes>", each followed by a
// newline, in that order. Anything else is not a pointer.
func ParsePointer(b []byte) (Pointer, bool) {
	if len(b) >= MaxPointerBytes {
		return Pointer{}, false
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) != 4 || lines[3] != "" || lines[0] != lfsVersion {
		return Pointer{}, false
	}
	oid, ok := strings.CutPrefix(lines[1], "oid sha256:")
	if !ok || len(oid) != 64 || strings.ToLower(oid) != oid {
		return Pointer{}, false
	}
	if _, err := hex.DecodeString(oid); err != nil {
		return Pointer{}, false
	}
	size, ok := strings.CutPrefix(lines[2], "size ")
	if !ok || size == "" || size[0] == '+' || len(size) > 1 && size[0] == '0' {
		return Pointer{}, false
	}
	n, err := strconv.ParseInt(size, 10, 64)
	if err != nil || n < 0 {
		return Pointer{}, false
	}
	return Pointer{OID: oid, Size: n}, true
}
