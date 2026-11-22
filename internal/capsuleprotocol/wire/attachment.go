package wire

import (
	"encoding/hex"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Attachment limits. One object is stored as independently authenticated
// segments so the bridge can move it in bounded messages and a segment can be
// read without decrypting the rest.
const (
	AttachmentSegmentBytes   = 256 << 10
	MaxAttachmentBytes       = 8 << 20
	MaxInvocationAttachments = 8
)

var (
	attachmentID   = regexp.MustCompile(`^att_[0-9a-f]{32}$`)
	attachmentType = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$`)
)

// AttachmentRef is everything the guest is told about a file: an opaque id and
// the metadata it must verify the bytes against. No host path, no URL.
type AttachmentRef struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
}

func (a AttachmentRef) Validate() error {
	if !attachmentID.MatchString(a.ID) || !ValidAttachmentName(a.Name) || !attachmentType.MatchString(a.MediaType) ||
		a.Size < 1 || a.Size > MaxAttachmentBytes {
		return ErrProtocol
	}
	if b, err := hex.DecodeString(a.SHA256); err != nil || len(b) != 32 {
		return ErrProtocol
	}
	return nil
}

// ValidAttachmentName accepts a display name only: no path separators, no
// control characters, no "." or "..", valid UTF-8, at most 200 bytes.
func ValidAttachmentName(n string) bool {
	if n == "" || len(n) > 200 || n == "." || n == ".." || !utf8.ValidString(n) || strings.ContainsAny(n, "/\\") {
		return false
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func ValidAttachmentType(t string) bool { return attachmentType.MatchString(t) }
func ValidAttachmentID(id string) bool  { return attachmentID.MatchString(id) }

// AttachmentSegment is one bounded piece of a file.
type AttachmentSegment struct {
	Index int    `json:"index"`
	Total int    `json:"total"`
	Data  []byte `json:"data"`
}
