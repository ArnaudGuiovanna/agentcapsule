// Package lukstest rewrites the metadata of a LUKS2 header, as a guest that
// holds its volume open could: for tests of the checks that read a header
// a guest may have written (S-21).
package lukstest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
)

// The binary header of a LUKS2 copy (cryptsetup's luks2_hdr_disk): the
// magic, the size of the copy (binary header and JSON area), its checksum
// algorithm, and its checksum, over the whole copy with the checksum field
// zeroed. The JSON area follows the first 4096 bytes.
const (
	binarySize     = 4096
	sizeOffset     = 8
	checksumAlg    = 72
	checksumOffset = 448
	checksumSize   = 64
)

// RewriteMetadata replaces the JSON metadata of both copies of the LUKS2
// header of the file at path with what edit makes of it, and writes their
// checksums again: libcryptsetup loads the result as a valid header.
// Numbers keep their exact value (json.Number).
func RewriteMetadata(path string, edit func(metadata map[string]any)) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	first := make([]byte, binarySize)
	if _, err = f.ReadAt(first, 0); err != nil {
		return err
	}
	if !bytes.Equal(first[:6], []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}) || binary.BigEndian.Uint16(first[6:8]) != 2 {
		return errors.New("lukstest: not a LUKS2 header")
	}
	size := int64(binary.BigEndian.Uint64(first[sizeOffset:]))
	if size <= binarySize || size > 4<<20 {
		return errors.New("lukstest: header size")
	}
	for _, offset := range []int64{0, size} {
		copyBytes := make([]byte, size)
		if _, err = f.ReadAt(copyBytes, offset); err != nil {
			return err
		}
		if string(bytes.TrimRight(copyBytes[checksumAlg:checksumAlg+32], "\x00")) != "sha256" {
			return errors.New("lukstest: checksum algorithm")
		}
		area := copyBytes[binarySize:]
		d := json.NewDecoder(bytes.NewReader(bytes.TrimRight(area, "\x00")))
		d.UseNumber()
		var metadata map[string]any
		if err = d.Decode(&metadata); err != nil {
			return err
		}
		edit(metadata)
		rewritten, err := json.Marshal(metadata)
		if err != nil {
			return err
		}
		if len(rewritten) >= len(area) {
			return errors.New("lukstest: the metadata outgrows its area")
		}
		clear(area)
		copy(area, rewritten)
		clear(copyBytes[checksumOffset : checksumOffset+checksumSize])
		sum := sha256.Sum256(copyBytes)
		copy(copyBytes[checksumOffset:], sum[:])
		if _, err = f.WriteAt(copyBytes, offset); err != nil {
			return err
		}
	}
	return f.Sync()
}

// Object returns the JSON object at the path of keys in metadata, or nil.
func Object(metadata map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		next, ok := metadata[k].(map[string]any)
		if !ok {
			return nil
		}
		metadata = next
	}
	return metadata
}
