// Package authoritylog is the replication stream of the two authorities
// (docs/adr/005-keys-outside-restored-domain.md, option a). It defines the
// records, the wrapping of secrets to the operator's unlock key, and the
// mutual-TLS link from the primary to the replica on the standby. It holds no
// storage: the restore authority keeps the primary's log and the replica.
//
// One stream carries the writes of both authorities. Each record has an epoch
// and a sequence number, and names the digest of the record before it. The
// replica applies records in order and refuses a gap, an older epoch, or a
// duplicate whose content differs.
package authoritylog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// Version is the record format.
const Version = 1

// Limits of one record and of one request.
const (
	MaxOps     = 64
	MaxArgs    = 8
	MaxRecord  = 64 << 10
	MaxRecords = 64
	maxText    = 512
	maxWrapped = 256
)

// The kinds of an operation.
const (
	// OpStatement is one restore authority statement, by its fixed number.
	OpStatement = "sql"
	// OpKeyCreate allocates a volume key; it carries the key wrapped to the
	// unlock key and a commitment to it, never the key.
	OpKeyCreate = "key_create"
	// OpKeyRevoke destroys a volume key and records its tombstone. The replica
	// removes its wrapped copy in the same transaction.
	OpKeyRevoke = "key_revoke"
)

// ErrRecord marks a malformed or non-canonical record.
var ErrRecord = errors.New("malformed authority record")

// Arg is one argument of a statement: text ("s"), integer ("i") or bytes ("b").
type Arg struct {
	Type  string `json:"t"`
	Text  string `json:"s,omitempty"`
	Int   int64  `json:"i,omitempty"`
	Bytes []byte `json:"b,omitempty"`
}

// Value returns the argument as a database/sql value.
func (a Arg) Value() any {
	switch a.Type {
	case "s":
		return a.Text
	case "i":
		return a.Int
	default:
		return a.Bytes
	}
}

// ArgOf converts a statement argument. Only text, integers and bytes are
// statement arguments in the authorities.
func ArgOf(v any) (Arg, error) {
	switch x := v.(type) {
	case string:
		return Arg{Type: "s", Text: x}, nil
	case int:
		return Arg{Type: "i", Int: int64(x)}, nil
	case int64:
		return Arg{Type: "i", Int: x}, nil
	case uint64:
		if x > 1<<63-1 {
			return Arg{}, ErrRecord
		}
		return Arg{Type: "i", Int: int64(x)}, nil
	case []byte:
		return Arg{Type: "b", Bytes: bytes.Clone(x)}, nil
	}
	return Arg{}, ErrRecord
}

// Op is one operation of a record.
type Op struct {
	Kind       string `json:"op"`
	Statement  int    `json:"stmt,omitempty"`
	Args       []Arg  `json:"args,omitempty"`
	Rows       int64  `json:"rows,omitempty"`
	Agent      string `json:"agent,omitempty"`
	Volume     string `json:"volume,omitempty"`
	Commitment []byte `json:"commitment,omitempty"`
	Wrapped    []byte `json:"wrapped,omitempty"`
}

// HasSecret reports whether the operation carries wrapped key material.
func (o Op) HasSecret() bool { return len(o.Wrapped) > 0 }

// Record is one write of the authorities: the operations of one local
// transaction, applied by the replica in one transaction.
type Record struct {
	Version int    `json:"v"`
	Epoch   uint64 `json:"epoch"`
	Seq     uint64 `json:"seq"`
	Prev    []byte `json:"prev"`
	Ops     []Op   `json:"ops"`
}

// HasSecret reports whether any operation carries wrapped key material.
func (r Record) HasSecret() bool {
	for _, o := range r.Ops {
		if o.HasSecret() {
			return true
		}
	}
	return false
}

// Position is how far a replica has applied the stream. Digest is the digest
// of the record at Seq, or 32 zero bytes at sequence 0.
type Position struct {
	Epoch  uint64 `json:"epoch"`
	Seq    uint64 `json:"seq"`
	Digest []byte `json:"digest"`
}

// Origin is the digest that the first record names as its predecessor.
func Origin() []byte { return make([]byte, 32) }

// ValidID reports whether id is prefix followed by 32 lowercase hex digits,
// the form of the authorities' identities and of agent and volume IDs.
func ValidID(id, prefix string) bool {
	if len(id) != len(prefix)+32 || !strings.HasPrefix(id, prefix) || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id[len(prefix):])
	return err == nil
}

func validText(s string) bool {
	return len(s) <= maxText && !strings.ContainsAny(s, "\x00\r\n")
}

func (o Op) valid() bool {
	switch o.Kind {
	case OpStatement:
		if o.Statement <= 0 || o.Statement > 1000 || len(o.Args) > MaxArgs || o.Rows <= 0 ||
			o.Agent != "" || o.Volume != "" || o.Commitment != nil || o.Wrapped != nil {
			return false
		}
		for _, a := range o.Args {
			switch {
			case a.Type == "s" && validText(a.Text) && a.Int == 0 && a.Bytes == nil:
			case a.Type == "i" && a.Text == "" && a.Bytes == nil:
			case a.Type == "b" && len(a.Bytes) > 0 && len(a.Bytes) <= maxText && a.Text == "" && a.Int == 0:
			default:
				return false
			}
		}
		return true
	case OpKeyCreate:
		return o.Statement == 0 && o.Args == nil && o.Rows == 0 && ValidID(o.Agent, "agt_") && ValidID(o.Volume, "vol_") &&
			len(o.Commitment) == 32 && len(o.Wrapped) > 0 && len(o.Wrapped) <= maxWrapped
	case OpKeyRevoke:
		return o.Statement == 0 && o.Args == nil && o.Rows == 0 && ValidID(o.Agent, "agt_") && ValidID(o.Volume, "vol_") &&
			o.Commitment == nil && o.Wrapped == nil
	}
	return false
}

func (r Record) valid() bool {
	if r.Version != Version || r.Epoch == 0 || r.Seq == 0 || r.Seq > 1<<63-1 || len(r.Prev) != 32 || len(r.Ops) == 0 || len(r.Ops) > MaxOps {
		return false
	}
	for _, o := range r.Ops {
		if !o.valid() {
			return false
		}
	}
	return true
}

// Encode returns the canonical bytes of a valid record. The digest and the
// replica's duplicate check are over these exact bytes.
func (r Record) Encode() ([]byte, error) {
	if !r.valid() {
		return nil, ErrRecord
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) > MaxRecord {
		return nil, ErrRecord
	}
	return b, nil
}

// Decode parses canonical record bytes. Unknown fields, trailing data and any
// encoding other than Encode's are refused.
func Decode(b []byte) (Record, error) {
	var r Record
	if len(b) == 0 || len(b) > MaxRecord {
		return r, ErrRecord
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil || d.More() {
		return Record{}, ErrRecord
	}
	again, err := r.Encode()
	if err != nil || !bytes.Equal(again, b) {
		return Record{}, ErrRecord
	}
	return r, nil
}

// Digest is the digest of canonical record bytes.
func Digest(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte("agentcapsule-authority-record-v1\x00"))
	h.Write(b)
	return h.Sum(nil)
}
