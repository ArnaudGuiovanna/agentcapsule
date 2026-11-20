package corpussource

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// The LFS drive's format (ADR 023 §6.2, C3): the worker writes the index at
// the head of lfs.bin, so that it never travels in an invocation.
const (
	// LFSMagic opens the drive.
	LFSMagic = "ACPLFS01"
	// LFSSchema names the index's JSON.
	LFSSchema = "agentcapsule.corpus-lfs/v1"
	// LFSFile and LFSJournal are the drive and its list of verified
	// objects, in a build's staging directory.
	LFSFile    = "lfs.bin"
	LFSJournal = "lfs.verified"
	// lfsBatch is the most objects one batch call asks for.
	lfsBatch = 100
)

// Pointer is an LFS pointer the builder found in the archive: an object's
// sha256 and size.
type Pointer struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

// LFSObject is one entry of the drive's index: the object and where its
// bytes are, from the start of the drive.
type LFSObject struct {
	OID    string `json:"oid"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
}

// LFSIndex is the JSON at the head of the drive.
type LFSIndex struct {
	Schema  string      `json:"schema"`
	Objects []LFSObject `json:"objects"`
}

// LFSDrive is a complete lfs.bin. Bytes is its content's size, up to the end
// of its last object, before the padding to a whole block; SHA256 is the
// sha256 of those bytes, as for an archive.
type LFSDrive struct {
	Objects     int    `json:"objects"`
	ObjectBytes int64  `json:"object_bytes"`
	Bytes       int64  `json:"bytes"`
	SHA256      string `json:"sha256"`
}

var oidPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// LFSLayout checks the pointers against the limits and places them: sorted
// by oid, each once, every object at a block boundary after the head. It
// returns the head (magic, index length, index) and the index. The same
// pointers always give the same layout, so a retry finds its objects where
// the previous attempt wrote them.
func LFSLayout(pointers []Pointer, l Limits) ([]byte, LFSIndex, error) {
	sorted := slices.Clone(pointers)
	slices.SortFunc(sorted, func(a, b Pointer) int { return strings.Compare(a.OID, b.OID) })
	sorted = slices.CompactFunc(sorted, func(a, b Pointer) bool { return a == b })
	if len(sorted) > l.LFSObjects {
		return nil, LFSIndex{}, fmt.Errorf("%w: %d LFS objects, past %d", ErrTooLarge, len(sorted), l.LFSObjects)
	}
	var total int64
	for i, p := range sorted {
		if !oidPattern.MatchString(p.OID) || p.Size < 0 || (i > 0 && sorted[i-1].OID == p.OID) {
			return nil, LFSIndex{}, fmt.Errorf("%w: an LFS pointer", ErrIntegrity)
		}
		if total += p.Size; p.Size > l.LFSBytes || total > l.LFSBytes {
			return nil, LFSIndex{}, fmt.Errorf("%w: LFS objects past %d bytes", ErrTooLarge, l.LFSBytes)
		}
	}
	// The index names the offsets, which depend on the index's length: grow
	// the head until the index fits in it.
	start := int64(Block)
	for {
		idx := LFSIndex{Schema: LFSSchema, Objects: make([]LFSObject, len(sorted))}
		at := start
		for i, p := range sorted {
			idx.Objects[i] = LFSObject{OID: p.OID, Offset: at, Length: p.Size}
			at += Padded(p.Size)
		}
		raw, err := json.Marshal(idx)
		if err != nil {
			return nil, LFSIndex{}, err
		}
		head := append(binary.BigEndian.AppendUint64([]byte(LFSMagic), uint64(len(raw))), raw...)
		if need := Padded(int64(len(head))); need > start {
			start = need
			continue
		}
		return head, idx, nil
	}
}

// lfsEnd is where the drive's content ends: after its last object.
func lfsEnd(head []byte, idx LFSIndex) int64 {
	if n := len(idx.Objects); n > 0 {
		return idx.Objects[n-1].Offset + idx.Objects[n-1].Length
	}
	return int64(len(head))
}

// LFSOptions tune an LFS fetch.
type LFSOptions struct {
	// BeforeBatch, when set, runs before each batch call; an error stops
	// the fetch (the worker's storage pressure check).
	BeforeBatch func() error
	// Fetched, when set, is told the size of each object downloaded, not
	// of those an earlier attempt verified.
	Fetched func(bytes int64)
}

// LFS downloads the pointers' objects into dir/lfs.bin through the forge's
// batch API (POST {repository}.git/info/lfs/objects/batch, download, basic
// transfer, at most 100 objects per call), each from the href the forge
// answers, to the forge or one of the rule's LFS hosts. Each object's size
// and sha256 must be its pointer's, or the fetch fails as ErrIntegrity. An
// object verified by an earlier attempt, listed in dir/lfs.verified once on
// disk, is not downloaded again. Once every object is verified, it hashes
// the drive.
func (f *Fetcher) LFS(ctx context.Context, s Source, token Token, pointers []Pointer, dir string, o LFSOptions) (LFSDrive, error) {
	c, err := f.client(s)
	if err != nil {
		return LFSDrive{}, err
	}
	head, idx, err := LFSLayout(pointers, f.limits)
	if err != nil {
		return LFSDrive{}, err
	}
	if len(idx.Objects) == 0 {
		return LFSDrive{}, nil
	}
	end := lfsEnd(head, idx)
	drive, verified, err := openDrive(dir, head, Padded(end))
	if err != nil {
		return LFSDrive{}, err
	}
	defer drive.Close()
	journal, err := os.OpenFile(filepath.Join(dir, LFSJournal), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return LFSDrive{}, err
	}
	defer journal.Close()
	var missing []LFSObject
	var objectBytes int64
	for _, obj := range idx.Objects {
		objectBytes += obj.Length
		if !verified[obj.OID] {
			missing = append(missing, obj)
		}
	}
	for len(missing) > 0 {
		batch := missing[:min(lfsBatch, len(missing))]
		missing = missing[len(batch):]
		if o.BeforeBatch != nil {
			if err = o.BeforeBatch(); err != nil {
				return LFSDrive{}, err
			}
		}
		err = c.lfsBatch(ctx, s, token, batch, drive, func(obj LFSObject) error {
			// The object is on disk before the journal says so.
			if err := drive.Sync(); err != nil {
				return err
			}
			if _, err := journal.Write([]byte(obj.OID + "\n")); err != nil {
				return err
			}
			if o.Fetched != nil {
				o.Fetched(obj.Length)
			}
			return journal.Sync()
		})
		if err != nil {
			return LFSDrive{}, err
		}
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.NewSectionReader(drive, 0, end)); err != nil {
		return LFSDrive{}, err
	}
	return LFSDrive{Objects: len(idx.Objects), ObjectBytes: objectBytes, Bytes: end, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// openDrive opens dir/lfs.bin for this layout and returns the objects an
// earlier attempt verified. A drive with another head (other pointers) is
// started again, its journal emptied.
func openDrive(dir string, head []byte, size int64) (*os.File, map[string]bool, error) {
	path := filepath.Join(dir, LFSFile)
	journal := filepath.Join(dir, LFSJournal)
	drive, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*os.File, map[string]bool, error) {
		drive.Close()
		return nil, nil, err
	}
	have := make([]byte, len(head))
	n, _ := drive.ReadAt(have, 0)
	st, err := drive.Stat()
	if err != nil {
		return fail(err)
	}
	verified := map[string]bool{}
	if n == len(head) && bytes.Equal(have, head) && st.Size() == size {
		raw, err := os.ReadFile(journal)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail(err)
		}
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for sc.Scan() {
			if oidPattern.MatchString(sc.Text()) {
				verified[sc.Text()] = true
			}
		}
		return drive, verified, nil
	}
	if err = os.Remove(journal); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	if err = drive.Truncate(0); err != nil {
		return fail(err)
	}
	if _, err = drive.WriteAt(head, 0); err != nil {
		return fail(err)
	}
	if err = drive.Truncate(size); err != nil {
		return fail(err)
	}
	if err = drive.Sync(); err != nil {
		return fail(err)
	}
	return drive, verified, syncDir(dir)
}

// batchObject is one object of a batch answer.
type batchObject struct {
	OID     string `json:"oid"`
	Size    int64  `json:"size"`
	Actions struct {
		Download *struct {
			Href   string            `json:"href"`
			Header map[string]string `json:"header"`
		} `json:"download"`
	} `json:"actions"`
	Error *struct {
		Code int `json:"code"`
	} `json:"error"`
}

// lfsBatch asks the batch API for the objects, then downloads each into its
// place in the drive, and calls verified once it checked it.
func (c *client) lfsBatch(ctx context.Context, s Source, token Token, objs []LFSObject, drive *os.File, verified func(LFSObject) error) error {
	type wanted struct {
		OID  string `json:"oid"`
		Size int64  `json:"size"`
	}
	req := struct {
		Operation string   `json:"operation"`
		Transfers []string `json:"transfers"`
		Objects   []wanted `json:"objects"`
		HashAlgo  string   `json:"hash_algo"`
	}{Operation: "download", Transfers: []string{"basic"}, HashAlgo: "sha256"}
	at := map[string]LFSObject{}
	for _, o := range objs {
		req.Objects = append(req.Objects, wanted{o.OID, o.Length})
		at[o.OID] = o
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	raw := c.scheme() + c.rule.Host + "/" + pathEscape(s.Repository) + ".git/info/lfs/objects/batch"
	resp, err := c.do(ctx, http.MethodPost, raw, bytes.NewReader(body), c.basic(token),
		map[string]string{"Accept": "application/vnd.git-lfs+json", "Content-Type": "application/vnd.git-lfs+json"})
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return statusError(resp, "the LFS batch API")
	}
	var answer struct {
		Transfer string        `json:"transfer"`
		Objects  []batchObject `json:"objects"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&answer); err != nil || (answer.Transfer != "" && answer.Transfer != "basic") {
		return fmt.Errorf("%w: the LFS batch answer", ErrUnavailable)
	}
	got := map[string]batchObject{}
	for _, b := range answer.Objects {
		if _, asked := at[b.OID]; asked {
			got[b.OID] = b
		}
	}
	for _, o := range objs {
		b, ok := got[o.OID]
		switch {
		case !ok:
			return fmt.Errorf("%w: the LFS batch answer lacks an object", ErrUnavailable)
		case b.Error != nil && (b.Error.Code == http.StatusNotFound || b.Error.Code == http.StatusGone):
			return fmt.Errorf("%w: an LFS object", ErrNotFound)
		case b.Error != nil && b.Error.Code == http.StatusUnprocessableEntity:
			return fmt.Errorf("%w: the forge refused an LFS pointer", ErrIntegrity)
		case b.Error != nil && (b.Error.Code == http.StatusUnauthorized || b.Error.Code == http.StatusForbidden):
			return fmt.Errorf("%w: an LFS object", ErrDenied)
		case b.Error != nil || b.Actions.Download == nil:
			return fmt.Errorf("%w: no download for an LFS object", ErrUnavailable)
		case b.Size != o.Length:
			return fmt.Errorf("%w: the forge's size of an LFS object", ErrIntegrity)
		}
		if err = c.lfsObject(ctx, b.Actions.Download.Href, b.Actions.Download.Header, token, o, drive); err != nil {
			return err
		}
		if err = verified(o); err != nil {
			return err
		}
	}
	return nil
}

// headerName: an HTTP field name; the forge's download headers are sent as
// they are, to the download's host only.
var headerName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// lfsObject downloads one object into its place in the drive, checking its
// size and its sha256 as it arrives.
func (c *client) lfsObject(ctx context.Context, href string, header map[string]string, token Token, o LFSObject, drive *os.File) error {
	u, err := url.Parse(href)
	if err != nil || !c.lfsURL(u) {
		return fmt.Errorf("%w: an LFS download outside the rule's hosts", ErrPolicy)
	}
	if len(header) > 16 {
		return fmt.Errorf("%w: the LFS download's headers", ErrUnavailable)
	}
	auth, given := "", false
	for k, v := range header {
		if !headerName.MatchString(k) || len(v) > 8192 || !validCredential(v) || strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") ||
			strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Accept-Encoding") || strings.EqualFold(k, "Connection") {
			return fmt.Errorf("%w: the LFS download's headers", ErrUnavailable)
		}
		given = given || strings.EqualFold(k, "Authorization")
	}
	if !given && c.forge(u.Host) {
		// The forge serves the object itself and gave no header: the same
		// credential as the batch call.
		auth = c.basic(token)
	}
	resp, err := c.do(ctx, http.MethodGet, href, nil, auth, header)
	if err != nil {
		return err
	}
	defer drain(resp)
	switch {
	case resp.StatusCode != http.StatusOK:
		return statusError(resp, "an LFS object")
	case encoded(resp):
		return fmt.Errorf("%w: an LFS object came with a content encoding", ErrIntegrity)
	case resp.ContentLength >= 0 && resp.ContentLength != o.Length:
		return fmt.Errorf("%w: an LFS object's size", ErrIntegrity)
	}
	h := sha256.New()
	w := io.NewOffsetWriter(drive, o.Offset)
	n, err := io.Copy(io.MultiWriter(localWriter{w}, h), io.LimitReader(resp.Body, o.Length+1))
	switch {
	case err != nil && isLocal(err):
		return err
	case err != nil:
		return fmt.Errorf("%w: LFS download: %s", ErrUnavailable, redact(err))
	case n != o.Length:
		return fmt.Errorf("%w: an LFS object's size", ErrIntegrity)
	case hex.EncodeToString(h.Sum(nil)) != o.OID:
		return fmt.Errorf("%w: an LFS object's sha256 is not its oid", ErrIntegrity)
	}
	return nil
}

// lfsURL: an object comes from the forge or one of the rule's LFS hosts.
func (c *client) lfsURL(u *url.URL) bool {
	if u.User != nil || !(u.Scheme == "https" || c.rule.Local && u.Scheme == "http") {
		return false
	}
	host := strings.ToLower(u.Host)
	return host == c.rule.Host || slices.Contains(c.rule.LFSHosts, host)
}

// localWriter marks a write error as the host's own.
type localWriter struct{ w io.Writer }

func (l localWriter) Write(p []byte) (int, error) {
	n, err := l.w.Write(p)
	if err != nil {
		err = localError{err}
	}
	return n, err
}

// validCredential: printable ASCII, so that a header value cannot split or
// inject a header.
func validCredential(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] < ' ' || v[i] > '~' {
			return false
		}
	}
	return true
}
