package corpuspkg

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
)

const (
	executionReportMagic    = "ACRPT001"
	executionFooterBytes    = 8 + 8 + sha256.Size
	MaxExecutionReportBytes = 1 << 20
)

// WriteExecutionReport writes the per-attempt report beyond the immutable
// filesystem. Writing the footer last makes incomplete writes detectable.
func WriteExecutionReport(w io.WriterAt, capacity, imageBytes int64, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxExecutionReportBytes || imageBytes <= 0 || capacity-imageBytes < int64(len(raw))+executionFooterBytes || capacity < imageBytes {
		return corpusmeta.Invalid("output drive has no room for the execution report")
	}
	if _, err := corpusmeta.ParseReport(raw); err != nil {
		return err
	}
	var footer [executionFooterBytes]byte
	copy(footer[:8], executionReportMagic)
	binary.BigEndian.PutUint64(footer[8:16], uint64(len(raw)))
	sum := sha256.Sum256(raw)
	copy(footer[16:], sum[:])
	if _, err := w.WriteAt(raw, capacity-int64(len(raw))-executionFooterBytes); err != nil {
		return err
	}
	_, err := w.WriteAt(footer[:], capacity-executionFooterBytes)
	return err
}

// ReadExecutionReport authenticates the bounded bytes and checks that they
// describe this build and its commit before trusting any per-file status.
func ReadExecutionReport(r io.ReaderAt, capacity, imageBytes int64, build, commit string) ([]byte, error) {
	if imageBytes <= 0 || capacity < imageBytes || capacity-imageBytes <= executionFooterBytes {
		return nil, corpusmeta.Invalid("execution report overlaps the image")
	}
	var footer [executionFooterBytes]byte
	if _, err := r.ReadAt(footer[:], capacity-executionFooterBytes); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint64(footer[8:16])
	if string(footer[:8]) != executionReportMagic || n == 0 || n > MaxExecutionReportBytes || n > uint64(capacity-imageBytes-executionFooterBytes) {
		return nil, corpusmeta.Invalid("execution report footer")
	}
	raw := make([]byte, int(n))
	if _, err := r.ReadAt(raw, capacity-executionFooterBytes-int64(n)); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if !bytes.Equal(sum[:], footer[16:]) {
		return nil, corpusmeta.Invalid("execution report digest")
	}
	report, err := corpusmeta.ParseReport(raw)
	if err != nil {
		return nil, err
	}
	if report.BuildID != build || report.Commit != commit {
		return nil, corpusmeta.Invalid("execution report build or commit")
	}
	return raw, nil
}
