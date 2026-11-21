package corpuspkg

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
)

func TestExecutionReportBindsItsBuildOutsideTheFilesystem(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "disk")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const capacity, imageBytes = 8192, 4096
	if err = f.Truncate(capacity); err != nil {
		t.Fatal(err)
	}
	build := "cbd_" + strings.Repeat("a", 32)
	commit := strings.Repeat("b", 40)
	report, err := json.Marshal(corpusmeta.Report{Schema: corpusmeta.ReportSchema, BuildID: build, Commit: commit, Files: []corpusmeta.ReportEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	if err = WriteExecutionReport(f, capacity, imageBytes, report); err != nil {
		t.Fatal(err)
	}
	if raw, err := ReadExecutionReport(f, capacity, imageBytes, build, commit); err != nil || !bytes.Equal(raw, report) {
		t.Fatal("valid report", err)
	}
	if _, err = ReadExecutionReport(f, capacity, imageBytes, "cbd_"+strings.Repeat("c", 32), commit); err == nil {
		t.Fatal("another build")
	}
	if _, err = ReadExecutionReport(f, capacity, capacity-executionFooterBytes-int64(len(report))+1, build, commit); err == nil {
		t.Fatal("overlap")
	}
	if _, err = f.WriteAt([]byte("!"), capacity-executionFooterBytes-int64(len(report))); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadExecutionReport(f, capacity, imageBytes, build, commit); err == nil {
		t.Fatal("tampered report")
	}
}
