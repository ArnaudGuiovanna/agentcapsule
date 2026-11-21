package corpusbuilder

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg/source"
)

func TestScanReadsTheCheckedDriveOnlyOnce(t *testing.T) {
	manifest, err := source.Template("Course", "fr")
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": strings.Repeat("b", 40)}}); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"forge-sha/notes/agentcapsule-corpus.yaml": manifest, "forge-sha/notes/ch1.md": []byte("Markets\n"), "forge-sha/other.md": []byte("Elsewhere\n")} {
		if err = tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0644}); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = gz.Close(); err != nil {
		t.Fatal(err)
	}
	guest := Guest{DataDir: t.TempDir(), DeviceDir: t.TempDir()}
	dev := filepath.Join(guest.DeviceDir, "source")
	body := archive.Bytes()
	if err = os.WriteFile(dev, append(bytes.Clone(body), make([]byte, 4096)...), 0600); err != nil {
		t.Fatal(err)
	}
	req := ScanRequest{Schema: Schema, Phase: "scan", BuildID: "cbd_" + strings.Repeat("a", 32), Name: "course", Builder: "builder@1.0.0", Path: "notes", Commit: strings.Repeat("b", 40), Source: Drive{int64(len(body)), fmt.Sprintf("%x", sha256.Sum256(body))}}
	bad := req
	bad.Source.SHA256 = strings.Repeat("0", 64)
	if _, err = guest.Scan(t.Context(), bad); err == nil {
		t.Fatal("accepted different source bytes")
	}
	reply, err := guest.Scan(t.Context(), req)
	if err != nil || reply.Manifest != "valid" || reply.Files.Included != 1 || reply.Kinds[source.KindMarkdown] != 1 {
		t.Fatalf("scan %+v: %v", reply, err)
	}
	if err = os.Remove(dev); err != nil {
		t.Fatal(err)
	}
	if _, err = guest.Scan(t.Context(), req); err != nil {
		t.Fatal("checkpoint replay", err)
	}
	if _, err = guest.Scan(t.Context(), bad); err == nil {
		t.Fatal("changed source under a committed build")
	}
}

func TestScanPagesDistinctPointers(t *testing.T) {
	s := source.Result{Manifest: &source.Manifest{}}
	for i := 0; i < 257; i++ {
		s.LFS = append(s.LFS, source.Pointer{OID: fmt.Sprintf("%064x", i), Size: 300})
	}
	first, err := scanPage(s, "")
	if err != nil || len(first.LFS) != 256 || first.NextCursor != "256" {
		t.Fatal(first.NextCursor, err)
	}
	last, err := scanPage(s, first.NextCursor)
	if err != nil || len(last.LFS) != 1 || last.LFS[0] != s.LFS[256] || last.NextCursor != "" {
		t.Fatal(last, err)
	}
	if _, err = scanPage(s, "257"); err == nil {
		t.Fatal("accepted invalid cursor")
	}
}
