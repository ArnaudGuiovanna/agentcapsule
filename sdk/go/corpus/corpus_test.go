//go:build sqlite_fts5 || fts5

package corpus_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/agentadapter"
	"github.com/ArnaudGuiovanna/agentcapsule/sdk/go/corpus"
)

// The same immutable files support native Go and Python callers and a
// language-independent stdio client. A hit identifies a source in its commit.
func TestMountedCorpusInteroperability(t *testing.T) {
	root := t.TempDir()
	m := corpus.Mounts(root)
	p := filepath.Join(root, "finance")
	for _, dir := range []string{"search", "docs/d42"} {
		if err := os.MkdirAll(filepath.Join(p, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	const commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const part = "<a id=\"p1\"></a>\nOrion reserves are twenty units."
	info := `{"schema":"agentcapsule.corpus/v1","name":"finance","title":"Finance","build_id":"cbd_00000000000000000000000000000001","commit":"` + commit + `","source_path":"course","builder":"builder@1","languages":["en"],"modalities":["text"],"tokens":4,"documents":[{"id":"d42","path":"finance.pdf","kind":"pdf","title":"Reserves","tokens":4}]}`
	for file, data := range map[string]string{"INDEX.md": "# Finance\n", "corpus.json": info, "docs/d42/part-001.md": part} {
		if err := os.WriteFile(filepath.Join(p, file), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite3", filepath.Join(p, "search", "fts.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE VIRTUAL TABLE passages USING fts5(title,body,doc_id UNINDEXED,element_id UNINDEXED,part UNINDEXED,locator UNINDEXED,tokenize='unicode61');
      INSERT INTO passages VALUES ('Reserves','Orion reserves are twenty units.','d42','p1','part-001.md','{"page":2}');`)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	mounts, err := m.List()
	if err != nil || strings.Join(mounts, "") != "finance" {
		t.Fatal(mounts, err)
	}
	hits, err := m.Search(t.Context(), "finance", "Orion reserves", 5)
	if err != nil || len(hits) != 1 || hits[0].Path != "course/finance.pdf" || hits[0].Commit != commit || string(hits[0].Locator) != `{"page":2}` {
		t.Fatal(hits, err)
	}
	got, err := m.Part("finance", hits[0].Document, hits[0].Part)
	if err != nil || got != part {
		t.Fatal(got, err)
	}
	if _, err = m.Part("finance", "..", "part-001.md"); err == nil {
		t.Fatal("opened an invalid document")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("Python required for cross-language verification", err)
	}
	script := `import sys,json,sqlite3
from agentcapsule_harness import Corpora
c=Corpora(sys.argv[1])
assert c.list()==["finance"] and c.index("finance")=="# Finance\n"
hits=c.search("finance","Orion reserves")
assert c.part("finance",hits[0]["doc_id"],hits[0]["part"]).startswith('<a id="p1">')
db=c.open_search("finance")
try:
    db.execute("delete from passages")
except sqlite3.OperationalError as e:
    assert "readonly" in str(e)
else:
    raise AssertionError("writable index")
finally:
    db.close()
print(json.dumps(hits))`
	cmd := exec.CommandContext(t.Context(), python, "-B", "-c", script, root)
	sdk, err := filepath.Abs("../../python")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(os.Environ(), "PYTHONPATH="+sdk)
	out, err := cmd.CombinedOutput()
	var ph []corpus.Passage
	if err != nil || json.Unmarshal(out, &ph) != nil || len(ph) != 1 || ph[0].Path != hits[0].Path || ph[0].Element != "p1" {
		t.Fatal(string(out), err)
	}
	input := strings.Join([]string{`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"corpus_search","arguments":{"mount":"finance","phrase":"Orion reserves"}}}`}, "\n")
	var output bytes.Buffer
	if err = agentadapter.ServeCorpusMCP(t.Context(), m, strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	var mcp struct {
		Result struct {
			Content []struct{ Text string }
			IsError bool
		}
	}
	if len(lines) != 3 || !strings.Contains(lines[1], "corpus_part") || json.Unmarshal([]byte(lines[2]), &mcp) != nil || mcp.Result.IsError || len(mcp.Result.Content) != 1 {
		t.Fatal(output.String())
	}
	var viaMCP []corpus.Passage
	if json.Unmarshal([]byte(mcp.Result.Content[0].Text), &viaMCP) != nil || fmt.Sprint(viaMCP) != fmt.Sprint(hits) {
		t.Fatal(mcp.Result.Content)
	}
}
