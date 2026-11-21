// Package corpus reads the published agentcapsule.corpus/v1 layout locally.
// Search uses SQLite FTS5; build with the sqlite_fts5 tag.
package corpus

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg"
	_ "github.com/mattn/go-sqlite3"
)

// Mounts is the root holding an agent's read-only corpus mounts.
type Mounts string

const Guest Mounts = "/corpus"

type Passage struct {
	Title    string          `json:"title"`
	Text     string          `json:"text"`
	Document string          `json:"doc_id"`
	Element  string          `json:"element_id"`
	Part     string          `json:"part"`
	Locator  json.RawMessage `json:"locator"`
	Path     string          `json:"source_path"`
	Commit   string          `json:"commit"`
}

func (m Mounts) List() ([]string, error) {
	entries, err := os.ReadDir(string(m))
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	mounts := []string{}
	for _, entry := range entries {
		if entry.IsDir() && corpuspkg.ValidMount(entry.Name()) {
			mounts = append(mounts, entry.Name())
		}
	}
	return mounts, nil
}

// file accepts only regular files in the immutable published layout. Reject
// symlinks, including those in a mount's parent components.
func (m Mounts) file(mount, name string) (string, error) {
	if !corpuspkg.ValidMount(mount) || !filepath.IsLocal(name) {
		return "", errors.New("invalid corpus mount or path")
	}
	root, err := filepath.Abs(string(m))
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, mount, name)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if resolved != path {
		return "", errors.New("unexpected symbolic link in corpus")
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("expected a regular corpus file")
	}
	return path, nil
}

func (m Mounts) read(mount, name string, limit int64) ([]byte, error) {
	path, err := m.file(mount, name)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit || !utf8.Valid(b) {
		return nil, errors.New("invalid corpus text")
	}
	return b, nil
}
func (m Mounts) Index(mount string) (string, error) {
	b, err := m.read(mount, corpuspkg.IndexFile, corpuspkg.MaxIndexBytes)
	return string(b), err
}

var partName = regexp.MustCompile(`^part-[0-9]{3}\.md$`)

func validPart(part string) bool { return partName.MatchString(part) && part != "part-000.md" }
func (m Mounts) Part(mount, document, part string) (string, error) {
	if !corpuspkg.ValidMount(document) || !validPart(part) {
		return "", errors.New("invalid corpus document or part")
	}
	b, err := m.read(mount, filepath.Join(corpuspkg.DocsDir, document, part), 1<<20)
	return string(b), err
}

// Search finds a literal phrase and returns its source commit, document,
// Markdown anchor and original page, sheet range or time interval.
func (m Mounts) Search(ctx context.Context, mount, phrase string, limit int) ([]Passage, error) {
	phrase = strings.TrimSpace(phrase)
	if phrase == "" || len(phrase) > 1024 || strings.ContainsRune(phrase, 0) || limit < 1 || limit > 20 {
		return nil, errors.New("expected a phrase and a limit between 1 and 20")
	}
	b, err := m.read(mount, corpuspkg.InfoFile, corpuspkg.MaxInfoBytes)
	if err != nil {
		return nil, err
	}
	info, err := corpuspkg.ParseInfo(b)
	if err != nil {
		return nil, err
	}
	paths := make(map[string]string, len(info.Documents))
	for _, d := range info.Documents {
		paths[d.ID] = d.Path
	}
	path, err := m.file(mount, corpuspkg.SearchFile)
	if err != nil {
		return nil, err
	}
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=ro&immutable=1&_query_only=1"}
	db, err := sql.Open("sqlite3", uri.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	expr := "\"" + strings.ReplaceAll(phrase, "\"", "\"\"") + "\""
	rows, err := db.QueryContext(ctx, `SELECT title,snippet(passages,1,'','',' … ',32),doc_id,element_id,part,locator FROM passages WHERE passages MATCH ? ORDER BY rank,rowid LIMIT ?`, expr, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hits := []Passage{}
	for rows.Next() {
		var p Passage
		var locator string
		if err = rows.Scan(&p.Title, &p.Text, &p.Document, &p.Element, &p.Part, &locator); err != nil {
			return nil, err
		}
		p.Path, p.Commit = paths[p.Document], info.Commit
		if info.SourcePath != "" && p.Path != "" {
			p.Path = info.SourcePath + "/" + p.Path
		}
		if p.Path == "" || !corpuspkg.ValidMount(p.Element) || !validPart(p.Part) || !json.Valid([]byte(locator)) {
			return nil, fmt.Errorf("invalid corpus passage citation")
		}
		p.Locator = json.RawMessage(locator)
		hits = append(hits, p)
	}
	return hits, rows.Err()
}
