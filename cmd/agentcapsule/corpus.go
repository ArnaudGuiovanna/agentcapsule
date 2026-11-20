package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg/source"
)

// corpusSourceInvalid: lint found what a build would refuse. Its report is
// on standard output; the command exits 1.
type corpusSourceInvalid struct{ codes []string }

func (e corpusSourceInvalid) Error() string {
	return "a build would refuse this corpus: " + strings.Join(e.codes, ", ")
}

// corpus runs the local corpus commands, which read and write the author's
// own files and call no API: init writes a commented manifest, lint says
// what a build would keep, ignore and process.
func (cli console) corpus(pos []string, o options) error {
	if len(pos) != 3 {
		return usageError{errors.New("use corpus init DIR [--title TEXT] [--language TAG] or corpus lint DIR")}
	}
	dir, err := filepath.Abs(pos[2])
	if err != nil {
		return err
	}
	if pos[1] == "lint" {
		if err = o.done(); err != nil {
			return usageError{err}
		}
		return cli.corpusLint(dir)
	}
	title, language := o.take("title"), o.take("language")
	if err = o.done(); err != nil {
		return usageError{err}
	}
	if title == "" {
		title = filepath.Base(dir)
	}
	if language == "" {
		language = "en"
	}
	manifest, err := source.Template(title, language)
	if err != nil {
		return usageError{fmt.Errorf("choose a --title of 1 to 200 characters and a --language tag such as fr: %w", err)}
	}
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, source.ManifestFile)
	// An existing manifest is the author's: never replace it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err = f.Write(manifest); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return err
	}
	return cli.print(map[string]string{"manifest": path, "title": title, "language": language}, "")
}

func (cli console) corpusLint(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	r, err := source.Scan(os.DirFS(dir), source.Options{Measure: true})
	if err != nil {
		return err
	}
	report := struct {
		Directory string   `json:"directory"`
		Valid     bool     `json:"valid"`
		Title     string   `json:"title,omitempty"`
		Language  string   `json:"language,omitempty"`
		Aliases   []string `json:"aliases"`
		source.Result
	}{Directory: dir, Valid: r.Valid(), Aliases: []string{}, Result: r}
	if r.Manifest != nil {
		report.Title, report.Language, report.Aliases = r.Manifest.Title, r.Manifest.Language, r.Manifest.Aliases()
		if report.Aliases == nil {
			report.Aliases = []string{}
		}
	}
	if err = cli.print(report, ""); err != nil {
		return err
	}
	if !r.Valid() {
		return corpusSourceInvalid{r.Errors.Codes()}
	}
	return nil
}
