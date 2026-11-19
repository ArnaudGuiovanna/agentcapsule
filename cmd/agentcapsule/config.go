package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

const maxDocument = 4 << 20

func validName(s string) bool {
	// These device names remain reserved even with a filename extension.
	if !namePattern.MatchString(s) || strings.HasSuffix(s, ".") {
		return false
	}
	base := strings.ToUpper(strings.Split(s, ".")[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL":
		return false
	}
	return !(len(base) == 4 && (base[:3] == "COM" || base[:3] == "LPT") && base[3] >= '1' && base[3] <= '9')
}

type connection struct {
	URL          string `json:"url"`
	Kind         string `json:"kind"`
	Organization string `json:"organization,omitempty"`
	CA           string `json:"ca_file,omitempty"`
	Token        string `json:"token,omitempty"`
	Pending      string `json:"pending_token,omitempty"`
}

func (c connection) public() connection { c.Token = ""; c.Pending = ""; return c }
func (c connection) validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return errors.New("context URL must be an HTTPS origin")
	}
	if c.Kind != "organization" && c.Kind != "platform" || (c.Kind == "organization") != (c.Organization != "") {
		return errors.New("use platform or organization with --organization ID")
	}
	return nil
}
func configDir() (string, error) {
	dir := os.Getenv("AGENTCAPSULE_CONFIG_DIR")
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, "agentcapsule")
	}
	if !filepath.IsAbs(dir) {
		return "", errors.New("configuration directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !st.IsDir() || runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
		return "", errors.New("configuration directory must be private (0700)")
	}
	return dir, nil
}
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("input exceeds size limit")
	}
	return b, err
}
func readFile(path string, private bool) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || private && runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s must be a regular%s file", path, map[bool]string{true: " private (0600)"}[private])
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !os.SameFile(st, current) {
		return nil, errors.New("file changed while opening")
	}
	return readBounded(f, maxDocument)
}
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".agentcapsule-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func contextPath(dir, name string) string { return filepath.Join(dir, "context-"+name+".json") }
func loadContext(dir, name string) (connection, error) {
	var c connection
	if !validName(name) {
		return c, errors.New("invalid context name")
	}
	raw, err := readFile(contextPath(dir, name), true)
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(raw, &c); err != nil {
		return c, errors.New("invalid context file")
	}
	return c, c.validate()
}
func saveContext(dir, name string, c connection) error {
	if !validName(name) {
		return errors.New("invalid context name")
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return writeFile(contextPath(dir, name), data)
}
func currentName(dir, name string) (string, error) {
	if name != "" {
		if validName(name) {
			return name, nil
		}
		return "", errors.New("invalid context name")
	}
	raw, err := readFile(filepath.Join(dir, "current"), true)
	if err != nil || !validName(string(bytes.TrimSpace(raw))) {
		return "", errors.New("select a context using --context NAME or context use NAME")
	}
	return string(bytes.TrimSpace(raw)), nil
}
