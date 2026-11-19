package hostops

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const repository = "ArnaudGuiovanna/agentcapsule"
const issuer = "https://token.actions.githubusercontent.com"

var releaseVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$`)

func selfUpdate(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] != "update" {
		return errors.New("usage: agentcapsule self update [--to VERSION] [--offline RELEASE_DIRECTORY]")
	}
	flags := flag.NewFlagSet("self update", flag.ContinueOnError)
	flags.SetOutput(errOut)
	version := flags.String("to", "", "release tag (defaults to the latest stable release)")
	offline := flags.String("offline", "", "directory of downloaded release assets")
	trust := flags.String("trusted-root", "", "locally trusted Sigstore trust root for offline use")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected self update arguments")
	}
	client := &http.Client{Timeout: 4 * time.Minute}
	if *version == "" && *offline == "" {
		resp, err := request(ctx, client, "https://api.github.com/repos/"+repository+"/releases/latest")
		if err != nil {
			return err
		}
		defer resp.Close()
		var release struct {
			Tag string `json:"tag_name"`
		}
		if err := json.NewDecoder(io.LimitReader(resp, 2<<20)).Decode(&release); err != nil {
			return err
		}
		*version = release.Tag
	}
	if !releaseVersion.MatchString(*version) {
		return errors.New("a release tag such as v0.1.0-rc.1 is required")
	}
	name := "agentcapsule-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	staging, err := os.MkdirTemp("", "agentcapsule-self-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	fetch := func(name string, target *os.File, max int64) error {
		var src io.ReadCloser
		var err error
		if *offline != "" {
			src, err = os.Open(filepath.Join(*offline, name))
		} else {
			src, err = request(ctx, client, "https://github.com/"+repository+"/releases/download/"+*version+"/"+name)
		}
		if err != nil {
			return err
		}
		defer src.Close()
		n, err := io.Copy(target, io.LimitReader(src, max+1))
		if n > max {
			return errors.New("release asset exceeds size limit")
		}
		return err
	}
	for _, file := range []string{"SHA256SUMS", "SHA256SUMS.sigstore.json"} {
		f, err := os.Create(filepath.Join(staging, file))
		if err != nil {
			return err
		}
		err = fetch(file, f, 8<<20)
		if e := f.Close(); err == nil {
			err = e
		}
		if err != nil {
			return err
		}
	}
	if *offline != "" && *trust == "" {
		*trust = filepath.Join(staging, "trusted-root.json")
		if err := os.WriteFile(*trust, trustedRoot, 0600); err != nil {
			return err
		}
	}
	verify := []string{"verify-blob", "--bundle", filepath.Join(staging, "SHA256SUMS.sigstore.json"), "--certificate-identity", "https://github.com/" + repository + "/.github/workflows/release.yml@refs/tags/" + *version, "--certificate-oidc-issuer", issuer}
	if *trust != "" {
		verify = append(verify, "--trusted-root", *trust, "--offline")
	}
	checksums := filepath.Join(staging, "SHA256SUMS")
	cmd := exec.CommandContext(ctx, "cosign", append(verify, checksums)...)
	cmd.Stdout, cmd.Stderr = errOut, errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("verifying the release signature with cosign: %w", err)
	}
	digest, err := assetDigest(checksums, name)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	dst, err := os.CreateTemp(filepath.Dir(exe), ".agentcapsule-update-")
	if err != nil {
		return err
	}
	defer os.Remove(dst.Name())
	defer dst.Close()
	if err := fetch(name, dst, 256<<20); err != nil {
		return err
	}
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, dst); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return errors.New("CLI digest differs from signed SHA256SUMS")
	}
	if err = dst.Chmod(0755); err != nil {
		return err
	}
	if err = dst.Sync(); err != nil {
		return err
	}
	if err = dst.Close(); err != nil {
		return err
	}
	if err = replaceExecutable(dst.Name(), exe); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]string{"schema": "agentcapsule.host/v1", "version": *version, "path": exe, "sha256": digest})
}

func request(ctx context.Context, client *http.Client, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Scheme != "https" {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTPS download failed: %s", resp.Status)
	}
	return resp.Body, nil
}

func assetDigest(checksums, name string) (string, error) {
	f, err := os.Open(checksums)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var digest string
	lines := bufio.NewScanner(f)
	for lines.Scan() {
		value, file, ok := strings.Cut(lines.Text(), "  ")
		if !ok || file != name {
			continue
		}
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != sha256.Size || digest != "" {
			return "", errors.New("invalid or duplicate signed digest")
		}
		digest = value
	}
	if err := lines.Err(); err != nil {
		return "", err
	}
	if digest == "" {
		return "", fmt.Errorf("%s absent from signed manifest", name)
	}
	return digest, nil
}

func replaceExecutable(staged, current string) error {
	if runtime.GOOS != "windows" {
		return os.Rename(staged, current)
	}
	// Windows permits renaming a running executable but not overwriting it.
	// A unique sibling prevents replacing an unrelated .previous file.
	dir, err := os.MkdirTemp(filepath.Dir(current), ".agentcapsule-previous-")
	if err != nil {
		return err
	}
	old := filepath.Join(dir, filepath.Base(current))
	if err := os.Rename(current, old); err != nil {
		_ = os.Remove(dir)
		return err
	}
	if err := os.Rename(staged, current); err != nil {
		return errors.Join(err, os.Rename(old, current))
	}
	return nil
}
