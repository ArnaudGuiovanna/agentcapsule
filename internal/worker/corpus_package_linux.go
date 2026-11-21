//go:build linux

package worker

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpuspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ext4image"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// catCorpusFile runs the same confined debugfs used for inspection. The
// directory entry supplies the expected size, so capped output is never
// accepted as a complete review file.
func catCorpusFile(ctx context.Context, sb sandbox.Options, debugfs, image, path string, max int) ([]byte, error) {
	if !ext4image.Quotable(path) {
		return nil, controlplane.ErrInput
	}
	entry, found, err := ext4image.Stat(ctx, sb, debugfs, image, "/"+path)
	if err != nil {
		return nil, err
	}
	if !found || !entry.IsRegular() || entry.Size < 0 || entry.Size > int64(min(max, sandbox.MaxOutput)) {
		return nil, controlplane.ErrInput
	}
	data, err := sb.Run(ctx, image, debugfs, "-R", `cat "/`+path+`"`, sandbox.ImagePath)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != entry.Size {
		return nil, controlplane.ErrInput
	}
	return data, nil
}
func (g corpusGuest) finishImage(ctx context.Context, j controlplane.CorpusWork, uuid, builderDigest, output string, size int64, extension *controlplane.CorpusExtensionWork) (string, error) {
	f, err := os.OpenFile(output, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "invalid_image", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "invalid_image", err
	}
	if !st.Mode().IsRegular() || size > st.Size() {
		return "invalid_image", controlplane.ErrInput
	}
	var execution []byte
	if extension == nil {
		execution, err = corpuspkg.ReadExecutionReport(f, st.Size(), size, j.ID, j.Commit)
		if err != nil {
			return "invalid_image", err
		}
	}
	maxBytes := int64(g.source.MaxImageMiB) << 20
	if err = corpuspkg.CheckImage(f, size, maxBytes, uuid); err != nil {
		return "invalid_image", err
	}
	cache := g.w.corpusCache
	name, version, _ := strings.Cut(j.Builder, "@")
	if err = os.MkdirAll(cache.root, 0700); err != nil {
		return "unavailable", err
	}
	tmp, err := os.MkdirTemp(cache.root, ".package-")
	if err != nil {
		return "unavailable", err
	}
	defer removeTree(tmp)
	destination, err := os.OpenFile(filepath.Join(tmp, corpuspkg.ImageFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "unavailable", err
	}
	_, err = io.Copy(destination, readerWithContext{ctx, io.NewSectionReader(f, 0, size)})
	// The confined inspector reopens the inherited descriptor after dropping
	// to its dedicated UID. The staging directory remains private to the worker.
	if err == nil {
		err = destination.Chmod(0o444)
	}
	if closeErr := destination.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "unavailable", err
	}
	image := filepath.Join(tmp, corpuspkg.ImageFile)
	var bundle map[string][]byte
	var truncated bool
	if extension == nil {
		bundle, truncated, err = g.readCorpusReview(ctx, j, image, execution)
	} else {
		err = corpuspkg.InspectExtension(ctx, image, g.inspection)
	}
	if err != nil {
		return "invalid_image", err
	}
	manifest := corpuspkg.PackageManifest{Schema: corpuspkg.Schema, Name: j.Name, BuildID: j.ID, Commit: j.Commit, Builder: corpuspkg.Builder{Name: name, Version: version, Digest: builderDigest}, Base: corpuspkg.GuestBase, UUID: uuid, Bytes: size}
	digest, err := corpuspkg.WritePackage(tmp, manifest, maxBytes)
	if err != nil {
		return "invalid_image", err
	}
	err = cache.withLock(ctx, func() error {
		dir := cache.dir(digest)
		if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
			return err
		}
		_, err := os.Lstat(dir)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if err = os.Rename(tmp, dir); err != nil {
				return err
			}
			if err = os.Chmod(dir, 0555); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			m, actual, err := corpuspkg.ReadPackage(dir, maxBytes)
			if err != nil || actual != digest || m.UUID != uuid {
				return controlplane.ErrCorpusUnavailable
			}
		}
		if extension != nil {
			return g.w.store.SettleCorpusExtension(ctx, *extension, &controlplane.CorpusExtensionImage{Name: extension.Name, UUID: uuid, Digest: digest, Bytes: size}, "")
		}
		return g.transit.CompleteCorpusReview(ctx, j, controlplane.CorpusResult{UUID: uuid, Digest: digest, Bytes: size, Files: bundle, Truncated: truncated})
	})
	if err != nil {
		return "", err
	}
	return "", removeTree(filepath.Dir(output))
}

func (g corpusGuest) readCorpusReview(ctx context.Context, j controlplane.CorpusWork, image string, execution []byte) (map[string][]byte, bool, error) {
	if err := corpuspkg.InspectImage(ctx, image, g.inspection); err != nil {
		return nil, false, err
	}
	debugfs, err := ext4image.Debugfs()
	if err != nil {
		return nil, false, err
	}
	read := func(path string, max int) ([]byte, error) {
		return catCorpusFile(ctx, g.inspection, debugfs, image, path, max)
	}
	metadata, err := read("corpus.json", sandbox.MaxOutput)
	if err != nil {
		return nil, false, err
	}
	info, err := corpuspkg.ParseInfo(metadata)
	if err != nil || info.Name != j.Name || info.Commit != j.Commit || info.Builder != j.Builder || info.SourcePath != j.Path {
		return nil, false, controlplane.ErrInput
	}
	bundle := map[string][]byte{}
	if bundle["INDEX.md"], err = read("INDEX.md", 64<<10); err != nil {
		return nil, false, err
	}
	raw, err := read("report.json", sandbox.MaxOutput)
	if err != nil {
		return nil, false, err
	}
	report, err := corpuspkg.ParseReport(raw)
	if err != nil || report.Commit != j.Commit {
		return nil, false, controlplane.ErrInput
	}
	bundle["report.json"] = execution
	total := len(bundle["INDEX.md"]) + len(bundle["report.json"])
	truncated := false
	for _, doc := range info.Documents {
		path := "docs/" + doc.ID + "/README.md"
		data, err := read(path, sandbox.MaxOutput)
		if err != nil {
			return nil, false, err
		}
		if len(data) > 8<<20-total {
			truncated = true
			break
		}
		bundle[path] = data
		total += len(data)
	}
	return bundle, truncated, nil
}
