package main

import "dagger/agentcapsule/internal/dagger"

// CorpusBuilder builds the CPU-only private builder harness. All document
// parsing tools live in its guest filesystem. The published release may be
// signed with the same Sign method as other harnesses.
func (m *Agentcapsule) CorpusBuilder() *dagger.Directory {
	helper := m.builder().WithEnvVariable("CGO_ENABLED", "0").
		WithExec([]string{"go", "build", "-buildvcs=false", "-trimpath", "-o", "/out/corpus-guest-tool", "./cmd/corpus-guest-tool"}).
		File("/out/corpus-guest-tool")
	root := dag.Container(dagger.ContainerOpts{Platform: platform}).From(pythonImage).
		WithExec([]string{"apk", "add", "--no-cache", "poppler-utils", "libwebp-tools", "libreoffice-writer", "libreoffice-impress", "ffmpeg", "e2fsprogs", "e2fsprogs-extra", "font-dejavu"}).
		WithExec([]string{"python3", "-m", "pip", "install", "--no-cache-dir", "openpyxl==3.1.5", "et-xmlfile==2.0.0"}).
		WithDirectory("/opt/corpus-builder", m.Source.Directory("examples/corpus-builder")).
		WithFile("/opt/corpus-builder/corpus-guest-tool", helper, dagger.ContainerWithFileOpts{Permissions: 0755}).
		WithFile("/opt/corpus-builder/agentcapsule_harness.py", m.Source.File("sdk/python/agentcapsule_harness.py")).
		WithExec([]string{"python3", "-c", "import sqlite3; sqlite3.connect(':memory:').execute('create virtual table t using fts5(v)')"}).
		Rootfs().WithoutDirectory("dev").WithoutDirectory("proc").WithoutDirectory("sys").
		WithNewDirectory("dev").WithNewDirectory("proc").WithNewDirectory("sys")
	return m.Pack(root, m.Source.File("examples/corpus-builder/harness.yaml"), 1792)
}
