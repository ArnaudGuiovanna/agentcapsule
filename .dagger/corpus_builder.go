package main

import (
	"context"

	"dagger/agentcapsule/internal/dagger"
)

// CorpusBuilder builds the CPU-only private builder harness. All document
// parsing tools live in its guest filesystem. The published release may be
// signed with the same Sign method as other harnesses.
func (m *Agentcapsule) CorpusBuilder(ctx context.Context,
	// Harness version for an official distribution, e.g. 0.1.6.
	// +optional
	releaseVersion string,
) (*dagger.Directory, error) {
	manifest, err := releaseManifest(ctx, m.Source.File("examples/corpus-builder/harness.yaml"), releaseVersion)
	if err != nil {
		return nil, err
	}
	helper := m.builder().WithEnvVariable("CGO_ENABLED", "0").
		WithExec([]string{"go", "build", "-buildvcs=false", "-trimpath", "-o", "/out/corpus-guest-tool", "./cmd/corpus-guest-tool"}).
		File("/out/corpus-guest-tool")
	ubuntu := dag.Container(dagger.ContainerOpts{Platform: platform}).
		From("ubuntu:26.04@sha256:0d5255be560e2d2ddcfbfda88549e9e815ef29e7cd7fc62183d5709e6e2963c6").
		WithEnvVariable("DEBIAN_FRONTEND", "noninteractive").
		WithExec([]string{"apt-get", "update"})
	root := ubuntu.WithMountedFile("/tmp/ffmpeg.deb", m.corpusFFmpeg(ubuntu)).
		WithExec([]string{"apt-get", "install", "-y", "--no-install-recommends", "python3", "python3-openpyxl", "poppler-utils", "webp", "libreoffice-writer", "libreoffice-impress", "/tmp/ffmpeg.deb", "e2fsprogs", "fonts-dejavu-core"}).
		WithExec([]string{"sh", "-ec", "apt-get clean; rm -rf /var/lib/apt/lists/*; ln -s /usr/bin/python3 /usr/local/bin/python3"}).
		WithDirectory("/opt/corpus-builder", m.Source.Directory("examples/corpus-builder"), dagger.ContainerWithDirectoryOpts{Include: []string{"*.py"}}).
		WithFile("/opt/corpus-builder/corpus-guest-tool", helper, dagger.ContainerWithFileOpts{Permissions: 0755}).
		WithFile("/opt/corpus-builder/agentcapsule_harness.py", m.Source.File("sdk/python/agentcapsule_harness.py")).
		WithExec([]string{"python3", "-c", "import sqlite3; sqlite3.connect(':memory:').execute('create virtual table t using fts5(v)')"}).
		Rootfs().WithoutDirectory("dev").WithoutDirectory("proc").WithoutDirectory("sys").
		WithNewDirectory("dev").WithNewDirectory("proc").WithNewDirectory("sys")
	return m.Pack(root, manifest, 1792), nil
}

// Use the signed upstream release for these networkless, local-file decoders.
// Installing it through dpkg retains its version, provenance and inventory.
func (m *Agentcapsule) corpusFFmpeg(ubuntu *dagger.Container) *dagger.File {
	const archive = "https://ffmpeg.org/releases/ffmpeg-9.1.tar.xz"
	const key = "https://ffmpeg.org/ffmpeg-devel.asc"
	return ubuntu.WithExec([]string{"apt-get", "install", "-y", "--no-install-recommends", "build-essential", "pkg-config", "nasm", "xz-utils", "gpg", "gpgv", "zlib1g-dev", "liblzma-dev", "libbz2-dev", "libmp3lame-dev", "libdav1d-dev", "libopus-dev"}).
		WithWorkdir("/build").
		WithFile("ffmpeg-9.1.tar.xz", dag.HTTP(archive, dagger.HTTPOpts{Checksum: "sha256:1a4d394ae63d190a526cd052eb4415c156b5c5e2df37efab41a7de0b8fde2433"})).
		WithFile("ffmpeg-9.1.tar.xz.asc", dag.HTTP(archive+".asc", dagger.HTTPOpts{Checksum: "sha256:8c0bf6017492434e11766c6cc841b30e4a6b31e896eaf813de0acd05757fd50e"})).
		WithFile("ffmpeg-devel.asc", dag.HTTP(key, dagger.HTTPOpts{Checksum: "sha256:397b3becedcd5a98769967ff1ff8501ddc89f8368b8f766e4701377d7dbaabe5"})).
		WithFile("build-ffmpeg.sh", m.Source.File("examples/corpus-builder/build-ffmpeg.sh")).
		WithExec([]string{"sh", "build-ffmpeg.sh"}).
		File("/build/ffmpeg.deb")
}
