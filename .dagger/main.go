// Builds, signs and publishes Agent Capsule harness packages.
//
// This is the reference build of harness packages, meant for CI or a
// developer machine, never for the platform host: the host only pulls,
// verifies and boots packages. Every base image is pinned by digest.
//
//	dagger call python-echo export --path=./build/python-echo
//	dagger call go-echo export --path=./build/go-echo
//	dagger call publish --pkg=./build/python-echo --registry=ghcr.io --repository=acme/python-echo \
//	  --tag=1.0.0 --username=acme-bot --password=env:GHCR_TOKEN
//	dagger call sign --ref=ghcr.io/acme/python-echo:1.0.0@sha256:... --key=file:./publisher.key \
//	  --username=acme-bot --password=env:GHCR_TOKEN
//	dagger call check
package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/agentcapsule/internal/dagger"
)

const (
	// Go 1.27.3 on Alpine 3.24: builds agentcapsule-harness and capsule-echo,
	// and packs images with e2fsprogs.
	goImage = "golang:1.27-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18"
	// Same base as examples/python-echo/Dockerfile.
	pythonImage = "python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca"
	// OCI distribution registry for the end-to-end check.
	registryImage = "registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
	platform      = dagger.Platform("linux/amd64")
)

type Agentcapsule struct {
	// Source holds only what builds harnesses: go.mod, go.sum, cmd, internal,
	// sdk and examples.
	Source *dagger.Directory
}

func New(
	// The Agent Capsule repository.
	// +defaultPath="/"
	// +ignore=["*", "!go.mod", "!go.sum", "!cmd", "!internal", "!sdk", "!examples"]
	source *dagger.Directory,
) *Agentcapsule {
	return &Agentcapsule{Source: source}
}

// builder is the Go toolchain with the repository and module caches.
func (m *Agentcapsule) builder() *dagger.Container {
	return dag.Container(dagger.ContainerOpts{Platform: platform}).
		From(goImage).
		WithExec([]string{"apk", "add", "--no-cache", "gcc", "musl-dev", "e2fsprogs", "e2fsprogs-extra"}).
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("agentcapsule-go-mod")).
		WithMountedCache("/root/.cache/go-build", dag.CacheVolume("agentcapsule-go-build")).
		WithEnvVariable("GOFLAGS", "-mod=readonly").
		WithEnvVariable("GOTOOLCHAIN", "local").
		WithDirectory("/src", m.Source).
		WithWorkdir("/src")
}

// Tool returns agentcapsule-harness, the package tool (pack, push, keygen,
// sign, verify), as a static binary.
func (m *Agentcapsule) Tool() *dagger.File {
	return m.builder().
		WithEnvVariable("CGO_ENABLED", "0").
		WithExec([]string{"go", "build", "-trimpath", "-o", "/out/agentcapsule-harness", "./cmd/agentcapsule-harness"}).
		File("/out/agentcapsule-harness")
}

// toolbox is a container with agentcapsule-harness and e2fsprogs on PATH.
func (m *Agentcapsule) toolbox() *dagger.Container {
	return dag.Container(dagger.ContainerOpts{Platform: platform}).
		From(goImage).
		WithExec([]string{"apk", "add", "--no-cache", "e2fsprogs", "e2fsprogs-extra"}).
		WithFile("/usr/local/bin/agentcapsule-harness", m.Tool(), dagger.ContainerWithFileOpts{Permissions: 0o755})
}

// Pack turns a root filesystem and a harness.yaml into a package directory
// (harness.yaml, checksums.json, harness.ext4). Missing mount points are
// created; ownership and timestamps are fixed, so the same inputs give the
// same digest.
func (m *Agentcapsule) Pack(
	// Root filesystem of the harness: its interpreter, libraries and code.
	rootfs *dagger.Directory,
	// The harness manifest.
	manifest *dagger.File,
	// Size of harness.ext4 in MiB.
	// +default=160
	sizeMib int,
) *dagger.Directory {
	return m.toolbox().
		WithDirectory("/rootfs", rootfs).
		WithFile("/harness.yaml", manifest).
		WithExec([]string{"agentcapsule-harness", "pack", "--manifest", "/harness.yaml", "--rootfs", "/rootfs",
			"--size-mib", fmt.Sprint(sizeMib), "--out", "/package"}).
		Directory("/package")
}

// PythonEcho builds the python-echo reference harness package: the pinned
// Python image, the Python SDK and examples/python-echo.
func (m *Agentcapsule) PythonEcho() *dagger.Directory {
	rootfs := dag.Container(dagger.ContainerOpts{Platform: platform}).
		From(pythonImage).
		WithFile("/opt/harness/agentcapsule_harness.py", m.Source.File("sdk/python/agentcapsule_harness.py")).
		WithFile("/opt/harness/harness.py", m.Source.File("examples/python-echo/harness.py")).
		WithExec([]string{"sh", "-c", "python3 -m compileall -q /opt/harness && chmod -R a+rX /opt/harness && mkdir -p /var/lib/agent"}).
		Rootfs().
		// The guest provides its own devices and kernel filesystems.
		WithoutDirectory("dev").WithoutDirectory("proc").WithoutDirectory("sys").
		WithNewDirectory("dev").WithNewDirectory("proc").WithNewDirectory("sys")
	return m.Pack(rootfs, m.Source.File("examples/python-echo/harness.yaml"), 160)
}

// GoEcho builds the Go reference harness package: capsule-echo as a single
// static binary at /opt/echo/harness, nothing else.
func (m *Agentcapsule) GoEcho() *dagger.Directory {
	binary := m.builder().
		WithEnvVariable("CGO_ENABLED", "1").
		WithExec([]string{"go", "build", "-buildvcs=false", "-trimpath", "-tags=netgo,osusergo,sqlite_omit_load_extension",
			"-ldflags=-linkmode external -extldflags '-static'", "-o", "/out/harness", "./cmd/capsule-echo"}).
		File("/out/harness")
	rootfs := dag.Directory().WithFile("opt/echo/harness", binary, dagger.DirectoryWithFileOpts{Permissions: 0o755})
	return m.Pack(rootfs, m.Source.File("examples/go-echo/harness.yaml"), 32)
}

// registryArgs adds the shared registry flags and password.
func registryArgs(c *dagger.Container, args []string, username string, password *dagger.Secret, local bool) (*dagger.Container, []string) {
	if username != "" {
		args = append(args, "--username", username)
	}
	if local {
		args = append(args, "--local")
	}
	if password != nil {
		c = c.WithSecretVariable("AGENTCAPSULE_REGISTRY_PASSWORD", password)
	}
	return c, args
}

// Publish pushes a package directory and returns its reference pinned by
// digest, which the platform operator imports.
func (m *Agentcapsule) Publish(ctx context.Context,
	// Package directory written by pack (or python-echo, go-echo).
	pkg *dagger.Directory,
	// Registry host, e.g. ghcr.io.
	registry string,
	// Repository, e.g. acme/python-echo.
	repository string,
	// Informational tag; the platform pins the digest.
	// +optional
	tag string,
	// +optional
	username string,
	// Registry password or token.
	// +optional
	password *dagger.Secret,
	// Plain HTTP registry on a private network (development only).
	// +optional
	local bool,
) (string, error) {
	c, args := registryArgs(m.toolbox().WithDirectory("/package", pkg),
		[]string{"agentcapsule-harness", "push", "--dir", "/package", "--registry", registry, "--repository", repository}, username, password, local)
	if tag != "" {
		args = append(args, "--tag", tag)
	}
	out, err := c.WithExec(args).Stdout(ctx)
	return strings.TrimSpace(out), err
}

// Sign attaches a publisher signature (cosign v3 format) to a pushed package.
// The key is an unencrypted PKCS#8 or EC private key, passed as a secret.
func (m *Agentcapsule) Sign(ctx context.Context,
	// Package reference pinned by digest, as printed by publish.
	ref string,
	// Publisher private key (PEM).
	key *dagger.Secret,
	// +optional
	username string,
	// +optional
	password *dagger.Secret,
	// +optional
	local bool,
) (string, error) {
	c, args := registryArgs(m.toolbox().WithMountedSecret("/run/secrets/publisher.key", key),
		[]string{"agentcapsule-harness", "sign", "--key", "/run/secrets/publisher.key", "--ref", ref}, username, password, local)
	out, err := c.WithExec(args).Stdout(ctx)
	return strings.TrimSpace(out), err
}

// Verify downloads a package and checks it as the platform's importer would;
// with a key, it also requires a signature by that key. It prints a report.
func (m *Agentcapsule) Verify(ctx context.Context,
	ref string,
	// Trusted publisher public key (PEM).
	// +optional
	key *dagger.File,
	// +optional
	username string,
	// +optional
	password *dagger.Secret,
	// +optional
	local bool,
) (string, error) {
	c := m.toolbox()
	args := []string{"agentcapsule-harness", "verify", "--ref", ref}
	if key != nil {
		c = c.WithFile("/publisher.pub", key)
		args = append(args, "--key", "/publisher.pub")
	}
	c, args = registryArgs(c, args, username, password, local)
	return c.WithExec(args).Stdout(ctx)
}

// Check runs the whole supply chain against a throwaway registry: builds both
// reference harnesses, publishes them, signs them with a new publisher key,
// and verifies each as the platform would, signature required.
func (m *Agentcapsule) Check(ctx context.Context) (string, error) {
	registry := dag.Container(dagger.ContainerOpts{Platform: platform}).
		From(registryImage).
		WithExposedPort(5000).
		AsService(dagger.ContainerAsServiceOpts{UseEntrypoint: true})
	c := m.toolbox().
		WithServiceBinding("registry", registry).
		WithDirectory("/keys", dag.Directory()).
		WithExec([]string{"agentcapsule-harness", "keygen", "--out", "/keys/publisher"})
	var report []string
	for name, pkg := range map[string]*dagger.Directory{"python-echo": m.PythonEcho(), "go-echo": m.GoEcho()} {
		dir := "/packages/" + name
		c = c.WithDirectory(dir, pkg)
		ref, err := c.WithExec([]string{"agentcapsule-harness", "push", "--dir", dir, "--registry", "registry:5000",
			"--repository", "acme/" + name, "--tag", "1.0.0", "--local"}).Stdout(ctx)
		if err != nil {
			return "", err
		}
		ref = strings.TrimSpace(ref)
		// Unsigned, it must be refused when a signature is required.
		unsigned, err := c.WithExec([]string{"agentcapsule-harness", "verify", "--ref", ref, "--key", "/keys/publisher.pub", "--local"},
			dagger.ContainerWithExecOpts{Expect: dagger.ReturnTypeFailure}).Stderr(ctx)
		if err != nil {
			return "", fmt.Errorf("%s: an unsigned package passed verification: %w", name, err)
		}
		if !strings.Contains(unsigned, "signature") {
			return "", fmt.Errorf("%s: unexpected refusal: %s", name, unsigned)
		}
		out, err := c.WithExec([]string{"sh", "-c", "agentcapsule-harness sign --key /keys/publisher.key --ref " + ref + " --local" +
			" && agentcapsule-harness verify --ref " + ref + " --key /keys/publisher.pub --local"}).Stdout(ctx)
		if err != nil {
			return "", err
		}
		report = append(report, name+": "+ref, out)
	}
	return strings.Join(report, "\n"), nil
}
