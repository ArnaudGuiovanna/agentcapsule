// agentcapsule-harness builds and publishes harness packages. It runs on a
// developer machine or in CI, never on the platform host:
//
//	agentcapsule-harness pack --manifest harness.yaml --rootfs ./rootfs --size-mib 64 --out ./package
//	agentcapsule-harness push --dir ./package --registry ghcr.io --repository org/echo --tag 1.0.0
//
// push prints the reference pinned by digest, which the platform operator
// imports with POST /v1/harness-imports. The registry password, if any, is
// read from AGENTCAPSULE_REGISTRY_PASSWORD, never from the command line.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agentcapsule-harness pack|push [flags]")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "pack":
		return pack(ctx, args[1:])
	case "push":
		return push(ctx, args[1:])
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func pack(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pack", flag.ContinueOnError)
	manifest := fs.String("manifest", "harness.yaml", "harness manifest")
	rootfs := fs.String("rootfs", "", "directory whose content becomes the read-only harness filesystem")
	size := fs.Int("size-mib", 64, "filesystem size in MiB")
	out := fs.String("out", "", "new output directory for the package")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rootfs == "" || *out == "" {
		return errors.New("--rootfs and --out are required")
	}
	raw, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	m, err := harnesspkg.ParseManifest(raw)
	if err != nil {
		return err
	}
	if err = os.Mkdir(*out, 0o755); err != nil {
		return err
	}
	if err = harnesspkg.BuildRootfs(ctx, m, *rootfs, filepath.Join(*out, harnesspkg.RootfsFile), *size); err != nil {
		return err
	}
	if err = harnesspkg.WritePackage(*out, m); err != nil {
		return err
	}
	fmt.Printf("packed %s %s into %s\n", m.Name, m.Version, *out)
	return nil
}

func push(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	dir := fs.String("dir", "", "package directory written by pack")
	registry := fs.String("registry", "", "registry host, e.g. ghcr.io")
	repository := fs.String("repository", "", "repository, e.g. org/echo")
	tag := fs.String("tag", "", "optional tag; the digest is what the platform pins")
	username := fs.String("username", "", "registry user; password from AGENTCAPSULE_REGISTRY_PASSWORD")
	local := fs.Bool("local", false, "plain HTTP registry on a private network (development only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *registry == "" || *repository == "" {
		return errors.New("--dir, --registry and --repository are required")
	}
	rule := ociregistry.Rule{Host: *registry, Repositories: []string{*repository}, Local: *local,
		Username: *username, Password: os.Getenv("AGENTCAPSULE_REGISTRY_PASSWORD")}
	ref, err := ociregistry.Push(ctx, rule, *repository, *tag, *dir)
	if err != nil {
		return err
	}
	fmt.Println(ref.String())
	return nil
}
