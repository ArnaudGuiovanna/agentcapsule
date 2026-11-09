// agentcapsule-harness builds and publishes harness packages. It runs on a
// developer machine or in CI, never on the platform host:
//
//	agentcapsule-harness pack --manifest harness.yaml --rootfs ./rootfs --size-mib 64 --out ./package
//	agentcapsule-harness push --dir ./package --registry ghcr.io --repository org/echo --tag 1.0.0
//	agentcapsule-harness keygen --out ./publisher
//	agentcapsule-harness sign --key ./publisher.key --ref ghcr.io/org/echo@sha256:...
//
// push prints the reference pinned by digest, which the platform operator
// imports with POST /v1/harness-imports. sign attaches a signature in the
// cosign v3 format ("cosign sign --key" works as well); the operator trusts the
// matching public key. The registry password, if any, is read from
// AGENTCAPSULE_REGISTRY_PASSWORD, never from the command line.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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
		return errors.New("usage: agentcapsule-harness pack|push|keygen|sign [flags]")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "pack":
		return pack(ctx, args[1:])
	case "push":
		return push(ctx, args[1:])
	case "keygen":
		return keygen(args[1:])
	case "sign":
		return signPackage(ctx, args[1:])
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

// keygen writes a new ECDSA P-256 publisher key pair: <out>.key (PKCS#8,
// private, never overwritten) and <out>.pub, the key operators trust.
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "path prefix for <out>.key and <out>.pub")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})
	id, err := ociregistry.ParsePublisherKey(pubPEM)
	if err != nil {
		return err
	}
	if err = writeNew(*out+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0o600); err != nil {
		return err
	}
	if err = writeNew(*out+".pub", pubPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s.key (keep private) and %s.pub (key ID %s)\n", *out, *out, id.ID)
	return nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// signPackage signs a pushed package with an unencrypted PKCS#8 or EC private
// key and attaches the signature to it in the registry.
func signPackage(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "PEM private key (PKCS#8 or EC), unencrypted")
	refText := fs.String("ref", "", "package reference pinned by digest, as printed by push")
	username := fs.String("username", "", "registry user; password from AGENTCAPSULE_REGISTRY_PASSWORD")
	local := fs.Bool("local", false, "plain HTTP registry on a private network (development only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *refText == "" {
		return errors.New("--key and --ref are required")
	}
	ref, err := ociregistry.ParseReference(*refText)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	key, err := parsePrivateKey(raw)
	if err != nil {
		return err
	}
	rule := ociregistry.Rule{Host: ref.Registry, Repositories: []string{ref.Repository}, Local: *local,
		Username: *username, Password: os.Getenv("AGENTCAPSULE_REGISTRY_PASSWORD")}
	digest, err := ociregistry.Sign(ctx, rule, ref, key)
	if err != nil {
		return err
	}
	fmt.Printf("signed %s (signature %s)\n", ref.String(), digest)
	return nil
}

func parsePrivateKey(raw []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("the key is not PEM (encrypted cosign keys: use cosign sign --key)")
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	}
	return nil, errors.New("unsupported private key (encrypted cosign keys: use cosign sign --key)")
}
