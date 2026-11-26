package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ociregistry"
)

// printDigest can also report the package's parsed guest identity, so a release
// can bind a named catalog entry to the exact manifest it signs and publishes.
func printDigest(dir, digest string, metadata bool) error {
	if !metadata {
		_, err := fmt.Println(digest)
		return err
	}
	f, err := os.Open(filepath.Join(dir, harnesspkg.ManifestFile))
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, harnesspkg.MaxManifestBytes+1))
	if err != nil {
		return err
	}
	m, err := harnesspkg.ParseManifest(raw)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"digest": digest, "name": m.Name, "version": m.Version, "base": m.Base})
}

func digestPackage(args []string) error {
	fs := flag.NewFlagSet("digest", flag.ContinueOnError)
	dir := fs.String("dir", "", "packed harness")
	pub := fs.String("key", "", "publisher key to verify the offline bundle")
	bundle := fs.String("bundle", "", "offline Sigstore bundle for this package")
	metadata := fs.Bool("json", false, "include the package name, version and guest base")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || (*pub == "") != (*bundle == "") {
		return errors.New("digest needs --dir and takes --key and --bundle together")
	}
	digest, err := ociregistry.PackageDigest(*dir)
	if err != nil {
		return err
	}
	if *pub != "" {
		if _, err := verifiedBundle(digest, *pub, *bundle); err != nil {
			return err
		}
	}
	return printDigest(*dir, digest, *metadata)
}

// Build workers can prepare and verify signed package references without any
// registry credentials. Only public signatures enter the publication job.
func signOffline(args []string) error {
	fs := flag.NewFlagSet("sign-offline", flag.ContinueOnError)
	dir := fs.String("dir", "", "packed harness")
	key := fs.String("key", "", "publisher's PEM private key")
	out := fs.String("out", "", "new Sigstore bundle")
	metadata := fs.Bool("json", false, "include the package name, version and guest base")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *key == "" || *out == "" {
		return errors.New("sign-offline needs --dir, --key and --out")
	}
	digest, err := ociregistry.PackageDigest(*dir)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*key)
	if err != nil {
		return err
	}
	signer, err := parsePrivateKey(raw)
	if err != nil {
		return err
	}
	bundle, err := ociregistry.SignBundle(digest, signer)
	if err != nil {
		return err
	}
	if err = writeNew(*out, bundle, 0644); err != nil {
		return err
	}
	return printDigest(*dir, digest, *metadata)
}

func verifiedBundle(digest, pub, file string) ([]byte, error) {
	bundle, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(pub)
	if err != nil {
		return nil, err
	}
	key, err := ociregistry.ParsePublisherKey(raw)
	if err != nil {
		return nil, err
	}
	_, err = ociregistry.VerifyBundle(bundle, digest, []ociregistry.PublisherKey{key})
	return bundle, err
}

func attachBundle(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	target := fs.String("ref", "", "pinned package reference")
	pub := fs.String("key", "", "trusted publisher public key")
	file := fs.String("bundle", "", "offline Sigstore bundle")
	user := fs.String("username", "", "registry username")
	local := fs.Bool("local", false, "local development registry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ref, err := ociregistry.ParseReference(*target)
	if err != nil {
		return err
	}
	bundle, err := verifiedBundle(ref.Digest, *pub, *file)
	if err != nil {
		return err
	}
	rule := ociregistry.Rule{Host: ref.Registry, Repositories: []string{ref.Repository}, Local: *local, Username: *user, Password: os.Getenv("AGENTCAPSULE_REGISTRY_PASSWORD")}
	digest, err := ociregistry.AttachSignature(ctx, rule, ref, bundle)
	if err == nil {
		fmt.Println(digest)
	}
	return err
}
