package hostops

import (
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
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

const bootstrapDir = "/var/lib/agentcapsule-userspace"
const pythonWrapper = bootstrapDir + "/python/bin/python3"
const portableArchive = "agentcapsule-userspace-linux-amd64.tar.gz"
const bootstrapCosignSHA = "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa"

type bootstrapOptions struct {
	version, offline, key, trust string
	allowOlder                   bool
}

func bootstrapArgs(args []string) (bootstrapOptions, error) {
	var o bootstrapOptions
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&o.version, "to", Version, "release tag")
	flags.StringVar(&o.offline, "offline", "", "media directory")
	flags.StringVar(&o.key, "development-key", "", "development public key")
	flags.StringVar(&o.trust, "trusted-root", "", "offline trust root")
	flags.BoolVar(&o.allowOlder, "allow-older", false, "allow older release")
	flags.String("profile", "", "installation profile")
	flags.Bool("plan-only", false, "prepare a plan")
	flags.Bool("follow-install", false, "wait for installation")
	if err := flags.Parse(args[1:]); err != nil {
		return o, err
	}
	if flags.NArg() != 0 {
		return o, errors.New("unexpected install argument")
	}
	return o, nil
}

// Enforce any trust material already pinned by a previous plan before
// executing code from the image, including after an interrupted bootstrap.
func checkBootstrapPin(record, input string) error {
	pin, err := os.ReadFile(record)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	data, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if string(pin) != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("bootstrap input differs from pinned %s", filepath.Base(record))
	}
	return nil
}

// Install the interpreter from the same signed release as the control plane.
// Used on minimal hosts only. The resulting executable is also used at reboot.
func bootstrapPython(ctx context.Context, args []string, log io.Writer) (string, error) {
	if path, err := exec.LookPath(pythonWrapper); err == nil {
		return path, nil
	}
	if args[0] != "install" || os.Geteuid() != 0 {
		return "", errors.New("run agentcapsule install as an administrator to bootstrap its private interpreter")
	}
	if runtime.GOARCH != "amd64" {
		return "", errors.New("this server release requires x86-64 Linux")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return "", errors.New("enable systemd on the Linux host")
	}
	if st, err := os.Stat("/dev/kvm"); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New("enable virtualization and expose /dev/kvm on the Linux host")
	}
	o, err := bootstrapArgs(args)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 20 * time.Minute}
	if o.version == "development" && o.offline == "" {
		body, err := request(ctx, client, "https://api.github.com/repos/"+repository+"/releases/latest")
		if err != nil {
			return "", err
		}
		defer body.Close()
		var release struct {
			Tag string `json:"tag_name"`
		}
		if err = json.NewDecoder(io.LimitReader(body, 1<<20)).Decode(&release); err != nil {
			return "", err
		}
		o.version = release.Tag
	}
	if !releaseVersion.MatchString(o.version) {
		return "", errors.New("specify a release tag with --to")
	}
	if releaseVersion.MatchString(Version) && !o.allowOlder {
		order, err := compareVersions(o.version, Version)
		if err != nil {
			return "", err
		}
		if order < 0 {
			return "", errors.New("older release requires --allow-older")
		}
	}
	if err = os.MkdirAll(bootstrapDir, 0700); err != nil {
		return "", err
	}
	lock, err := os.OpenFile(bootstrapDir+"/python.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return "", err
	}
	if path, err := exec.LookPath(pythonWrapper); err == nil {
		return path, nil
	}
	stage, err := os.MkdirTemp(bootstrapDir, ".python-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	fetch := func(name, url, digest string, limit int64) error {
		var src io.ReadCloser
		var err error
		if o.offline != "" {
			src, err = os.Open(filepath.Join(o.offline, name))
		} else {
			src, err = request(ctx, client, url)
		}
		if err != nil {
			return err
		}
		defer src.Close()
		f, err := os.OpenFile(filepath.Join(stage, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		hash := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(f, hash), io.LimitReader(src, limit+1))
		closeErr := f.Close()
		if err = errors.Join(copyErr, closeErr); err != nil {
			return err
		}
		if n > limit || (digest != "" && hex.EncodeToString(hash.Sum(nil)) != digest) {
			return fmt.Errorf("invalid size or digest for %s", name)
		}
		return nil
	}
	base := "https://github.com/" + repository + "/releases/download/" + o.version + "/"
	sums := filepath.Join(stage, "SHA256SUMS")
	if err = fetch("SHA256SUMS", base+"SHA256SUMS", "", 8<<20); err != nil {
		return "", err
	}
	run := func(name string, argv ...string) error {
		cmd := exec.CommandContext(ctx, name, argv...)
		cmd.Stdout, cmd.Stderr = log, log
		return cmd.Run()
	}
	hostState := "/var/lib/agentcapsule-install"
	if err = checkBootstrapPin(filepath.Join(hostState, "downloads", o.version, "verified-manifest.sha256"), sums); err != nil {
		return "", err
	}
	if !o.allowOlder {
		data, e := os.ReadFile(filepath.Join(hostState, "highest-release.json"))
		if e == nil {
			var record struct{ Version string }
			if e = json.Unmarshal(data, &record); e != nil {
				return "", e
			}
			order, e := compareVersions(o.version, record.Version)
			if e != nil {
				return "", e
			}
			if order < 0 {
				return "", errors.New("release is older than the recorded host release; pass --allow-older")
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return "", e
		}
	}
	if o.key != "" {
		if o.offline == "" || !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-dev\.[0-9]+$`).MatchString(o.version) {
			return "", errors.New("development trust requires an offline -dev.N release")
		}
		if err = checkBootstrapPin(filepath.Join(hostState, "development-key.sha256"), o.key); err != nil {
			return "", err
		}
		// Never introduce a new development key into an existing installation.
		for _, installed := range []string{"/opt/agentcapsule", "/var/lib/agentcapsule-install/active-release.json", bootstrapDir + "/system"} {
			if _, e := os.Lstat(installed); e == nil || !errors.Is(e, os.ErrNotExist) {
				return "", errors.New("cannot bootstrap with a development key on an installed host")
			}
		}
		if err = fetch("SHA256SUMS.dev.sig", "", "", 1024); err != nil {
			return "", err
		}
		err = run("/usr/bin/openssl", "pkeyutl", "-verify", "-pubin", "-inkey", o.key, "-rawin", "-in", sums, "-sigfile", filepath.Join(stage, "SHA256SUMS.dev.sig"))
	} else {
		bundle := filepath.Join(stage, "SHA256SUMS.sigstore.json")
		if err = fetch("SHA256SUMS.sigstore.json", base+"SHA256SUMS.sigstore.json", "", 8<<20); err != nil {
			return "", err
		}
		if err = fetch("cosign-linux-amd64", "https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64", bootstrapCosignSHA, 240<<20); err != nil {
			return "", err
		}
		verifier := filepath.Join(stage, "cosign-linux-amd64")
		if err = os.Chmod(verifier, 0700); err != nil {
			return "", err
		}
		flags := cosignVerification(bundle, o.version)
		if o.offline != "" {
			if o.trust == "" {
				o.trust = filepath.Join(stage, "trust.json")
				if err = os.WriteFile(o.trust, trustedRoot, 0600); err != nil {
					return "", err
				}
			}
			flags = append(flags, "--offline", "--trusted-root", o.trust)
		}
		if err = run(verifier, append(flags, sums)...); err == nil {
			err = checkSigningEnvironment(bundle, sums, o.version)
		}
	}
	if err != nil {
		return "", fmt.Errorf("verifying bootstrap release: %w", err)
	}
	digest, err := assetDigest(sums, portableArchive)
	if err != nil {
		return "", err
	}
	fmt.Fprintln(log, "Installing the signed private interpreter for "+o.version)
	if err = fetch(portableArchive, base+portableArchive, digest, 2<<30); err != nil {
		return "", err
	}
	root := filepath.Join(stage, "python")
	if err = os.MkdirAll(root+"/root", 0700); err != nil {
		return "", err
	}
	if err = run("/usr/bin/tar", "--numeric-owner", "-xpf", filepath.Join(stage, portableArchive), "-C", root+"/root"); err != nil {
		return "", err
	}
	// Run the same host probes with the staged interpreter before committing
	// it to disk. The loader runs against the real host kernel and mounts.
	libs := filepath.Join(root, "root/usr/lib/x86_64-linux-gnu")
	check := string(capabilities) + "\nportable_host_preflight(Path('/var/lib/agentcapsule-userspace'))"
	if err = run(filepath.Join(libs, "ld-linux-x86-64.so.2"), "--library-path", libs, filepath.Join(root, "root/usr/bin/python3"), "-I", "-c", check); err != nil {
		return "", err
	}
	if err = os.Mkdir(root+"/bin", 0700); err != nil {
		return "", err
	}
	const lib = bootstrapDir + "/python/root/usr/lib/x86_64-linux-gnu"
	script := "#!/bin/sh\nexec " + lib + "/ld-linux-x86-64.so.2 --library-path " + lib + " " + bootstrapDir + "/python/root/usr/bin/python3 \"$@\"\n"
	if err = os.WriteFile(root+"/bin/python3", []byte(script), 0700); err != nil {
		return "", err
	}
	if err = run("/usr/bin/sync", "-f", root); err != nil {
		return "", err
	}
	if err = os.Rename(root, bootstrapDir+"/python"); err != nil {
		return "", err
	}
	// Reuse large verified downloads. The Python controller rechecks these
	// against the signed index, including candidates left by interrupted runs.
	cache := filepath.Join(hostState, "downloads", o.version)
	if os.MkdirAll(cache, 0700) == nil {
		_ = os.Link(filepath.Join(stage, portableArchive), filepath.Join(cache, portableArchive))
		if o.key == "" {
			_ = os.Link(filepath.Join(stage, "cosign-linux-amd64"), filepath.Join(hostState, "cosign"))
		}
	}
	return pythonWrapper, nil
}

func localController(ctx context.Context, forwarded []string, encoded string, interactive bool, stdin io.Reader, stdout, stderr io.Writer) (*exec.Cmd, error) {
	python := "/usr/bin/python3"
	clean := []string{"HOME=/root", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	if err := exec.CommandContext(ctx, python, "-I", "-c", "import sys; sys.exit(sys.version_info < (3, 10))").Run(); err != nil {
		if interactive && os.Geteuid() != 0 {
			// Pin the running executable across sudo even when a user-local
			// installation concurrently replaces its directory entry.
			args := []string{"-H", "--", "/usr/bin/env", "-i"}
			args = append(args, clean...)
			args = append(args, fmt.Sprintf("/proc/%d/exe", os.Getpid()))
			args = append(args, slices.DeleteFunc(slices.Clone(forwarded), func(s string) bool { return s == "--follow-install" })...)
			c := exec.CommandContext(ctx, "/usr/bin/sudo", args...)
			c.Stdin, c.Stdout, c.Stderr = stdin, stdout, stderr
			return nil, c.Run()
		}
		python, err = bootstrapPython(ctx, forwarded, stderr)
		if err != nil {
			return nil, err
		}
	}
	if interactive && os.Geteuid() != 0 {
		if _, err := exec.LookPath("/usr/bin/sudo"); err != nil {
			return nil, errors.New("open a root shell or install sudo to install the PaaS")
		}
		args := append([]string{"-H", "--", "/usr/bin/env", "-i"}, clean...)
		return exec.CommandContext(ctx, "/usr/bin/sudo", append(args, python, "-I", "-", encoded)...), nil
	}
	return exec.CommandContext(ctx, python, "-I", "-", encoded), nil
}
