package hostops

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// The release workflow signs SHA256SUMS in the protected "release"
// environment (S-16, ADR 013), which Fulcio writes in the signing certificate.
// The two releases signed before that environment existed are accepted by the
// digest of their SHA256SUMS only. install.sh and internal/hostops/host.py
// hold the same values.
const releaseEnvironment = "release"

var environmentOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 23}

var signedBeforeEnvironment = map[string]string{
	"v0.0.1": "500038470c97b46ea7efc31ca1fc08c305f46d2d181d61707a1c24e9ea30391e",
	"v0.1.0": "b0574da8b4811af9c57edc5127a58a68a09140c58391c2566a4815946f1a4c41",
}

// cosignVerification binds the signature to the release workflow of version,
// started by a push of its tag in this repository.
func cosignVerification(bundle, version string) []string {
	return []string{"verify-blob", "--bundle", bundle,
		"--certificate-identity", "https://github.com/" + repository + "/.github/workflows/release.yml@refs/tags/" + version,
		"--certificate-oidc-issuer", issuer,
		"--certificate-github-workflow-trigger", "push",
		"--certificate-github-workflow-repository", repository,
		"--certificate-github-workflow-ref", "refs/tags/" + version}
}

// checkSigningEnvironment refuses a signature that cosign verified but that
// the release environment's job did not make. Run it after cosign.
func checkSigningEnvironment(bundle, checksums, version string) error {
	sums, err := os.ReadFile(checksums)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(sums)
	if want, ok := signedBeforeEnvironment[version]; ok && hex.EncodeToString(digest[:]) == want {
		return nil
	}
	raw, err := os.ReadFile(bundle)
	if err != nil {
		return err
	}
	environment, err := signingEnvironment(raw)
	if err != nil {
		return err
	}
	if environment != releaseEnvironment {
		return fmt.Errorf("release %s was not signed in the protected release environment", version)
	}
	return nil
}

// signingEnvironment is the deployment environment of the run that signed a
// Sigstore bundle, empty when its certificate names none.
func signingEnvironment(bundle []byte) (string, error) {
	var b struct {
		VerificationMaterial struct {
			Certificate *struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificate"`
			Chain *struct {
				Certificates []struct {
					RawBytes string `json:"rawBytes"`
				} `json:"certificates"`
			} `json:"x509CertificateChain"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil {
		return "", fmt.Errorf("invalid signature bundle: %w", err)
	}
	var raw string
	switch m := b.VerificationMaterial; {
	case m.Certificate != nil:
		raw = m.Certificate.RawBytes
	case m.Chain != nil && len(m.Chain.Certificates) > 0:
		raw = m.Chain.Certificates[0].RawBytes
	default:
		return "", errors.New("no signing certificate in the signature bundle")
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", errors.New("invalid signing certificate in the signature bundle")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("invalid signing certificate: %w", err)
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(environmentOID) {
			continue
		}
		var value string
		if rest, err := asn1.UnmarshalWithParams(ext.Value, &value, "utf8"); err != nil || len(rest) != 0 {
			return "", errors.New("invalid deployment environment in the signing certificate")
		}
		return value, nil
	}
	return "", nil
}

var semantic = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*))?$`)

// compareVersions orders two release tags as semantic versions, like
// version_order in internal/hostops/host.py.
func compareVersions(a, b string) (int, error) {
	pa, pb := semantic.FindStringSubmatch(a), semantic.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		return 0, errors.New("invalid semantic version")
	}
	for _, pre := range []string{pa[4], pb[4]} {
		for _, id := range strings.Split(pre, ".") {
			if len(id) > 1 && id[0] == '0' && strings.Trim(id, "0123456789") == "" {
				return 0, errors.New("invalid numeric prerelease identifier")
			}
		}
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.ParseUint(pa[i], 10, 64)
		y, _ := strconv.ParseUint(pb[i], 10, 64)
		if x != y {
			if x < y {
				return -1, nil
			}
			return 1, nil
		}
	}
	switch {
	case pa[4] == pb[4]:
		return 0, nil
	case pa[4] == "":
		return 1, nil
	case pb[4] == "":
		return -1, nil
	}
	la, lb := strings.Split(pa[4], "."), strings.Split(pb[4], ".")
	for i := 0; i < len(la) && i < len(lb); i++ {
		if c := comparePrerelease(la[i], lb[i]); c != 0 {
			return c, nil
		}
	}
	switch {
	case len(la) < len(lb):
		return -1, nil
	case len(la) > len(lb):
		return 1, nil
	}
	return 0, nil
}

func comparePrerelease(a, b string) int {
	numeric := func(s string) bool { return strings.Trim(s, "0123456789") == "" }
	switch {
	case numeric(a) && numeric(b):
		x, _ := strconv.ParseUint(a, 10, 64)
		y, _ := strconv.ParseUint(b, 10, 64)
		if x < y {
			return -1
		} else if x > y {
			return 1
		}
		return 0
	case numeric(a):
		return -1
	case numeric(b):
		return 1
	}
	return strings.Compare(a, b)
}

// The highest release this CLI has been, kept in its configuration directory
// (L-13): a self update goes below it only with --allow-older.
func highestRecordPath() (string, error) {
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
	return filepath.Join(dir, "self-update.json"), nil
}

func highestRecord() (string, error) {
	path, err := highestRecordPath()
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var record struct {
		Highest string `json:"highest"`
	}
	if err := json.Unmarshal(raw, &record); err != nil || !semantic.MatchString(record.Highest) {
		return "", fmt.Errorf("%s is not a valid record of the highest release: remove it to start again", path)
	}
	return record.Highest, nil
}

// releaseFloor is the higher of the running release and the recorded one; a
// development build has no release of its own.
func releaseFloor(running, recorded string) (string, error) {
	floor := recorded
	if semantic.MatchString(running) {
		if floor == "" {
			return running, nil
		}
		c, err := compareVersions(running, floor)
		if err != nil {
			return "", err
		}
		if c > 0 {
			floor = running
		}
	}
	return floor, nil
}

func olderThan(version, floor string) (bool, error) {
	if floor == "" {
		return false, nil
	}
	c, err := compareVersions(version, floor)
	return c < 0, err
}

func recordHighest(version, floor string) error {
	highest, err := releaseFloor(version, floor)
	if err != nil {
		return err
	}
	path, err := highestRecordPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(map[string]string{"highest": highest})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".self-update-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
