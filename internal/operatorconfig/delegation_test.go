//go:build linux

package operatorconfig

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDelegationPublicConfigurationStrictAndBounded(t *testing.T) {
	valid := `{"version":1,"trusts":[{"tenant_id":"org-a","issuer":"https://issuer.example","audience":"capsule","allowed_scopes":["org:read"],"max_ttl_seconds":300,"keys":[{"kid":"key-1","public_key":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}]}]}`
	dir := t.TempDir()
	file := filepath.Join(dir, "trusts.json")
	if err := os.WriteFile(file, []byte(valid), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDelegationConfig(file)
	if err != nil || len(got.Trusts) != 1 || got.Trusts[0].TenantID != "org-a" {
		t.Fatal("public configuration refused", err)
	}
	for name, input := range map[string]string{
		"duplicate-field":   strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		"escaped-duplicate": strings.Replace(valid, `"version":1`, `"version":1,"ver\u0073ion":1`, 1),
		"unknown-field":     strings.Replace(valid, `"version":1`, `"version":1,"private_key":"not-a-key"`, 1),
		"unknown-nested":    strings.Replace(valid, `"kid":"key-1"`, `"kid":"key-1","jku":"https://example.invalid"`, 1),
		"malformed-key":     strings.Replace(valid, base64.StdEncoding.EncodeToString(make([]byte, 32)), "broken", 1),
		"wrong-key-size":    strings.Replace(valid, base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(make([]byte, 64)), 1),
		"trailing":          valid + "{}",
		"null":              "null",
		"empty-trusts":      `{"version":1,"trusts":[]}`,
		"wrong-version":     strings.Replace(valid, `"version":1`, `"version":2`, 1),
		"huge":              strings.Repeat(" ", (1<<20)+1),
		"duplicate-kid":     strings.Replace(valid, `"keys":[`, `"keys":[{"kid":"key-1","public_key":"`+base64.StdEncoding.EncodeToString(make([]byte, 32))+`"},`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(file, []byte(input), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadDelegationConfig(file); !errors.Is(err, ErrDelegationConfig) {
				t.Fatal("unsafe config accepted", err)
			}
		})
	}
	if err := os.WriteFile(file, []byte(valid), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDelegationConfig(file); !errors.Is(err, ErrDelegationConfig) {
		t.Fatal("mutable public trust accepted", err)
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDelegationConfig(link); !errors.Is(err, ErrDelegationConfig) {
		t.Fatal("symlink config accepted", err)
	}
}

func TestDelegationConfigurationRejectsCaseAliasesAtEveryLevel(t *testing.T) {
	public := base64.StdEncoding.EncodeToString(make([]byte, 32))
	valid := `{"version":1,"trusts":[{"tenant_id":"org-a","issuer":"https://issuer.example","audience":"capsule","allowed_scopes":["org:read"],"max_ttl_seconds":300,"keys":[{"kid":"key-1","public_key":"` + public + `"}]}]}`
	file := filepath.Join(t.TempDir(), "trusts.json")
	for name, input := range map[string]string{
		"version-alias-last":                strings.Replace(valid, `"version":1`, `"version":2,"Version":1`, 1),
		"version-alias-first":               strings.Replace(valid, `"version":1`, `"Version":2,"version":1`, 1),
		"version-single-alias":              strings.Replace(valid, `"version":1`, `"Version":1`, 1),
		"version-uppercase":                 strings.Replace(valid, `"version":1`, `"VERSION":1`, 1),
		"version-escaped-alias":             strings.Replace(valid, `"version":1`, `"\u0056ersion":1`, 1),
		"version-unicode-fold":              strings.Replace(valid, `"version":1`, `"ver\u017fion":1`, 1),
		"trusts-alias":                      strings.Replace(valid, `"trusts":`, `"Trusts":`, 1),
		"issuer-alias-last":                 strings.Replace(valid, `"issuer":"https://issuer.example"`, `"issuer":"https://other.example","Issuer":"https://issuer.example"`, 1),
		"issuer-alias-first":                strings.Replace(valid, `"issuer":"https://issuer.example"`, `"Issuer":"https://other.example","issuer":"https://issuer.example"`, 1),
		"tenant-alias":                      strings.Replace(valid, `"tenant_id":`, `"Tenant_ID":`, 1),
		"key-id-alias-last":                 strings.Replace(valid, `"kid":"key-1"`, `"kid":"other-key","Kid":"key-1"`, 1),
		"key-id-alias-first":                strings.Replace(valid, `"kid":"key-1"`, `"Kid":"other-key","kid":"key-1"`, 1),
		"key-id-unicode-fold":               strings.Replace(valid, `"kid":`, `"\u212aid":`, 1),
		"public-key-alias":                  strings.Replace(valid, `"public_key":`, `"PUBLIC_KEY":`, 1),
		"documented-key-wrong-top-level":    strings.Replace(valid, `"version":1`, `"version":1,"issuer":"https://issuer.example"`, 1),
		"documented-key-wrong-nested-level": strings.Replace(valid, `"kid":"key-1"`, `"kid":"key-1","version":1`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(file, []byte(input), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadDelegationConfig(file); !errors.Is(err, ErrDelegationConfig) {
				t.Fatal("noncanonical JSON field accepted", err)
			}
		})
	}
	// JSON escapes resolving to the exact documented key remain valid; only
	// aliases and duplicates are rejected, not legitimate JSON string encoding.
	canonicalEscaped := strings.Replace(valid, `"issuer":`, `"i\u0073suer":`, 1)
	if err := os.WriteFile(file, []byte(canonicalEscaped), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDelegationConfig(file); err != nil {
		t.Fatal("canonical escaped field refused", err)
	}
}
