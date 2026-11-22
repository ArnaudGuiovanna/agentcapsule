package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOIDCEdgeRefusesAnIncompleteOrNonLoopbackConfiguration(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	for _, f := range []string{cert, key} {
		if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, args := range map[string][]string{
		"no listener":        {"-tls-cert", cert, "-tls-key", key},
		"no certificate":     {"-listen", "127.0.0.1:0", "-tls-key", key},
		"public upstream":    {"-listen", "127.0.0.1:0", "-tls-cert", cert, "-tls-key", key, "-upstream", "192.0.2.1:9445"},
		"named upstream":     {"-listen", "127.0.0.1:0", "-tls-cert", cert, "-tls-key", key, "-upstream", "keycloak:9445"},
		"extra argument":     {"-listen", "127.0.0.1:0", "-tls-cert", cert, "-tls-key", key, "more"},
		"unusable TLS files": {"-listen", "127.0.0.1:0", "-tls-cert", cert, "-tls-key", key},
	} {
		if code := run(append([]string{"oidc-edge"}, args...)); code == 0 {
			t.Errorf("%s: started", name)
		}
	}
}
