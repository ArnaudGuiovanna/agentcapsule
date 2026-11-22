package controlplane

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The store composes these domains. It opens the transaction with the durable
// preamble and owns its outcome, including post-commit revocation recording.
func TestDomainQueriesUseTheCallingTransaction(t *testing.T) {
	for _, domain := range []string{"reconciliation", "audit", "mailbox", "workqueue", "diagnostics", "corpus", "identity", "budgets", "accounting", "transitcrypto"} {
		t.Run(domain, func(t *testing.T) {
			p, err := build.Default.ImportDir(domain, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range p.Imports {
				if strings.HasSuffix(path, "/internal/controlplane") || strings.HasSuffix(path, "/pgxpool") {
					t.Errorf("%s imports %s", domain, path)
				}
				if (domain == "accounting" || domain == "transitcrypto") && strings.HasPrefix(path, "github.com/jackc/pgx") {
					t.Errorf("%s depends on the database driver", domain)
				}
			}
			for _, name := range p.GoFiles {
				f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(domain, name), nil, parser.SkipObjectResolution)
				if err != nil {
					t.Fatal(err)
				}
				ast.Inspect(f, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if ok {
						s, ok := call.Fun.(*ast.SelectorExpr)
						if ok && slices.Contains([]string{"Begin", "BeginTx", "Commit", "Rollback"}, s.Sel.Name) {
							t.Errorf("%s takes ownership of the caller's transaction in %s", domain, name)
						}
					}
					return true
				})
			}
		})
	}
}
