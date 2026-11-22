package controlplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The service roles' writes (ADR 001, "Changes after the v0.1.0 audit"):
// what each process may write is what the code it runs writes. This file
// derives it from the sources, without PostgreSQL. A process runs the Go
// packages its command imports; a function of this package runs in it when
// one of those packages, or a function that runs, names it (calls, method
// values and interface calls alike: the name is enough, which only ever adds
// functions). Each function's SQL is its string literals. A statement that
// inserts, updates or deletes rows needs that privilege; one that locks rows
// (FOR UPDATE, FOR SHARE...) needs UPDATE on the tables it reads (PostgreSQL's
// rule); a write to a table also needs what that table's triggers write.
// Every role reads every table, and no role truncates, references or
// triggers: those are not derived.

const modulePath = "github.com/ArnaudGuiovanna/agentcapsule"

// serviceCommands are the commands each service role serves.
var serviceCommands = map[string]string{
	"agentcapsule_api":    "cmd/agentcapsule-api",
	"agentcapsule_worker": "cmd/agentcapsule-worker",
}

// dynamicWrites are the statements that name their table in a variable:
// the function that runs them and what they write.
var dynamicWrites = map[string][]string{
	// The retention purge of the audit trail (operations.go, auditTables).
	"PurgeAudit": auditTableDeletes(),
	// The operator's credential revocation (agentcapsule-admin only).
	"RevokeOperatorCredential": {"UPDATE platform_credentials", "UPDATE api_tokens"},
	"SetAuditRetention":        {},
	// The expired receipts' purge (receipt_purge.go).
	"PurgeExpiredReceipts": {"DELETE http_receipts", "UPDATE http_receipts", "DELETE tenant_http_receipts", "UPDATE tenant_http_receipts"},
}

func auditTableDeletes() []string {
	var out []string
	for _, a := range auditTables {
		out = append(out, "DELETE "+a.table)
	}
	return out
}

type goPackage struct {
	dir     string
	files   []*ast.File
	imports []string
	pgx     bool
}

func parsePackage(t *testing.T, fset *token.FileSet, dir string) *goPackage {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := &goPackage{dir: dir}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		p.files = append(p.files, f)
		for _, spec := range f.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if strings.HasPrefix(path, "github.com/jackc/pgx/") {
				p.pgx = true
			}
			if rest, ok := strings.CutPrefix(path, modulePath+"/"); ok && !slices.Contains(p.imports, rest) {
				p.imports = append(p.imports, rest)
			}
		}
	}
	return p
}

// closure parses the packages of the module that command imports, itself
// included, by their directory relative to the module's root.
func closure(t *testing.T, fset *token.FileSet, root, command string) map[string]*goPackage {
	t.Helper()
	out := map[string]*goPackage{}
	queue := []string{command}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		if out[dir] != nil {
			continue
		}
		p := parsePackage(t, fset, filepath.Join(root, dir))
		out[dir] = p
		queue = append(queue, p.imports...)
	}
	return out
}

// sqlNode is a function, a method or a package-level value of this package:
// the names it uses and its string literals.
type sqlNode struct {
	name     string
	names    []string
	literals []string
}

func nodeOf(name string, n ast.Node) *sqlNode {
	s := &sqlNode{name: name}
	ast.Inspect(n, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.Ident:
			s.names = append(s.names, v.Name)
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				if text, err := strconv.Unquote(v.Value); err == nil {
					s.literals = append(s.literals, text)
				}
			}
		}
		return true
	})
	return s
}

func packageNodes(p *goPackage) map[string][]*sqlNode {
	out := map[string][]*sqlNode{}
	for _, f := range p.files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				out[d.Name.Name] = append(out[d.Name.Name], nodeOf(d.Name.Name, d))
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							out[n.Name] = append(out[n.Name], nodeOf(n.Name, s))
						}
					case *ast.TypeSpec:
						// Struct fields and interface methods name nothing that runs.
					}
				}
			}
		}
	}
	return out
}

var (
	sqlIdentifier = `([a-z_][a-z0-9_]*)`
	insertInto    = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+` + sqlIdentifier)
	onConflict    = regexp.MustCompile(`(?is)\bON\s+CONFLICT\b.*?\bDO\s+UPDATE\b`)
	updateSet     = regexp.MustCompile(`(?is)\bUPDATE\s+(?:ONLY\s+)?` + sqlIdentifier + `(?:\s+(?:AS\s+)?[a-z_][a-z0-9_]*)?\s+SET\b`)
	deleteFrom    = regexp.MustCompile(`(?is)\bDELETE\s+FROM\s+(?:ONLY\s+)?` + sqlIdentifier)
	readsFrom     = regexp.MustCompile(`(?is)\b(?:FROM|JOIN)\s+(?:ONLY\s+)?` + sqlIdentifier)
	// alsoReads is the next table of a comma-joined list: FROM a x, b y.
	alsoReads = regexp.MustCompile(`(?is)^\s*,\s*(?:ONLY\s+)?` + sqlIdentifier)
	// aliasOf is the alias after a table, unless it is a keyword (notAliases).
	aliasOf      = regexp.MustCompile(`(?is)^\s+(?:AS\s+)?` + sqlIdentifier)
	rowLock      = regexp.MustCompile(`(?is)\bFOR\s+(?:NO\s+KEY\s+UPDATE|UPDATE|KEY\s+SHARE|SHARE)\b(?:\s+OF\s+(` + sqlIdentifier + `(?:\s*,\s*[a-z_][a-z0-9_]*)*))?`)
	dynamicTable = regexp.MustCompile(`(?is)(?:^|[^a-z0-9_])(INSERT\s+INTO|(?:([a-z_]+)\s+)?UPDATE|DELETE\s+FROM)\s*$`)
)

// notAliases are the keywords that may follow a table without being its
// alias: FROM a JOIN b reads b too.
var notAliases = map[string]bool{}

func init() {
	for k := range strings.FieldsSeq(`where join inner left right full cross natural lateral on using group order limit offset fetch
        for union except intersect having window returning set and or not when then else end with values select into do from
        is in between like ilike case null true false tablesample`) {
		notAliases[k] = true
	}
}

// sqlWrites adds to need what the statements in literals write: table ->
// privileges. A row lock anywhere in them needs UPDATE on every table they
// read, or, for a lock that names its tables (FOR UPDATE OF r), on the tables
// those names stand for in them (PostgreSQL locks, and checks UPDATE on, the
// named tables only); a name that stands for no table they read falls back to
// every table they read. It reports whether a statement names its table in a
// variable.
func sqlWrites(literals []string, tables map[string]bool, need map[string]map[string]bool) (dynamic bool) {
	add := func(table, privilege string) {
		if !tables[table] {
			return
		}
		if need[table] == nil {
			need[table] = map[string]bool{}
		}
		need[table][privilege] = true
	}
	locks := false
	var read, lockedNames []string
	aliases := map[string][]string{}
	for _, text := range literals {
		for _, m := range insertInto.FindAllStringSubmatchIndex(text, -1) {
			table := text[m[2]:m[3]]
			add(table, "INSERT")
			rest := text[m[1]:]
			if next := insertInto.FindStringIndex(rest); next != nil {
				rest = rest[:next[0]]
			}
			if onConflict.MatchString(rest) {
				add(table, "UPDATE")
			}
		}
		for _, m := range updateSet.FindAllStringSubmatch(text, -1) {
			add(m[1], "UPDATE")
		}
		for _, m := range deleteFrom.FindAllStringSubmatch(text, -1) {
			add(m[1], "DELETE")
		}
		// reads records table, read, and its alias at the start of rest; it
		// returns rest past the alias.
		reads := func(table, rest string) string {
			alias := ""
			if a := aliasOf.FindStringSubmatchIndex(rest); a != nil && !notAliases[strings.ToLower(rest[a[2]:a[3]])] {
				alias, rest = rest[a[2]:a[3]], rest[a[1]:]
			}
			read = append(read, table)
			for _, name := range []string{table, alias} {
				if name = strings.ToLower(name); name != "" && !slices.Contains(aliases[name], table) {
					aliases[name] = append(aliases[name], table)
				}
			}
			return rest
		}
		for _, m := range readsFrom.FindAllStringSubmatchIndex(text, -1) {
			rest := reads(text[m[2]:m[3]], text[m[1]:])
			// The tables that follow it in a comma-joined list.
			for c := alsoReads.FindStringSubmatchIndex(rest); c != nil; c = alsoReads.FindStringSubmatchIndex(rest) {
				rest = reads(rest[c[2]:c[3]], rest[c[1]:])
			}
		}
		for _, m := range rowLock.FindAllStringSubmatch(text, -1) {
			if m[1] == "" {
				locks = true
				continue
			}
			for name := range strings.SplitSeq(m[1], ",") {
				lockedNames = append(lockedNames, strings.ToLower(strings.TrimSpace(name)))
			}
		}
		if m := dynamicTable.FindStringSubmatch(text); m != nil && !strings.EqualFold(m[2], "FOR") && !strings.EqualFold(m[2], "KEY") {
			dynamic = true
		}
	}
	for _, name := range lockedNames {
		if len(aliases[name]) == 0 {
			locks = true
		}
		for _, table := range aliases[name] {
			add(table, "UPDATE")
		}
	}
	if locks {
		for _, table := range read {
			add(table, "UPDATE")
		}
	}
	return dynamic
}

// functionWrites adds to need what the function of the migrations named fn
// writes, with the functions it calls: they run with its caller's
// privileges (none is SECURITY DEFINER).
func functionWrites(fn string, bodies map[string]string, tables map[string]bool, need map[string]map[string]bool, seen map[string]bool) {
	if seen[fn] {
		return
	}
	seen[fn] = true
	body, ok := bodies[fn]
	if !ok {
		return
	}
	sqlWrites([]string{body}, tables, need)
	for name := range bodies {
		if strings.Contains(body, name+"(") {
			functionWrites(name, bodies, tables, need, seen)
		}
	}
}

// sqlFunctions are the functions the migrations define, by name, with the
// body of their last definition; triggers are the functions each table's
// triggers run.
func sqlFunctions() (bodies map[string]string, triggers map[string][]string) {
	function := regexp.MustCompile(`(?is)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+` + sqlIdentifier + `\s*\(.*?(\$[a-z_]*\$)(.*?)(\$[a-z_]*\$)`)
	trigger := regexp.MustCompile(`(?is)CREATE\s+(?:CONSTRAINT\s+)?TRIGGER\s+[a-z_][a-z0-9_]*\s+.*?\bON\s+` + sqlIdentifier + `\b.*?\bEXECUTE\s+(?:FUNCTION|PROCEDURE)\s+` + sqlIdentifier)
	bodies, triggers = map[string]string{}, map[string][]string{}
	for _, m := range controlPlaneMigrations {
		for _, f := range function.FindAllStringSubmatch(m.sql, -1) {
			if f[2] == f[4] {
				bodies[f[1]] = f[3]
			}
		}
		for _, tr := range trigger.FindAllStringSubmatch(m.sql, -1) {
			if !slices.Contains(triggers[tr[1]], tr[2]) {
				triggers[tr[1]] = append(triggers[tr[1]], tr[2])
			}
		}
	}
	return bodies, triggers
}

// serviceRoleWrites derives, for each service role, the privileges its
// process needs on each table: table -> privilege -> true.
func serviceRoleWrites(t *testing.T) map[string]map[string]map[string]bool {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	tables := map[string]bool{}
	for _, table := range durableTables {
		tables[table] = true
	}
	view := regexp.MustCompile(`(?is)CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+` + sqlIdentifier)
	for _, m := range controlPlaneMigrations {
		for _, v := range view.FindAllStringSubmatch(m.sql, -1) {
			tables[v[1]] = true
		}
	}
	bodies, triggers := sqlFunctions()
	fset := token.NewFileSet()
	out := map[string]map[string]map[string]bool{}
	for role, command := range serviceCommands {
		nodes := map[string][]*sqlNode{}
		need := map[string]map[string]bool{}
		var names []string
		for dir, p := range closure(t, fset, root, command) {
			if dir == "internal/controlplane" || strings.HasPrefix(dir, "internal/controlplane/") {
				for name, definitions := range packageNodes(p) {
					nodes[name] = append(nodes[name], definitions...)
				}
				continue
			}
			for _, f := range p.files {
				n := nodeOf(dir, f)
				names = append(names, n.names...)
				if p.pgx && sqlWrites(n.literals, tables, need) {
					t.Errorf("%s: a statement names its table in a variable; derive its writes here", dir)
				}
			}
		}
		reached := map[*sqlNode]bool{}
		for len(names) > 0 {
			name := names[len(names)-1]
			names = names[:len(names)-1]
			for _, n := range nodes[name] {
				if reached[n] {
					continue
				}
				reached[n] = true
				names = append(names, n.names...)
				dynamic := sqlWrites(n.literals, tables, need)
				extra, listed := dynamicWrites[n.name]
				if dynamic && !listed {
					t.Errorf("%s: a statement names its table in a variable; list its writes in dynamicWrites", n.name)
				}
				for _, w := range extra {
					verb, table, _ := strings.Cut(w, " ")
					sqlWrites([]string{map[string]string{"INSERT": "INSERT INTO ", "UPDATE": "UPDATE ", "DELETE": "DELETE FROM "}[verb] + table + " SET"}, tables, need)
				}
				// A statement may call a function of the migrations: it runs
				// with the caller's privileges.
				for _, text := range n.literals {
					for name := range bodies {
						if strings.Contains(text, name+"(") {
							functionWrites(name, bodies, tables, need, map[string]bool{})
						}
					}
				}
			}
		}
		// A write to a table runs its triggers, with the writer's privileges,
		// and the functions they call, and their writes run theirs.
		for changed := true; changed; {
			changed = false
			for table := range need {
				for _, fn := range triggers[table] {
					before := len(flatten(need))
					functionWrites(fn, bodies, tables, need, map[string]bool{})
					changed = changed || len(flatten(need)) != before
				}
			}
		}
		out[role] = need
	}
	return out
}

func flatten(need map[string]map[string]bool) []string {
	var out []string
	for table, privileges := range need {
		for p := range privileges {
			out = append(out, p+" "+table)
		}
	}
	slices.Sort(out)
	return out
}
