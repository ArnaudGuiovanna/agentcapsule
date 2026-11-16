package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"gopkg.in/yaml.v3"
)

// openapi/openapi.yaml is the API's contract (CONV-1). These tests tie it to
// the server: the same routes with the same methods, and answers with the
// fields it documents.

const openAPIFile = "../../openapi/openapi.yaml"

var openAPIMethods = []string{"get", "put", "post", "delete", "patch", "head", "options", "trace"}

type openAPIDoc struct{ root map[string]any }

func loadOpenAPI(t *testing.T) *openAPIDoc {
	t.Helper()
	raw, err := os.ReadFile(openAPIFile)
	if err != nil {
		t.Fatal(err)
	}
	var root any
	if err = yaml.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	doc := &openAPIDoc{root: stringKeys(root).(map[string]any)}
	if doc.root["openapi"] != "3.1.0" {
		t.Fatal("not an OpenAPI 3.1 document:", doc.root["openapi"])
	}
	return doc
}

// stringKeys makes every mapping of a YAML document a map[string]any.
func stringKeys(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			v[k] = stringKeys(x)
		}
		return v
	case map[any]any:
		out := map[string]any{}
		for k, x := range v {
			out[fmt.Sprint(k)] = stringKeys(x)
		}
		return out
	case []any:
		for i, x := range v {
			v[i] = stringKeys(x)
		}
	}
	return v
}

func (d *openAPIDoc) paths() map[string]any {
	paths, _ := d.root["paths"].(map[string]any)
	return paths
}

// routes maps "METHOD shape" to the documented path of each operation.
func (d *openAPIDoc) routes() map[string]string {
	out := map[string]string{}
	for path, item := range d.paths() {
		for method := range item.(map[string]any) {
			if slices.Contains(openAPIMethods, method) {
				out[strings.ToUpper(method)+" "+rbacPattern(path)] = path
			}
		}
	}
	return out
}

// servedRoutes maps "METHOD shape" to the server's pattern, for each method
// each route accepts. Every handler checks the method first and answers 405
// with the methods it accepts: no database is needed.
func servedRoutes(t *testing.T) map[string]string {
	t.Helper()
	s, err := NewForHost(&controlplane.Store{}, &controlplane.Accounts{}, "local")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, pattern := range s.routes {
		if pattern == "/" {
			continue
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("PATCH", rbacPlaceholder.ReplaceAllString(pattern, "x"), nil))
		if w.Code != 405 || w.Header().Get("Allow") == "" {
			t.Fatal(pattern, "does not refuse PATCH with the methods it accepts:", w.Code)
		}
		for _, method := range strings.Split(w.Header().Get("Allow"), ", ") {
			out[method+" "+rbacPattern(pattern)] = pattern
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// CONV-1: every route the server serves is under /v1 and in
// openapi/openapi.yaml with each of its methods, every documented operation
// is served, and the RBAC matrix lists the same operations.
func TestOpenAPIDescribesExactlyTheServedRoutes(t *testing.T) {
	documented, served := loadOpenAPI(t).routes(), servedRoutes(t)
	matrix := map[string]bool{}
	for _, r := range rbacRoutes {
		matrix[r.Method+" "+rbacPattern(r.Path)] = true
	}
	for _, key := range sortedKeys(served) {
		method, _, _ := strings.Cut(key, " ")
		if !strings.HasPrefix(served[key], "/v1/") {
			t.Error("served outside /v1:", method, served[key])
		}
		if _, ok := documented[key]; !ok {
			t.Error("served, not in openapi/openapi.yaml:", method, served[key])
		}
		if !matrix[key] {
			t.Error("served, not in the RBAC matrix:", method, served[key])
		}
	}
	for _, key := range sortedKeys(documented) {
		if _, ok := served[key]; !ok {
			method, _, _ := strings.Cut(key, " ")
			t.Error("in openapi/openapi.yaml, not served:", method, documented[key])
		}
	}
	for _, key := range sortedKeys(matrix) {
		if _, ok := served[key]; !ok {
			t.Error("in the RBAC matrix, not served:", key)
		}
	}
	if len(served) < 100 {
		t.Fatal("too few operations served:", len(served))
	}
}

// CONV-4: the document gives a 202 answer to the routes of asyncRoutes and
// of the legacy domain, and to no other.
func TestOpenAPIDocumentsTheAsynchronousRoutes(t *testing.T) {
	doc := loadOpenAPI(t)
	want := map[string]bool{}
	for _, r := range rbacRoutes {
		if _, ok := asyncRoutes[r.Method+" "+r.Path]; ok || r.Success == 202 {
			want[r.Method+" "+rbacPattern(r.Path)] = true
		}
	}
	for key, path := range doc.routes() {
		method, _, _ := strings.Cut(key, " ")
		op := doc.paths()[path].(map[string]any)[strings.ToLower(method)].(map[string]any)
		responses, _ := op["responses"].(map[string]any)
		_, accepted := responses["202"]
		if accepted != want[key] {
			t.Errorf("%s %s: documented 202 %v, answers 202 %v", method, path, accepted, want[key])
		}
	}
}

// operation finds the documented operation of a request: the template with
// the most literal segments that matches the path.
func (d *openAPIDoc) operation(method, path string) (string, map[string]any) {
	path, _, _ = strings.Cut(path, "?")
	segments := strings.Split(path, "/")
	best, literals := "", -1
	for template := range d.paths() {
		parts := strings.Split(template, "/")
		if len(parts) != len(segments) {
			continue
		}
		n := 0
		for i, p := range parts {
			if rbacPlaceholder.MatchString(p) {
				continue
			}
			if p != segments[i] {
				n = -1
				break
			}
			n++
		}
		if n > literals {
			best, literals = template, n
		}
	}
	if best == "" {
		return "", nil
	}
	op, _ := d.paths()[best].(map[string]any)[strings.ToLower(method)].(map[string]any)
	return best, op
}

// resolve follows $ref within the document.
func (d *openAPIDoc) resolve(v any) map[string]any {
	m, _ := v.(map[string]any)
	for m != nil {
		ref, ok := m["$ref"].(string)
		if !ok {
			break
		}
		var cur any = d.root
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			next, _ := cur.(map[string]any)
			cur = next[part]
		}
		m, _ = cur.(map[string]any)
	}
	return m
}

// fieldSets are the top-level shapes a schema allows: its required fields,
// and its declared fields (nil when it declares none).
type fieldSet struct{ required, declared []string }

func (d *openAPIDoc) fieldSets(schema map[string]any) []fieldSet {
	schema = d.resolve(schema)
	if schema == nil {
		return nil
	}
	for _, alt := range []string{"oneOf", "anyOf"} {
		if list, ok := schema[alt].([]any); ok {
			var out []fieldSet
			for _, s := range list {
				out = append(out, d.fieldSets(d.resolve(s))...)
			}
			return out
		}
	}
	var set fieldSet
	if list, ok := schema["allOf"].([]any); ok {
		for _, s := range list {
			for _, sub := range d.fieldSets(d.resolve(s)) {
				set.required = append(set.required, sub.required...)
				set.declared = append(set.declared, sub.declared...)
			}
		}
	}
	for _, r := range asList(schema["required"]) {
		set.required = append(set.required, fmt.Sprint(r))
	}
	if props, ok := schema["properties"].(map[string]any); ok {
		for k := range props {
			set.declared = append(set.declared, k)
		}
	}
	return []fieldSet{set}
}

func asList(v any) []any {
	list, _ := v.([]any)
	return list
}

// answerSchema is the documented schema of an answer, or nil when the
// document gives none for that status.
func (d *openAPIDoc) answerSchema(op map[string]any, status int) map[string]any {
	responses, _ := op["responses"].(map[string]any)
	response := d.resolve(responses[strconv.Itoa(status)])
	if response == nil && status >= 400 {
		response = d.resolve(responses["default"])
	}
	content, _ := response["content"].(map[string]any)
	for _, media := range []string{"application/json", "application/problem+json"} {
		if c, ok := content[media].(map[string]any); ok {
			return d.resolve(c["schema"])
		}
	}
	return nil
}

// checkAnswer checks an answer's top-level fields against the documented
// schema of its operation and status: the required fields are present and
// every field is documented. A list's items are checked the same way.
func (d *openAPIDoc) checkAnswer(method, path string, status int, body []byte) error {
	template, op := d.operation(method, path)
	if op == nil {
		return fmt.Errorf("%s %s is not documented", method, path)
	}
	responses, _ := op["responses"].(map[string]any)
	if _, ok := responses[strconv.Itoa(status)]; !ok && status < 400 {
		return fmt.Errorf("%s %s: status %d is not documented", method, template, status)
	}
	schema := d.answerSchema(op, status)
	if schema == nil {
		return nil
	}
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil // not JSON: a download
	}
	return d.checkFields(fmt.Sprintf("%s %s %d", method, template, status), schema, value)
}

func (d *openAPIDoc) checkFields(where string, schema map[string]any, value any) error {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	var problems []string
	for _, set := range d.fieldSets(schema) {
		missing, unknown := []string{}, []string{}
		for _, r := range set.required {
			if _, ok := object[r]; !ok {
				missing = append(missing, r)
			}
		}
		for k := range object {
			if set.declared != nil && !slices.Contains(set.declared, k) {
				unknown = append(unknown, k)
			}
		}
		if len(missing) == 0 && len(unknown) == 0 {
			// A list's items, one level down.
			props, _ := d.resolve(schema)["properties"].(map[string]any)
			items := d.resolve(d.resolve(props["items"])["items"])
			for _, item := range asList(object["items"]) {
				if items == nil {
					break
				}
				if err := d.checkFields(where+" items", items, item); err != nil {
					return err
				}
			}
			return nil
		}
		sort.Strings(missing)
		sort.Strings(unknown)
		problems = append(problems, fmt.Sprintf("missing %v, undocumented %v", missing, unknown))
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%s: the answer matches no documented shape: %s", where, strings.Join(problems, "; "))
}
