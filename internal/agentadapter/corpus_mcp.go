package agentadapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/sdk/go/corpus"
)

type toolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Input       map[string]any `json:"inputSchema"`
}

var corpusTools = []toolSpec{
	corpusTool("corpus_list", "List this agent's corpus mounts."),
	corpusTool("corpus_index", "Read a corpus's Markdown index.", "mount"),
	corpusTool("corpus_search", "Find a phrase offline and return passages with their original source locations.", "mount", "phrase"),
	corpusTool("corpus_part", "Read the Markdown part containing a cited element.", "mount", "doc_id", "part"),
}

func corpusTool(name, description string, required ...string) toolSpec {
	props := map[string]any{}
	for _, k := range required {
		props[k] = map[string]any{"type": "string", "minLength": 1}
	}
	if name == "corpus_search" {
		props["limit"] = map[string]any{"type": "integer", "minimum": 1, "maximum": 20, "default": 5}
	}
	schema := map[string]any{"type": "object", "additionalProperties": false, "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return toolSpec{name, description, schema}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func callCorpusTool(ctx context.Context, mounts corpus.Mounts, params json.RawMessage) (any, *rpcError) {
	var call struct {
		Name      string
		Arguments json.RawMessage
	}
	if json.Unmarshal(params, &call) != nil {
		return nil, &rpcError{-32602, "Invalid tool call"}
	}
	var spec *toolSpec
	for i := range corpusTools {
		if corpusTools[i].Name == call.Name {
			spec = &corpusTools[i]
			break
		}
	}
	if spec == nil {
		return nil, &rpcError{-32602, "Unknown tool"}
	}
	if call.Arguments == nil {
		call.Arguments = json.RawMessage("{}")
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(call.Arguments, &raw) != nil || raw == nil {
		return nil, &rpcError{-32602, "Invalid tool arguments"}
	}
	properties := spec.Input["properties"].(map[string]any)
	for k := range raw {
		if _, ok := properties[k]; !ok {
			return nil, &rpcError{-32602, "Unknown tool argument"}
		}
	}
	if required, ok := spec.Input["required"].([]string); ok {
		for _, k := range required {
			v := raw[k]
			var arg string
			if json.Unmarshal(v, &arg) != nil || strings.TrimSpace(arg) == "" {
				return nil, &rpcError{-32602, "Missing required string argument"}
			}
		}
	}
	var args struct {
		Mount, Phrase, Part string
		Document            string `json:"doc_id"`
		Limit               int
	}
	args.Limit = 5
	if json.Unmarshal(call.Arguments, &args) != nil {
		return nil, &rpcError{-32602, "Invalid tool arguments"}
	}
	var value any
	var err error
	switch call.Name {
	case "corpus_list":
		value, err = mounts.List()
	case "corpus_index":
		value, err = mounts.Index(args.Mount)
	case "corpus_search":
		value, err = mounts.Search(ctx, args.Mount, args.Phrase, args.Limit)
	case "corpus_part":
		value, err = mounts.Part(args.Mount, args.Document, args.Part)
	}
	var text string
	if err != nil {
		text = "Could not read the requested corpus or passage."
	} else if s, ok := value.(string); ok {
		text = s
	} else {
		b, e := json.Marshal(value)
		if e != nil {
			return nil, &rpcError{-32603, "Cannot encode tool result"}
		}
		text = string(b)
	}
	return map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "isError": err != nil}, nil
}

// ServeCorpusMCP serves the optional local stdio transport. The child shares
// the harness's read-only mounts. No credentials or platform socket are needed.
func ServeCorpusMCP(ctx context.Context, mounts corpus.Mounts, in io.Reader, out io.Writer) error {
	lines := bufio.NewScanner(in)
	lines.Buffer(make([]byte, 4096), 64<<10)
	enc := json.NewEncoder(out)
	initialized := false
	for lines.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		req := rpcRequest{}
		r := rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null")}
		if err := json.Unmarshal(lines.Bytes(), &req); err != nil {
			r.Error = &rpcError{-32700, "Parse error"}
		} else if req.JSONRPC != "2.0" || req.Method == "" || (req.ID != nil && (bytes.Equal(req.ID, []byte("null")) || (req.ID[0] != '"' && req.ID[0] != '-' && (req.ID[0] < '0' || req.ID[0] > '9')))) {
			r.Error = &rpcError{-32600, "Invalid Request"}
		} else {
			if req.ID == nil {
				continue
			}
			r.ID = req.ID
			switch req.Method {
			case "initialize":
				var init struct{ ProtocolVersion string }
				if json.Unmarshal(req.Params, &init) != nil || init.ProtocolVersion == "" {
					r.Error = &rpcError{-32602, "Expected a protocol version"}
					break
				}
				version := init.ProtocolVersion
				switch version {
				case "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25":
				default:
					version = "2025-11-25"
				}
				initialized = true
				r.Result = map[string]any{"protocolVersion": version, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "corpus", "version": "1"}}
			case "ping":
				r.Result = struct{}{}
			case "tools/list", "tools/call":
				if !initialized {
					r.Error = &rpcError{-32002, "Server not initialized"}
					break
				}
				if req.Method == "tools/list" {
					r.Result = map[string]any{"tools": corpusTools}
					break
				}
				read, cancel := context.WithTimeout(ctx, 5*time.Second)
				r.Result, r.Error = callCorpusTool(read, mounts, req.Params)
				cancel()
			default:
				r.Error = &rpcError{-32601, "Method not found"}
			}
		}
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	if err := lines.Err(); err != nil {
		return errors.New("reading corpus MCP request")
	}
	return nil
}
