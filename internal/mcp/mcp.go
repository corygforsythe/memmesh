// Package mcp serves the Model Context Protocol over a JSON-RPC 2.0 stream.
//
// One MCP server is the entire integration surface (plan §7). Hermes, firstmate
// crewmates, Claude Code, Claude Desktop and Gemini CLI all attach the same way, and
// none of them gets a field or a code path of its own.
//
// Records stay model-neutral: a Gemini-authored fact is fully legible to Claude.
// `author_model` is recorded for audit and is never a filter. Resisting per-harness
// special cases is what keeps that true.
//
// # Why this is hand-rolled
//
// No MCP SDK is reachable in this build (docs/decisions/0002). JSON-RPC 2.0 over a
// newline-delimited stream is a small enough protocol that implementing it directly
// is less risk than it sounds, and it keeps the dependency count at zero.
package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// ProtocolVersion is the MCP revision this server implements.
const ProtocolVersion = "2024-11-05"

// JSON-RPC 2.0 error codes, plus the MCP convention of returning tool failures as
// results rather than protocol errors.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
)

// request is an incoming JSON-RPC message.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// isNotification reports whether the message expects no reply.
func (r *request) isNotification() bool { return len(r.ID) == 0 }

// response is an outgoing JSON-RPC message.
type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Tool is one callable tool.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`

	// Handler runs the tool. It returns the structured result, or an error.
	//
	// A returned error becomes an MCP tool result marked isError rather than a
	// JSON-RPC protocol error, because a tool that failed is a normal outcome the
	// model should see and reason about, not a transport fault.
	Handler func(params json.RawMessage) (any, error) `json:"-"`
}

// Server dispatches MCP requests to registered tools.
//
// A Server is safe for concurrent use, but Serve processes one request at a time on a
// single stream, which is what stdio transports give you anyway.
type Server struct {
	name    string
	version string

	mu    sync.RWMutex
	tools map[string]Tool
	order []string
}

// NewServer returns an empty server.
func NewServer(name, version string) *Server {
	return &Server{name: name, version: version, tools: make(map[string]Tool)}
}

// Register adds a tool. Registering the same name twice replaces it.
func (s *Server) Register(t Tool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tools[t.Name]; !exists {
		s.order = append(s.order, t.Name)
	}
	s.tools[t.Name] = t
}

// Tools lists the registered tools in registration order, which is the order a
// client will present them in.
func (s *Server) Tools() []Tool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tool, 0, len(s.order))
	for _, name := range s.order {
		out = append(out, s.tools[name])
	}
	return out
}

// Serve reads newline-delimited JSON-RPC requests from r and writes responses to w.
//
// It returns nil at end of stream. A malformed line produces a parse error response
// and the stream continues: one bad message from a client is not a reason to drop a
// working session.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	// Records can be up to 1 MiB, so a request carrying one needs well over the
	// default 64 KiB line limit.
	scanner.Buffer(make([]byte, 0, 64<<10), 8<<20)
	enc := json.NewEncoder(w)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			if err := enc.Encode(response{
				JSONRPC: "2.0",
				Error:   &rpcError{Code: codeParse, Message: fmt.Sprintf("parse error: %v", err)},
			}); err != nil {
				return err
			}
			continue
		}
		resp, reply := s.dispatch(&req)
		if !reply {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("mcp: read: %w", err)
	}
	return nil
}

// dispatch handles one request, returning the response and whether to send it.
func (s *Server) dispatch(req *request) (response, bool) {
	if req.JSONRPC != "2.0" {
		return s.fail(req, codeInvalidRequest, fmt.Sprintf("jsonrpc must be \"2.0\", got %q", req.JSONRPC)), !req.isNotification()
	}

	switch req.Method {
	case "initialize":
		return s.ok(req, map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    s.name,
				"version": s.version,
			},
		}), !req.isNotification()

	case "notifications/initialized", "initialized":
		return response{}, false

	case "ping":
		return s.ok(req, map[string]any{}), !req.isNotification()

	case "tools/list":
		return s.ok(req, map[string]any{"tools": s.Tools()}), !req.isNotification()

	case "tools/call":
		return s.callTool(req), !req.isNotification()

	default:
		return s.fail(req, codeMethodNotFound, fmt.Sprintf("unknown method %q", req.Method)), !req.isNotification()
	}
}

// callParams is the shape of a tools/call request.
type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// content is one piece of an MCP tool result.
type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// toolResult is the MCP tool response shape.
//
// The structured result is returned twice: once as JSON text in Content, which every
// client can display, and once in StructuredContent for clients that parse it. That
// redundancy is in the protocol, not an accident here.
type toolResult struct {
	Content           []content `json:"content"`
	StructuredContent any       `json:"structuredContent,omitempty"`
	IsError           bool      `json:"isError,omitempty"`
}

func (s *Server) callTool(req *request) response {
	var p callParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return s.fail(req, codeInvalidParams, fmt.Sprintf("bad params: %v", err))
		}
	}
	s.mu.RLock()
	tool, ok := s.tools[p.Name]
	s.mu.RUnlock()
	if !ok {
		return s.fail(req, codeInvalidParams, fmt.Sprintf("unknown tool %q", p.Name))
	}

	result, err := tool.Handler(p.Arguments)
	if err != nil {
		// A tool failure is content the model should see, not a transport error it
		// will never be shown.
		return s.ok(req, toolResult{
			Content: []content{{Type: "text", Text: err.Error()}},
			IsError: true,
		})
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return s.fail(req, codeInternal, fmt.Sprintf("encode result: %v", err))
	}
	return s.ok(req, toolResult{
		Content:           []content{{Type: "text", Text: string(encoded)}},
		StructuredContent: result,
	})
}

func (s *Server) ok(req *request, result any) response {
	return response{JSONRPC: "2.0", ID: req.ID, Result: result}
}

func (s *Server) fail(req *request, code int, msg string) response {
	return response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: code, Message: msg}}
}
