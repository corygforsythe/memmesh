package mcp

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"strings"
	"testing"

	"github.com/coryforsythe/memmesh/internal/clock"
	"github.com/coryforsythe/memmesh/internal/node"
	"github.com/coryforsythe/memmesh/internal/record"
)

type detReader struct{ rng *rand.Rand }

func (d detReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(d.rng.Intn(256))
	}
	return len(p), nil
}

func newServer(t *testing.T) (*Server, *node.Node) {
	t.Helper()
	n, err := node.Open(node.Config{
		Root:    t.TempDir(),
		ID:      "alpha",
		Clock:   clock.NewFake(1_757_700_000_000),
		Entropy: detReader{rng: rand.New(rand.NewSource(1))},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	if err := n.CreateSpace("user/cory"); err != nil {
		t.Fatal(err)
	}
	s := NewServer("memmesh", "test")
	Attach(s, n)
	return s, n
}

// exchange runs one request through the server and returns the parsed response.
func exchange(t *testing.T, s *Server, line string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := s.Serve(strings.NewReader(line+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("parse response %q: %v", out.String(), err)
	}
	return resp
}

func TestInitializeHandshake(t *testing.T) {
	s, _ := newServer(t)
	resp := exchange(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)

	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", resp)
	}
	if result["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v, want %s", result["protocolVersion"], ProtocolVersion)
	}
	caps, ok := result["capabilities"].(map[string]any)
	if !ok || caps["tools"] == nil {
		t.Errorf("server did not advertise tool support: %v", result)
	}
	if resp["id"] != float64(1) {
		t.Errorf("response id = %v, want the request id", resp["id"])
	}
}

func TestNotificationsGetNoReply(t *testing.T) {
	s, _ := newServer(t)
	var out bytes.Buffer
	// No id means a notification, and JSON-RPC says notifications are not answered.
	if err := s.Serve(strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Errorf("a notification produced a reply: %s", out.String())
	}
}

func TestToolsListCoversTheFiveTools(t *testing.T) {
	s, _ := newServer(t)
	resp := exchange(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	result := resp["result"].(map[string]any)
	tools := result["tools"].([]any)

	want := map[string]bool{"remember": false, "recall": false, "forget": false, "link": false, "list_spaces": false}
	for _, raw := range tools {
		tool := raw.(map[string]any)
		name := tool["name"].(string)
		if _, expected := want[name]; expected {
			want[name] = true
		}
		if tool["description"] == "" {
			t.Errorf("tool %s has no description; the descriptions are what teach memory hygiene", name)
		}
		if tool["inputSchema"] == nil {
			t.Errorf("tool %s has no input schema", name)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("tool %s is missing", name)
		}
	}
	if len(tools) != 5 {
		t.Errorf("got %d tools, want exactly the 5 in the plan", len(tools))
	}
}

// TestRecallDescriptionTeachesConflictHandling guards a requirement that is easy to
// lose in a refactor: returning siblings to an agent that does not know they are
// siblings is worse than returning one wrong answer (plan §6.2).
func TestRecallDescriptionTeachesConflictHandling(t *testing.T) {
	s, _ := newServer(t)
	var recall Tool
	for _, tool := range s.Tools() {
		if tool.Name == "recall" {
			recall = tool
		}
	}
	if recall.Name == "" {
		t.Fatal("no recall tool")
	}
	for _, phrase := range []string{"siblings", "evidence", "saw_this_claim", "more_siblings", "contradict"} {
		if !strings.Contains(recall.Description, phrase) {
			t.Errorf("the recall description does not mention %q, so a model would not know what to do with a conflict block", phrase)
		}
	}
}

func TestRememberAndRecallOverMCP(t *testing.T) {
	s, _ := newServer(t)

	resp := exchange(t, s, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"remember","arguments":{"space":"user/cory","body":"parse_ts assumes UTC input","kind":"fact","evidence":"observed","tags":["parse_ts"],"agent":"crew-1"}}}`)
	result := resp["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("remember failed: %v", result["content"])
	}
	structured := result["structuredContent"].(map[string]any)
	if structured["id"] == nil || structured["kind"] != "fact" {
		t.Fatalf("remember returned %v", structured)
	}

	resp = exchange(t, s, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"recall","arguments":{"query":"timezone assumption parse_ts"}}}`)
	result = resp["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("recall failed: %v", result["content"])
	}
	recall := result["structuredContent"].(map[string]any)
	hits := recall["hits"].([]any)
	if len(hits) == 0 {
		t.Fatal("recall over MCP returned nothing")
	}
	hit := hits[0].(map[string]any)
	if !strings.Contains(hit["body"].(string), "parse_ts") {
		t.Errorf("top hit body = %v", hit["body"])
	}
	if hit["provenance"] == nil {
		t.Error("a hit came back without provenance")
	}

	// The text content must carry the same thing, since some clients only read that.
	content := result["content"].([]any)
	if len(content) == 0 || !strings.Contains(content[0].(map[string]any)["text"].(string), "parse_ts") {
		t.Error("the text content does not carry the result")
	}
}

func TestToolFailuresComeBackAsResults(t *testing.T) {
	s, _ := newServer(t)
	// A space that does not exist is a normal mistake, and the model should see it
	// rather than the transport swallowing it.
	resp := exchange(t, s, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"remember","arguments":{"space":"user/nope","body":"x"}}}`)
	if resp["error"] != nil {
		t.Fatalf("a tool failure became a protocol error: %v", resp["error"])
	}
	result := resp["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("a failing tool was not marked isError: %v", result)
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "no such space") {
		t.Errorf("the error text does not say what went wrong: %q", text)
	}
}

func TestProtocolErrors(t *testing.T) {
	s, _ := newServer(t)
	tests := []struct {
		name string
		line string
		code float64
	}{
		{"bad jsonrpc version", `{"jsonrpc":"1.0","id":1,"method":"ping"}`, codeInvalidRequest},
		{"unknown method", `{"jsonrpc":"2.0","id":1,"method":"nope"}`, codeMethodNotFound},
		{"unknown tool", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope"}}`, codeInvalidParams},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := exchange(t, s, tc.line)
			errObj, ok := resp["error"].(map[string]any)
			if !ok {
				t.Fatalf("no error in %v", resp)
			}
			if errObj["code"] != tc.code {
				t.Errorf("code = %v, want %v", errObj["code"], tc.code)
			}
		})
	}
}

func TestMalformedLineDoesNotKillTheStream(t *testing.T) {
	s, _ := newServer(t)
	var out bytes.Buffer
	input := "not json\n" + `{"jsonrpc":"2.0","id":9,"method":"ping"}` + "\n"
	if err := s.Serve(strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d responses, want a parse error followed by the ping reply: %s", len(lines), out.String())
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first["error"] == nil {
		t.Error("the malformed line did not produce an error response")
	}
	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if second["result"] == nil {
		t.Error("the stream did not continue after a malformed line")
	}
}

func TestForgetAndLinkOverMCP(t *testing.T) {
	s, n := newServer(t)

	first, err := n.Remember(node.RememberRequest{Space: "user/cory", Kind: record.KindFact, Body: "the parser reads ISO-8601"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := n.Remember(node.RememberRequest{Space: "user/cory", Kind: record.KindEpisode, Body: "found it while chasing a flake"})
	if err != nil {
		t.Fatal(err)
	}

	link := exchange(t, s, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"link","arguments":{"space":"user/cory","ids":["`+
		first.ID.String()+`","`+second.ID.String()+`"],"note":"the fact came from this episode"}}}`)
	if link["result"].(map[string]any)["isError"] == true {
		t.Fatalf("link failed: %v", link)
	}

	forget := exchange(t, s, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"forget","arguments":{"space":"user/cory","id":"`+
		first.ID.String()+`","reason":"it reads RFC-3339, not ISO-8601"}}}`)
	result := forget["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatalf("forget failed: %v", result)
	}
	if result["structuredContent"].(map[string]any)["kind"] != "retraction" {
		t.Errorf("forget with a reason produced %v, want a retraction", result["structuredContent"])
	}

	// A malformed id must be reported, not silently ignored.
	bad := exchange(t, s, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"forget","arguments":{"space":"user/cory","id":"not-a-ulid"}}}`)
	if bad["result"].(map[string]any)["isError"] != true {
		t.Error("a malformed record id was accepted")
	}
}

func TestListSpacesOverMCP(t *testing.T) {
	s, _ := newServer(t)
	resp := exchange(t, s, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"list_spaces","arguments":{}}}`)
	structured := resp["result"].(map[string]any)["structuredContent"].(map[string]any)
	if structured["node"] != "alpha" {
		t.Errorf("node = %v", structured["node"])
	}
	spaces := structured["spaces"].([]any)
	if len(spaces) != 1 {
		t.Fatalf("got %d spaces", len(spaces))
	}
	space := spaces[0].(map[string]any)
	if space["space"] != "user/cory" || space["readable"] != true {
		t.Errorf("space = %v", space)
	}
	if space["conflict_policy"] != "siblings-auto" {
		t.Errorf("policy = %v, want siblings-auto for a user/* space", space["conflict_policy"])
	}
	if structured["embed_model"] == "" {
		t.Error("list_spaces does not report the embedding model")
	}
}

func TestSchemasAreValidJSON(t *testing.T) {
	s, _ := newServer(t)
	for _, tool := range s.Tools() {
		var parsed any
		if err := json.Unmarshal(tool.InputSchema, &parsed); err != nil {
			t.Errorf("tool %s has an invalid input schema: %v", tool.Name, err)
		}
	}
}
