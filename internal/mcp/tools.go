package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/coryforsythe/memmesh/internal/node"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/ulid"
)

// The tool descriptions below are load-bearing, not documentation.
//
// The tools alone do not produce good memory hygiene (plan §7.1). A model that can
// call `remember` will write episodes and never promote them, will claim `observed`
// for things it inferred, and will treat a conflict block as noise to pick from. What
// stops that is being told, here, at the point of use — reinforced by the SKILL.md
// shipped in M6.

// Attach registers the five tools against a node.
func Attach(s *Server, n *node.Node) {
	s.Register(Tool{
		Name: "remember",
		Description: `Write a memory that outlives this session.

Default to kind "episode": what happened, concretely, with enough detail that someone
reading it cold could act on it. A background distiller promotes episodes into durable
facts and procedures later, so you do not need to decide what is worth keeping — write
the episode and let promotion happen.

Write kind "fact" only for a claim you would defend, and "procedure" only for how
things are actually done here.

Set evidence honestly, because it outranks recency when two memories contradict:
  observed  — you saw the transcript, command output or file content that backs this
  asserted  — you believe it but have not shown the backing (the default)
  derived   — you concluded it from other memories

Claiming "observed" for something you inferred corrupts conflict resolution for
everyone, and it is not recoverable by anyone reading later.

Tags are how you make a memory findable by words its body never uses.`,
		InputSchema: schema(`{
  "type": "object",
  "properties": {
    "space":      {"type": "string", "description": "Space to write to, e.g. user/cory or shared/crew"},
    "body":       {"type": "string", "description": "The memory itself"},
    "kind":       {"type": "string", "enum": ["episode","fact","procedure","artifact_ref"], "description": "Defaults to episode"},
    "tags":       {"type": "array", "items": {"type": "string"}},
    "evidence":   {"type": "string", "enum": ["observed","asserted","derived"], "description": "Defaults to asserted"},
    "supersedes": {"type": "array", "items": {"type": "string"}, "description": "Record ids this replaces"},
    "refs":       {"type": "array", "items": {"type": "string"}, "description": "Related record ids, without replacing them"},
    "agent":      {"type": "string", "description": "Your agent name, so your writes are attributable to you rather than to a shared default"}
  },
  "required": ["space","body"]
}`),
		Handler: func(params json.RawMessage) (any, error) {
			var in struct {
				Space      record.SpaceID  `json:"space"`
				Body       string          `json:"body"`
				Kind       record.Kind     `json:"kind"`
				Tags       []string        `json:"tags"`
				Evidence   record.Evidence `json:"evidence"`
				Supersedes []string        `json:"supersedes"`
				Refs       []string        `json:"refs"`
				Agent      string          `json:"agent"`
			}
			if err := decode(params, &in); err != nil {
				return nil, err
			}
			supersedes, err := parseIDs(in.Supersedes, "supersedes")
			if err != nil {
				return nil, err
			}
			refs, err := parseIDs(in.Refs, "refs")
			if err != nil {
				return nil, err
			}
			return n.Remember(node.RememberRequest{
				Agent:      in.Agent,
				Space:      in.Space,
				Kind:       in.Kind,
				Body:       in.Body,
				Tags:       in.Tags,
				Evidence:   in.Evidence,
				Supersedes: supersedes,
				Refs:       refs,
			})
		},
	})

	s.Register(Tool{
		Name: "recall",
		Description: `Search memory before you start work, not after you are stuck.

Results carry full provenance: which agent wrote it, on which machine, how well
backed it is, and when.

IMPORTANT — a hit may carry "siblings". Those are memories that contradict it and are
equally current. Both are real, both are signed, and neither has been resolved. Do
not silently pick one.

When you see siblings:
  - Weigh them by evidence first (observed > asserted > derived), then by recency.
  - Check "saw_this_claim" on each sibling. True means that author had already seen
    the memory they contradict — a considered disagreement. False means they wrote
    without knowing about it, which is ignorance rather than dispute, and much weaker
    grounds for preferring them.
  - Look for a missing qualifier before assuming anyone is wrong. "parse_ts assumes
    UTC" and "parse_ts assumes local time" are often both true in different repos, and
    the right move is to write two scoped facts, not to pick a winner.
  - Say in your answer that the memories disagree. Presenting one side as settled fact
    is worse than saying you found a contradiction.
  - If "more_siblings" is non-zero, the claim is contested beyond what is shown and
    needs a human to adjudicate. Say so.

A hit marked superseded, with retractions attached, has already been corrected. Read
the retraction text: it says why.`,
		InputSchema: schema(`{
  "type": "object",
  "properties": {
    "query":              {"type": "string"},
    "spaces":             {"type": "array", "items": {"type": "string"}, "description": "Defaults to every readable space"},
    "limit":              {"type": "integer"},
    "kinds":              {"type": "array", "items": {"type": "string", "enum": ["episode","fact","procedure","artifact_ref","retraction"]}},
    "tags":               {"type": "array", "items": {"type": "string"}, "description": "A hit must carry all of these"},
    "include_superseded": {"type": "boolean", "description": "Surface memories that have been replaced; useful for reconstructing what a space used to say"},
    "min_score":          {"type": "number"}
  },
  "required": ["query"]
}`),
		Handler: func(params json.RawMessage) (any, error) {
			var in struct {
				Query             string           `json:"query"`
				Spaces            []record.SpaceID `json:"spaces"`
				Limit             int              `json:"limit"`
				Kinds             []record.Kind    `json:"kinds"`
				Tags              []string         `json:"tags"`
				IncludeSuperseded bool             `json:"include_superseded"`
				MinScore          float32          `json:"min_score"`
			}
			if err := decode(params, &in); err != nil {
				return nil, err
			}
			return n.Recall(node.RecallRequest{
				Query:             in.Query,
				Spaces:            in.Spaces,
				Limit:             in.Limit,
				Kinds:             in.Kinds,
				Tags:              in.Tags,
				IncludeSuperseded: in.IncludeSuperseded,
				MinScore:          in.MinScore,
			})
		},
	})

	s.Register(Tool{
		Name: "forget",
		Description: `Stop a memory from surfacing.

This never erases anything. Memory is append-only: the original stays on disk, stays
verifiable, and stays reachable by id. What changes is that recall no longer returns
it. If you need to tell someone their data was deleted, this is not that.

Pass "reason" whenever you have one. With a reason this writes a retraction, which
preserves the correction — future readers see both the claim and why it changed.
Without one it writes a tombstone, which says only "this should not be here" and
loses the fact that anyone ever believed it.

Prefer a reason. Almost always, the reason is the valuable part.`,
		InputSchema: schema(`{
  "type": "object",
  "properties": {
    "space":  {"type": "string"},
    "id":     {"type": "string", "description": "Record id to stop surfacing"},
    "reason": {"type": "string", "description": "Why it was wrong. Writes a retraction instead of a tombstone."},
    "agent":  {"type": "string"}
  },
  "required": ["space","id"]
}`),
		Handler: func(params json.RawMessage) (any, error) {
			var in struct {
				Space  record.SpaceID `json:"space"`
				ID     string         `json:"id"`
				Reason string         `json:"reason"`
				Agent  string         `json:"agent"`
			}
			if err := decode(params, &in); err != nil {
				return nil, err
			}
			id, err := ulid.Parse(in.ID)
			if err != nil {
				return nil, fmt.Errorf("id: %w", err)
			}
			return n.Forget(node.ForgetRequest{Agent: in.Agent, Space: in.Space, ID: id, Reason: in.Reason})
		},
	})

	s.Register(Tool{
		Name: "link",
		Description: `Record that memories belong together, without replacing any of them.

Use it when two memories are about the same thing and a future reader would want both
— an episode and the fact distilled from it, a bug and the fix, a decision and the
constraint that forced it.

This is not how you mark a contradiction. Contradictions are detected in the
background and surfaced as siblings; a link says "related", not "in tension".`,
		InputSchema: schema(`{
  "type": "object",
  "properties": {
    "space": {"type": "string"},
    "ids":   {"type": "array", "items": {"type": "string"}, "minItems": 2},
    "note":  {"type": "string", "description": "Why these belong together"},
    "agent": {"type": "string"}
  },
  "required": ["space","ids"]
}`),
		Handler: func(params json.RawMessage) (any, error) {
			var in struct {
				Space record.SpaceID `json:"space"`
				IDs   []string       `json:"ids"`
				Note  string         `json:"note"`
				Agent string         `json:"agent"`
			}
			if err := decode(params, &in); err != nil {
				return nil, err
			}
			ids, err := parseIDs(in.IDs, "ids")
			if err != nil {
				return nil, err
			}
			return n.Link(node.LinkRequest{Agent: in.Agent, Space: in.Space, IDs: ids, Note: in.Note})
		},
	})

	s.Register(Tool{
		Name: "list_spaces",
		Description: `List the memory spaces this node holds.

"readable: false" means the node stores and relays that space but holds no key for it.
It can tell you how many records and how many bytes, and nothing else — no bodies, no
tags, not even a title. Do not treat an empty search of a relayed space as evidence
that it contains nothing.

Conflict policy differs by space class and is worth knowing before you write:
  agent/*   private to one agent; last write wins, no ceremony
  user/*    one person's spaces; contradictions are detected and may auto-resolve
  shared/*  crosses a trust boundary; contradictions are NEVER auto-resolved`,
		InputSchema: schema(`{"type": "object", "properties": {}}`),
		Handler: func(json.RawMessage) (any, error) {
			return map[string]any{
				"node":        string(n.ID()),
				"spaces":      n.ListSpaces(),
				"embed_model": n.Embedder().ModelID(),
				"relaying":    n.Relaying(),
				"warm":        n.Warm(),
			}, nil
		},
	})
}

func schema(s string) json.RawMessage {
	var check any
	if err := json.Unmarshal([]byte(s), &check); err != nil {
		// A malformed schema literal is a programming error, and it should not be
		// discovered by a client at runtime.
		panic(fmt.Sprintf("mcp: invalid tool schema: %v", err))
	}
	return json.RawMessage(s)
}

func decode(params json.RawMessage, into any) error {
	if len(params) == 0 {
		return nil
	}
	if err := json.Unmarshal(params, into); err != nil {
		return fmt.Errorf("bad arguments: %w", err)
	}
	return nil
}

func parseIDs(in []string, field string) ([]ulid.ULID, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]ulid.ULID, 0, len(in))
	for _, s := range in {
		id, err := ulid.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		out = append(out, id)
	}
	return out, nil
}
