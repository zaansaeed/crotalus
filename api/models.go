package main

import (
	"encoding/json"
	"time"
)

// One release and its verdicts. Used on its own by /flagged, and embedded in
// ReleaseDetail by /releases/{name}/{version}.
type Release struct {
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Score        int       `json:"score"`
	RulesVerdict string    `json:"rules_verdict"`
	LLMVerdict   *string   `json:"llm_verdict"` // NULL until triaged
	FinalVerdict string    `json:"final_verdict"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
}

type Finding struct {
	RuleID   string          `json:"rule_id"`
	Severity string          `json:"severity"`
	Message  string          `json:"message"`
	Evidence json.RawMessage `json:"evidence"` // jsonb: already JSON, written out as-is
}

// The LLM's answer. Only 'done' triage rows are shown, and those always have a
// verdict, confidence and reasoning, so none of these need to be pointers.
type Triage struct {
	Model              string   `json:"model"`
	PromptVersion      string   `json:"prompt_version"`
	Verdict            string   `json:"verdict"`
	Confidence         float32  `json:"confidence"`
	Reasoning          string   `json:"reasoning"`
	FalsePositiveRules []string `json:"false_positive_rules"`
}

type ReleaseDetail struct {
	Release            // embedded: its fields are part of this struct and its JSON
	Findings []Finding `json:"findings"`
	Triage   *Triage   `json:"triage"` // nil when not triaged → null
}
