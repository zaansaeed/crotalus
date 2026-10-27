package main

import (
	"time"
)

type FlaggedRelease struct {
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Score        int       `json:"score"`
	RulesVerdict string    `json:"rules_verdict"`
	LLMVerdict   *string   `json:"llm_verdict"`   // NULL until triaged
	FinalVerdict string    `json:"final_verdict"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
}
