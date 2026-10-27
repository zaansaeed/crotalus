package main

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The most recently seen releases whose final verdict is suspicious or worse.
func flaggedReleases(ctx context.Context, pool *pgxpool.Pool, limit int) ([]Release, error) {
	sql := `
		SELECT p.name, r.version, r.score, r.rules_verdict, r.llm_verdict,
		       r.final_verdict, r.first_seen_at
		FROM releases r JOIN packages p ON p.id = r.package_id
		WHERE r.final_verdict IN ('suspicious', 'likely_malicious')
		ORDER BY r.first_seen_at DESC
		LIMIT $1`
	rows, err := pool.Query(ctx, sql, limit) //limit here is the $1
	if err != nil {
		return nil, err // the handler decides what the client sees
	}
	defer rows.Close() //close the query when function ends

	// Empty list
	releases := []Release{}

	for rows.Next() {
		var r Release
		// one &field per column, in SELECT order
		err := rows.Scan(&r.Name, &r.Version, &r.Score, &r.RulesVerdict, &r.LLMVerdict,
			&r.FinalVerdict, &r.FirstSeenAt)
		if err != nil {
			return nil, err
		}
		releases = append(releases, r)
	}
	return releases, rows.Err() // an error that ended the loop early, or nil
}

func releaseDetail(ctx context.Context, pool *pgxpool.Pool, name string, version string) (*ReleaseDetail, error) {
	// Only 'done' releases: pending and failed ones have NULL score and verdicts,
	// which can't be scanned into Release's plain int and string fields.
	releaseSQL := `
		SELECT r.id, p.name, r.version, r.score, r.rules_verdict, r.llm_verdict,
		       r.final_verdict, r.first_seen_at
		FROM releases r JOIN packages p ON p.id = r.package_id
		WHERE p.name = $1 AND r.version = $2 AND r.status = 'done'`

	findingsSQL := `
		SELECT rule_id, severity, message, evidence
		FROM findings
		WHERE release_id = $1
		ORDER BY id`

	// The latest answer: a release can have several triage rows (one per model and
	// prompt version). Pick the latest one
	triageSQL := `
		SELECT model, prompt_version, verdict, confidence, reasoning, false_positive_rules
		FROM triage
		WHERE release_id = $1 AND status = 'done'
		ORDER BY created_at DESC
		LIMIT 1`

	// 1. The release. No row is returned as pgx.ErrNoRows, which the handler turns
	// into a 404. id is only needed for the next two queries, not the JSON.
	var id int64
	release := ReleaseDetail{Findings: []Finding{}} // empty, not nil: JSON [] instead of null
	err := pool.QueryRow(ctx, releaseSQL, name, version).Scan(&id, &release.Name, &release.Version,
		&release.Score, &release.RulesVerdict, &release.LLMVerdict, &release.FinalVerdict, &release.FirstSeenAt)
	if err != nil {
		return nil, err
	}

	// 2. Its findings.
	rows, err := pool.Query(ctx, findingsSQL, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var finding Finding
		if err := rows.Scan(&finding.RuleID, &finding.Severity, &finding.Message, &finding.Evidence); err != nil {
			return nil, err
		}
		release.Findings = append(release.Findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 3. Its latest triage. Not triaged is normal, not an error: Triage stays nil.
	var triage Triage
	err = pool.QueryRow(ctx, triageSQL, id).Scan(&triage.Model, &triage.PromptVersion, &triage.Verdict,
		&triage.Confidence, &triage.Reasoning, &triage.FalsePositiveRules)
	if errors.Is(err, pgx.ErrNoRows) {
		return &release, nil
	}
	if err != nil {
		return nil, err
	}
	release.Triage = &triage
	return &release, nil
}
