package main

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The most recently seen releases whose final verdict is suspicious or worse.
func flaggedReleases(ctx context.Context, pool *pgxpool.Pool, limit int) ([]FlaggedRelease, error) {
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
	releases := []FlaggedRelease{}

	for rows.Next() {
		var r FlaggedRelease
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
