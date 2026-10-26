-- Seventh migration: a release's final verdict, next to the rules' verdict.
--
-- A release now has two verdicts:
--   rules_verdict  what the rules' findings add up to (scoring.rules_verdict).
--                  Renamed from `verdict`, now that it isn't the only one.
--   final_verdict  the verdict to act on: rules_verdict, adjusted by the LLM's
--                  opinion where the policy allows (scoring.final_verdict).
--
-- The worker sets both to the rules' verdict. The triager later updates
-- final_verdict when the LLM has an opinion. Keeping both shows when, and how
-- often, the LLM changed the outcome.

-- 1. The rename. The CHECK on its values follows the column automatically.
ALTER TABLE releases RENAME COLUMN verdict TO rules_verdict;

-- 2. The new column. NULL until the release is analyzed.
ALTER TABLE releases
    ADD COLUMN final_verdict text CHECK (final_verdict IN ('clean', 'suspicious', 'likely_malicious'));

-- 3. Fill it in for releases already analyzed, using their latest successful triage.
--    The same policy as scoring.final_verdict: the LLM decides only 'suspicious' releases.
UPDATE releases r SET final_verdict = CASE
    WHEN r.rules_verdict = 'suspicious' AND latest.verdict = 'benign' THEN 'clean'
    WHEN r.rules_verdict = 'suspicious' AND latest.verdict = 'malicious' THEN 'likely_malicious'
    ELSE r.rules_verdict
END
FROM releases r2
LEFT JOIN LATERAL (
    SELECT t.verdict FROM triage t
    WHERE t.release_id = r2.id AND t.status = 'done'
    ORDER BY t.created_at DESC
    LIMIT 1
) latest ON true
WHERE r.id = r2.id AND r.status = 'done';

-- 4. done <=> has a score and both verdicts (replaces releases_verdict_iff_done).
ALTER TABLE releases DROP CONSTRAINT releases_verdict_iff_done;
ALTER TABLE releases ADD CONSTRAINT releases_verdicts_iff_done CHECK (
    (status = 'done')
    = (score IS NOT NULL AND rules_verdict IS NOT NULL AND final_verdict IS NOT NULL)
);
