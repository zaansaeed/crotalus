-- Eighth migration: the LLM's verdict on the release row, next to the other two.
--
--   rules_verdict  what the rules' findings add up to
--   llm_verdict    the LLM's opinion behind the current final_verdict ('benign' |
--                  'suspicious' | 'malicious'). NULL when the LLM hasn't given one:
--                  the release was clean, is still waiting, or its triage failed.
--   final_verdict  the verdict to act on (scoring.final_verdict of the two above)
--
-- The triage table keeps every opinion (each model and prompt version, with its
-- reasoning). This column is the one that counts right now, so a release row
-- explains itself without a join. The triager sets it along with final_verdict;
-- the worker clears it when it re-analyzes a release (its triage is deleted then).

-- 1. The new column.
ALTER TABLE releases
    ADD COLUMN llm_verdict text CHECK (llm_verdict IN ('benign', 'suspicious', 'malicious'));

-- 2. Fill it in from each analyzed release's latest successful triage (the same one
--    migration 007 used for final_verdict).
UPDATE releases r SET llm_verdict = (
    SELECT t.verdict FROM triage t
    WHERE t.release_id = r.id AND t.status = 'done'
    ORDER BY t.created_at DESC
    LIMIT 1
)
WHERE r.status = 'done';

-- 3. Only an analyzed release can have the LLM's opinion.
ALTER TABLE releases ADD CONSTRAINT releases_llm_verdict_only_when_done CHECK (
    llm_verdict IS NULL OR status = 'done'
);
