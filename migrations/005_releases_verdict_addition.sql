-- 1. Releases analyzed before scoring existed have no verdict. Send them back to
--    the queue so they're re-analyzed and scored (and the CHECK below can hold).
UPDATE releases SET status = 'pending' WHERE status = 'done';

-- 2. The new columns. NULL until the release is analyzed.
ALTER TABLE releases
    ADD COLUMN score integer CHECK (score >= 0),
    ADD COLUMN verdict text CHECK (verdict IN ('clean', 'suspicious', 'likely_malicious'));

-- 3. done <=> has a score and verdict.
ALTER TABLE releases ADD CONSTRAINT releases_verdict_iff_done CHECK (
    (status = 'done') = (score IS NOT NULL AND verdict IS NOT NULL)
);