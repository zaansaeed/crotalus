-- Ninth migration: when each stage handled a release, for measuring speed.
--
--   published_at         PyPI's upload time (from the feed)
--   first_seen_at        when the poller stored it
--   analysis_started_at  when the worker claimed it (its transaction began)
--   analyzed_at          when the worker finished: findings and rules verdict stored
--   triaged_at           when the triager stored the LLM's verdict
--
-- So, per release: upload -> seen is the poller's delay, seen -> started the time in
-- the queue, started -> analyzed the analysis itself, and upload -> analyzed (or
-- triaged) the time to a verdict.
--
-- Releases analyzed before this migration have NULLs: their times weren't recorded.

ALTER TABLE releases
    ADD COLUMN analysis_started_at timestamptz,
    ADD COLUMN analyzed_at timestamptz,
    ADD COLUMN triaged_at timestamptz;
