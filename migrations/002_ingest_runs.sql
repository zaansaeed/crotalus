-- Second migration: ingest_runs, one row per RSS poll.
--
-- Records the poller's history: when each poll ran, how many feed entries it saw,
-- how many releases were new, and why it was skipped if it failed.
-- Uses:
--   - check the poller is still running (gaps between started_at values)
--   - spot missed releases: if new_releases is close to entries, more releases
--     arrived between polls than the feed holds, so some were probably lost
--
--   ingest_runs
--   ┌──────────────────────────────────────────┐
--   │ id            bigint       PK            │
--   │ started_at    timestamptz                │
--   │ entries       integer      NULL if failed│
--   │ new_releases  integer      NULL if failed│
--   │ error         text         NULL if ok    │
--   └──────────────────────────────────────────┘
--
-- Each row is either a successful poll (counts set, no error) or a failed one
-- (error set, no counts). The CHECK enforces that it's exactly one of the two.

CREATE TABLE ingest_runs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    started_at timestamptz NOT NULL DEFAULT now(), -- when the poll began; the poller should pass it in
    entries integer CHECK (entries >= 0),          -- items in the feed
    new_releases integer CHECK (new_releases >= 0), -- releases that weren't stored before
    error text,                                    -- why the poll was skipped

    CONSTRAINT ingest_runs_success_or_error CHECK (
        (error IS NULL AND entries IS NOT NULL AND new_releases IS NOT NULL)
        OR (error IS NOT NULL AND entries IS NULL AND new_releases IS NULL)
    ),
    CONSTRAINT ingest_runs_new_within_entries CHECK (new_releases <= entries)
);
