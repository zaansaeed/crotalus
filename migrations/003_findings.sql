-- Third migration: findings. One row is a some rule fired on some release.
--
-- The analyzer runs detection rules over each release. Every time a rule fires
-- it records a finding: which rule, how serious, and the evidence behind it.
-- A release with no findings had nothing flagged, thus nothing recorded.
--
--   releases                     findings
--   ┌──────────────────┐         ┌──────────────────────────────────────────┐
--   │ id  bigint  PK   │◄────────│ release_id   bigint       FK             │
--   │ ...              │  1 : N  │ id           bigint       PK             │
--   └──────────────────┘         │ rule_id      text         e.g. typosquat │
--                                │ severity     'low' | 'medium'            │
--                                │              | 'high' | 'critical'       │
--                                │ message      text         human summary  │
--                                │ evidence     jsonb        rule-specific  │
--                                │ created_at   timestamptz                 │
--                                └──────────────────────────────────────────┘
--
-- No UNIQUE (release_id, rule_id): one rule can fire several times on a release
-- (e.g. exec() in two different files). Re-analyzing a release should delete its
-- old findings and insert the new ones in the same transaction.

CREATE TABLE findings (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    release_id bigint NOT NULL REFERENCES releases (id),
    rule_id text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    message text NOT NULL, -- one line for humans, e.g. "name is 1 edit away from 'requests'"
    -- Shape depends on the rule, e.g. {"similar_to": "requests", "distance": 1}
    -- or {"file": "setup.py", "line": 12, "snippet": "exec(...)"}.
    evidence jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),

    --must be a proper rule id (<x>_<y>_<z> etc.)
    CONSTRAINT findings_rule_id_format CHECK (rule_id ~ '^[a-z0-9]+(_[a-z0-9]+)*$')
);

-- Postgres does not index foreign keys automatically. Without this, "all findings
-- for release X" scans the whole table.
CREATE INDEX findings_release_id_idx ON findings (release_id);
