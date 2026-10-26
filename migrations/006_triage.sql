-- Sixth migration: triage. One row is the LLM's second opinion on a flagged release.
--
-- Only releases the rules scored 'suspicious' or 'likely_malicious' are triaged
-- (see triage.py). The rules' verdict on releases is never overwritten: keeping both
-- is what lets the eval compare rules-only against rules + LLM.
--
--   releases                     triage
--   ┌──────────────────┐         ┌────────────────────────────────────────────────┐
--   │ id  bigint  PK   │◄────────│ release_id            bigint     FK            │
--   │ verdict          │  1 : N  │ id                    bigint     PK            │
--   │ ...              │         │ model                 text       which LLM     │
--   └──────────────────┘         │ prompt_version        text       e.g. 'v1'     │
--                                │ status                'done' | 'failed'        │
--                                │ verdict               'benign' | 'suspicious'  │
--                                │                       | 'malicious'            │
--                                │ confidence            real       0 to 1        │
--                                │ reasoning             text       for humans    │
--                                │ false_positive_rules  text[]     rule_ids      │
--                                │ error                 text       if failed     │
--                                │ created_at            timestamptz              │
--                                └────────────────────────────────────────────────┘
--
-- 1 : N because the same release can be triaged by different models and prompts, to
-- compare them. At most one row per (release, model, prompt_version).
--
-- 'failed': the model answered, but not in the format asked for. Kept so the triager
-- doesn't spend its rate limit retrying the same release; delete the row to retry.
-- (Rate limits and outages aren't stored: the triager backs off and tries again.)

CREATE TABLE triage (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    release_id bigint NOT NULL REFERENCES releases (id),
    model text NOT NULL, -- e.g. 'gemini-flash-lite-latest'
    prompt_version text NOT NULL, -- triage.PROMPT_VERSION when this row was made
    status text NOT NULL CHECK (status IN ('done', 'failed')),

    -- Set when done, NULL when failed.
    verdict text CHECK (verdict IN ('benign', 'suspicious', 'malicious')),
    confidence real CHECK (confidence BETWEEN 0 AND 1),
    reasoning text,
    false_positive_rules text[] NOT NULL DEFAULT '{}',

    error text, -- set when failed: what was wrong with the answer
    created_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT triage_release_model_prompt_unique UNIQUE (release_id, model, prompt_version),
    -- done <=> has an answer; failed <=> has an error.
    CONSTRAINT triage_answer_iff_done CHECK (
        (status = 'done') = (verdict IS NOT NULL AND confidence IS NOT NULL AND reasoning IS NOT NULL)
    ),
    CONSTRAINT triage_error_iff_failed CHECK ((status = 'failed') = (error IS NOT NULL))
);

-- No separate index on release_id: the UNIQUE constraint's index starts with
-- release_id, so "triage rows for release X" already uses it.
