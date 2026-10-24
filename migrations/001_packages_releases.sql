-- First migration, creating our two SQL tables: packages and releases. 
-- Packages: simple package names
-- Releases: specific versions for each package. id in packages is FK in Releases
            -- Releases can be discovered from the ingestor or from the external API
            -- Each release has a status of whether it has been looked at yet.
--
--   packages                                releases
--   ┌──────────────────────────────┐        ┌──────────────────────────────────────┐
--   │ id             bigint    PK  │◄───────│ package_id     bigint    FK          │
--   │ name           text UNIQUE   │ 1 : N  │ id             bigint    PK          │
--   │                (normalized)  │        │ version        text                  │
--   │ first_seen_at  timestamptz   │        │ published_at   timestamptz           │
--   └──────────────────────────────┘        │ first_seen_at  timestamptz           │
--                                           │ source         'rss' | 'on_demand'   │
--                                           │ status         'pending'             │
--                                           │                | 'analyzing'         │
--                                           │                | 'done' | 'failed'   │
--                                           │ UNIQUE (package_id, version)         │
--                                           └──────────────────────────────────────┘
--
--   One package has many releases; each release belongs to exactly one package.


-- This creates our package table. Stores the name of package and when it was first seen. 
-- Releases will point to some package in this table.
CREATE TABLE packages (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- PK
    -- PEP 503 normalized: lowercase alphanumeric chunks joined by single '-'.
    -- Must stay in sync with normalize_name() in pypi.py.
    name TEXT NOT NULL UNIQUE
        CONSTRAINT packages_name_normalized CHECK (name ~ '^[a-z0-9]+(-[a-z0-9]+)*$'), --start with <char/nums> (-<char/nums>) any num times.
                                                                                       --basically, must be PEP normalized.
    first_seen_at timestamptz NOT NULL DEFAULT now() -- if a time is not given, use the firs ttime
);


CREATE TABLE releases(
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    package_id bigint NOT NULL REFERENCES packages (id),
    version TEXT NOT NULL,
    published_at timestamptz NOT NULL, -- specific time this release was published
    first_seen_at timestamptz NOT NULL DEFAULT now(), -- the time crotalus discovered this release
    source text NOT NULL CHECK (source IN ('rss', 'on_demand')),-- 'rss': seen by the feed poller      
                                                                -- 'on_demand': fetched from PyPI's JSON API after a user lookup missed
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'analyzing', 'done', 'failed')),

    CONSTRAINT releases_package_version_unique UNIQUE (package_id, version)
);