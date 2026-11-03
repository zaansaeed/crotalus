-- Tenth migration: a read-only database role for the public API.
--
-- The API only reads, so it connects as crotalus_api instead of crotalus: if it were
-- ever exploited, it could read what the API already shows, but not change or
-- delete anything. And the database itself cancels any query of this role that runs
-- over 5 seconds, so a slow query can't tie up connections the worker needs.
--
--   crotalus_api   SELECT on packages, releases, findings, triage; nothing els

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'crotalus_api') THEN
        CREATE ROLE crotalus_api LOGIN PASSWORD 'crotalus_api';
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO crotalus_api;
GRANT SELECT ON packages, releases, findings, triage TO crotalus_api;

ALTER ROLE crotalus_api SET statement_timeout = '5s';
