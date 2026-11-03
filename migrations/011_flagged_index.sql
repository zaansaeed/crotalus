-- Eleventh migration: an index for the API's /flagged, the newest flagged releases.
--
--   SELECT ... FROM releases WHERE final_verdict IN ('suspicious', 'likely_malicious')
--   ORDER BY first_seen_at DESC LIMIT 50
--
-- Without it, Postgres reads every release (~10k more a day), keeps the flagged
-- ~2%, and sorts them, just to return 50. With it, it reads the index from the
-- newest end and stops after 50.

CREATE INDEX releases_flagged_first_seen_idx ON releases (first_seen_at)
    WHERE final_verdict IN ('suspicious', 'likely_malicious');
