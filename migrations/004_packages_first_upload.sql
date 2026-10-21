-- Fourth migration: remember when each package first appeared on PyPI.
--
-- The new_package rule needs a package's age. Working it out means downloading
-- the package's whole history from PyPI (/pypi/<name>/json), which is several MB
-- for big projects like boto3. The first upload never changes, so the worker
-- fetches it once per package and stores it here.
--
--   packages
--   ┌──────────────────────────────────────────────┐
--   │ ...                                          │
--   │ first_uploaded_at  timestamptz  NULL until   │
--   │                                 fetched      │
--   └──────────────────────────────────────────────┘
--
-- NULL means "not looked up yet" (or the package has no files on PyPI at all).

ALTER TABLE packages ADD COLUMN first_uploaded_at timestamptz;
