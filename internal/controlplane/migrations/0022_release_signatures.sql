-- Publisher signatures (REG-009): a release records the publisher key whose
-- signature was verified at import, and an import refused for lack of a
-- trusted signature is rejected as 'signature'.
ALTER TABLE harness_releases
  ADD COLUMN signer text CHECK (signer IS NULL OR signer ~ '^sha256:[0-9a-f]{64}$');
ALTER TABLE harness_imports DROP CONSTRAINT harness_imports_error_code_check,
  ADD CONSTRAINT harness_imports_error_code_check CHECK (error_code IN
    ('','policy','not_found','access_denied','signature','integrity','version_conflict','unavailable'));
