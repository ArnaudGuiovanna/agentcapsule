-- Registry credentials (REG-02): an import the registry refuses (private
-- repository, missing or wrong credentials) is rejected as access_denied
-- instead of being retried as unavailable.
ALTER TABLE harness_imports DROP CONSTRAINT harness_imports_error_code_check,
  ADD CONSTRAINT harness_imports_error_code_check CHECK (error_code IN
    ('','policy','not_found','access_denied','integrity','version_conflict','unavailable'));
