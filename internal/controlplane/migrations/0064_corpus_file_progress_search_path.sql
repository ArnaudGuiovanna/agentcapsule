-- Resolve the build for a progress notification in the schema of this
-- installation, including for writes from sessions with a different search path.
ALTER FUNCTION corpus_notify_file_progress() SET search_path FROM CURRENT;
