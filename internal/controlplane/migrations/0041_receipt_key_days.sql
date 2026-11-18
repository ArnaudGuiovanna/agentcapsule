-- The daily receipt keys (docs/adr/006-authority-service.md §7, wave 6). A
-- receipt encrypted with the daily key of the authority service names that
-- day (UTC). NULL is the installation's receipt key: every receipt written
-- before this migration, and those of an API without the authority service
-- (development). They stay readable until they expire, 24 hours after they
-- were written.
ALTER TABLE http_receipts ADD COLUMN key_day date;
ALTER TABLE tenant_http_receipts ADD COLUMN key_day date;
