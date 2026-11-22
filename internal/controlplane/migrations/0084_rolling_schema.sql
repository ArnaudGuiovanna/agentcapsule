-- The admin records an expand declaration in the same transaction as its
-- checksum. Only the schema owner can write this ledger. Existing migrations
-- require an exact match until an expand-aware binary has been deployed.
ALTER TABLE schema_migrations ADD COLUMN compatible_with_previous boolean NOT NULL DEFAULT false;
