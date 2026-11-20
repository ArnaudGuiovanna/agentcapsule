ALTER TABLE llm_providers ADD COLUMN auth_mode text NOT NULL DEFAULT 'secret'
    CHECK (auth_mode IN ('secret','none'));
ALTER TABLE llm_providers ADD CONSTRAINT llm_provider_auth_material CHECK (
    (auth_mode <> 'none' OR octet_length(secret_ciphertext) = 0)
    AND (auth_mode <> 'secret' OR status <> 'active' OR octet_length(secret_ciphertext) > 0)
);
