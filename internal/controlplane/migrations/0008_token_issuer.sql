-- Records which credential issued each user token. A service holding user:manage
-- can mint a token that opens the user's private content, so issuance must be
-- attributable. Existing rows keep NULL: their issuer was not recorded.
ALTER TABLE api_tokens ADD COLUMN issued_by_token_id text REFERENCES api_tokens(id);
