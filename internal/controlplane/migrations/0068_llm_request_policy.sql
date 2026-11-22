-- An alias's request policy (v0.1.0 audit, findings S-11 and S-13). A
-- forwarded request passes with its dialect's plain fields and the client's
-- own tools only; the organization names the other top-level fields and tool
-- types the alias allows (a provider-executed tool, a cost-changing option).
-- A call that declares no output cap is held to max_output_tokens (null: the
-- platform's default), written into the request in output_cap_field, and
-- reserved. Existing aliases allow nothing more, and keep the default cap.
-- Adding columns with constant defaults rewrites no row; the checks scan the
-- aliases, a small table.
ALTER TABLE llm_model_aliases
  ADD COLUMN allowed_fields text[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(allowed_fields) <= 32 AND array_position(allowed_fields, NULL) IS NULL
      AND array_to_string(allowed_fields, ' ') ~ '^[a-z0-9_ ]*$'),
  ADD COLUMN allowed_tool_types text[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(allowed_tool_types) <= 32 AND array_position(allowed_tool_types, NULL) IS NULL
      AND array_to_string(allowed_tool_types, ' ') ~ '^[a-z0-9_ ]*$'),
  ADD COLUMN max_output_tokens integer CHECK (max_output_tokens BETWEEN 1 AND 1000000),
  ADD COLUMN output_cap_field text NOT NULL DEFAULT 'max_tokens' CHECK (output_cap_field IN ('max_tokens','max_completion_tokens'));

ALTER TABLE llm_audit
  DROP CONSTRAINT llm_audit_action_check,
  ADD CONSTRAINT llm_audit_action_check CHECK (action IN ('provider.created','provider.rotated','provider.disabled','alias.created','alias.disabled',
    'budget.created','budget.disabled','alias.access_set','alias.prices_set','alias.grant_created','alias.grant_revoked','usage.settled','usage.released',
    'alias.operations_set','alias.request_policy_set'));
