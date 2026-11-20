-- The multimodal gateway (ADR 023 §12). An alias declares the operations its
-- model serves; a platform channel route it does not declare is refused before
-- any reservation. Existing aliases serve chat only. Audio is priced by the
-- minute and OCR by the page; a null price leaves that unit unpriced, so a
-- hard cost budget refuses its calls.
ALTER TABLE llm_model_aliases
  ADD COLUMN operations text[] NOT NULL DEFAULT '{chat}'
    CHECK (cardinality(operations) BETWEEN 1 AND 5 AND operations <@ '{chat,vision,embed,transcribe,ocr}'::text[]),
  ADD COLUMN audio_micro_per_minute bigint CHECK (audio_micro_per_minute BETWEEN 0 AND 1000000000000),
  ADD COLUMN ocr_micro_per_page bigint CHECK (ocr_micro_per_page BETWEEN 0 AND 1000000000000);

-- A call records its operation. An embedding counts input tokens only; a
-- transcription counts seconds of audio and an OCR call pages, never tokens:
-- token budgets do not count them. The reservation is the caller's declared
-- duration or page count, the settlement the provider's figure. A call keeps
-- the unit prices of its reservation, as it keeps its token prices; priced
-- says whether its own unit was priced.
ALTER TABLE llm_usage
  ADD COLUMN operation text NOT NULL DEFAULT 'chat' CHECK (operation IN ('chat','embed','transcribe','ocr')),
  ADD COLUMN reserved_audio_seconds bigint NOT NULL DEFAULT 0 CHECK (reserved_audio_seconds >= 0),
  ADD COLUMN reserved_pages integer NOT NULL DEFAULT 0 CHECK (reserved_pages >= 0),
  ADD COLUMN audio_seconds bigint CHECK (audio_seconds >= 0),
  ADD COLUMN pages integer CHECK (pages >= 0),
  ADD COLUMN audio_micro_per_minute bigint NOT NULL DEFAULT 0 CHECK (audio_micro_per_minute >= 0),
  ADD COLUMN ocr_micro_per_page bigint NOT NULL DEFAULT 0 CHECK (ocr_micro_per_page >= 0),
  DROP CONSTRAINT llm_usage_reserved_tokens_check,
  ADD CONSTRAINT llm_usage_reserved_tokens_check CHECK (reserved_tokens >= 0),
  ADD CONSTRAINT llm_usage_operation_units CHECK (CASE operation
    WHEN 'transcribe' THEN reserved_tokens = 0 AND reserved_audio_seconds > 0 AND reserved_pages = 0 AND pages IS NULL
      AND (state <> 'settled' OR (audio_seconds IS NOT NULL AND input_tokens = 0 AND output_tokens = 0))
    WHEN 'ocr' THEN reserved_tokens = 0 AND reserved_pages > 0 AND reserved_audio_seconds = 0 AND audio_seconds IS NULL
      AND (state <> 'settled' OR (pages IS NOT NULL AND input_tokens = 0 AND output_tokens = 0))
    ELSE reserved_tokens > 0 AND reserved_audio_seconds = 0 AND reserved_pages = 0 AND audio_seconds IS NULL AND pages IS NULL
      AND (operation = 'chat' OR state <> 'settled' OR output_tokens = 0) END);

ALTER TABLE llm_audit
  DROP CONSTRAINT llm_audit_action_check,
  ADD CONSTRAINT llm_audit_action_check CHECK (action IN ('provider.created','provider.rotated','provider.disabled','alias.created','alias.disabled',
    'budget.created','budget.disabled','alias.access_set','alias.prices_set','alias.grant_created','alias.grant_revoked','usage.settled','usage.released',
    'alias.operations_set'));
