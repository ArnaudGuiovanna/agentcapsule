# Embeddings, transcription and OCR on the platform channel (draft)

> **Draft, not served.** These routes are the contract of corpus lot 2
> ([ADR 023](../adr/023-corpora.md) §12). No platform channel serves them
> yet: a call today answers `not_found`. Lot 2 implements them, removes this
> notice, and moves the text into [api/llm.md](../api/llm.md#vm-bridge-cap-01)
> beside `/v1/llm/complete` and `/v1/llm/forward`.

A running capsule calls three more kinds of model through its authenticated
platform channel, never through the guest network. The builder agent of
corpora uses them, and so may any harness: query embeddings, for example.

| Route | Upstream request | Unit metered |
|---|---|---|
| `POST /v1/llm/embed` | OpenAI `POST /v1/embeddings` | input tokens |
| `POST /v1/llm/transcribe` | OpenAI `POST /v1/audio/transcriptions` | seconds of audio |
| `POST /v1/llm/ocr` | Mistral `POST /v1/ocr` | pages |

## What they share with `/v1/llm/complete`

- **Identity**: organization and agent come from the channel (the current
  boot's generation and VM), never from the body. A `tenant_id`,
  `provider_secret` or similar field is refused (`invalid`).
- **Capability**: `llm.invoke`, as the other model routes (ADR 016).
- **Policy**: the body names an alias of the organization; a listed alias
  serves only the agents it grants. The alias must declare the route's
  operation (`embed`, `transcribe` or `ocr`) in its `operations`, otherwise
  the call is refused before any reservation with `unsupported`.
- **Accounting**: a reservation before the call, the provider called outside
  the host lock, a settlement on the usage the provider reports. Budgets and
  prices of [ADR 011](../adr/011-llm-access-and-cost-budgets.md) apply, with
  the units below.
- **Idempotency**: the request's `idempotency_key` (at most 200 characters)
  is the ledger's key. A settled key never calls the provider again: the
  guest repeats the request with a new key. A cut after sending is
  `outcome_unknown`: the reservation keeps counting, do not retry with the
  same key.
- **Timeouts**: 300 s in total, as `complete`.
- **Size**: a request at most 960 KiB (the channel's message limit is
  1 MiB); a provider answer past 960 KiB was still produced and billed, so
  its outcome is `outcome_unknown`.
- **No decoding on the host.** The gateway checks base64 syntax and decoded
  sizes, never the audio or image itself. The duration and the page count of
  a reservation are the caller's declarations; the settlement uses the
  provider's figures.

## `POST /v1/llm/embed`

```json
{"alias": "embed", "input": ["What is the net present value?", "..."]}
```

- `input`: 1 to 64 strings, each 1 to 32 KiB of UTF-8.
- The gateway asks for `encoding_format: "base64"`, so vectors stay compact.
- Reservation: the body's size / 3 tokens; settlement: `usage.prompt_tokens`.

```json
{"embeddings": ["<base64 of little-endian float32>", "..."],
 "dimensions": 1536, "input_tokens": 18, "soft_budget_exceeded": false}
```

`embeddings` is in the order of `input`. Token budgets count `input_tokens`.

## `POST /v1/llm/transcribe`

```json
{"alias": "transcribe-fr", "audio": "<base64>", "format": "mp3",
 "duration_seconds": 290, "language": "fr", "prompt": "Corporate finance lecture"}
```

- `format`: `mp3`, `wav`, `flac`, `ogg`, `m4a` or `webm`; decoded `audio` at
  most 700 KiB; `duration_seconds` 1 to 600, declared by the caller (the
  builder cuts audio with ffmpeg in its VM to fit); `language` an optional
  ISO 639-1 code; `prompt` optional, at most 1,024 characters.
- The gateway builds the provider's multipart body from the JSON request,
  with `response_format: verbose_json` and segment timestamps.
- Reservation: `duration_seconds`; settlement: the provider's `duration`,
  rounded up to the second, or the reservation when it reports none.

```json
{"text": "...", "segments": [{"start": 0.0, "end": 4.2, "text": "..."}],
 "duration_seconds": 288, "soft_budget_exceeded": false}
```

Cost budgets count `duration_seconds` at the alias's
`audio_micro_per_minute`; token budgets do not count them. An alias without
that price is unpriced for this unit: a hard cost budget refuses the call
(`quota_exceeded`).

## `POST /v1/llm/ocr`

```json
{"alias": "ocr", "document": "<base64>", "media_type": "image/png", "pages": 1}
```

- `media_type`: `image/png`, `image/jpeg`, `image/webp` or `application/pdf`;
  decoded `document` at most 700 KiB; `pages` 1 to 8, declared by the caller.
- The provider must be an `openai_compatible` provider whose alias declares
  `ocr`; the gateway sends the document as a data URL.
- Reservation: `pages`; settlement: `usage_info.pages_processed`, or the
  reservation when the provider reports none.

```json
{"pages": [{"index": 0, "markdown": "..."}], "pages_processed": 1,
 "soft_budget_exceeded": false}
```

Cost budgets count pages at the alias's `ocr_micro_per_page`; token budgets
do not count them.

## Errors

Enumerated codes, never a provider message: those of `/v1/llm/complete`
(`quota_exceeded`, `rate_limited`, `rejected`, `outcome_unknown`,
`conflict`, `invalid`, `unauthorized`, `unavailable`, `capability_denied`),
and one more:

| Code | HTTP | When |
|---|---|---|
| `unsupported` | 400 | the alias does not declare the route's operation; refused before any reservation |

An older `capsule-init` maps a code it does not know to `unavailable`, as for
`capability_denied` (ADR 016).
