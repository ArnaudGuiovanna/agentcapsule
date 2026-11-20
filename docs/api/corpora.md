# Corpora

An organization can build a GitHub or GitLab repository into a read-only corpus, review its contents and mount a published version in an agent. These operations use the same HTTPS API from any programming language. Each mutation requires an `Idempotency-Key`. Repeating a request with its original key returns its receipt.

1. Declare the repository with `POST /v1/corpora`. Supply a name and a source containing `kind`, `url` and `ref`. To use a private repository, create a source credential for that forge first and supply its `credential_id`. A relative `path` selects a subtree.
2. Send `POST /v1/corpora/{id}/builds` with `{}`, a single `ref` or a 40-character lowercase `commit`. The response is HTTP 202 with a build ID. Poll `GET /v1/corpus-builds/{id}` until it reaches `REVIEW` or a terminal state. Each organization runs one build at a time.
3. List review files with `GET /v1/corpus-builds/{id}/review`. Read the index at `GET /v1/corpus-builds/{id}/review-file?path=INDEX.md`. The listing includes the size and SHA-256 of each file and a `truncated` flag. To try the image on an agent, send its `agent_id` and an optional `mount` to `POST /v1/corpus-builds/{id}/try`.
4. Publish with `POST /v1/corpus-builds/{id}/publish` and a positive integer `version`. A new version returns 201. An existing version with the same image digest returns 200. A different digest at that version returns 409 with `version_conflict`.
5. Replace an agent's corpus list with `POST /v1/agents/{id}/corpora`. The body contains `corpora`, an ordered array of up to four objects with `name`, `version` and optional `mount`. An empty array removes all mounts. The bindings take effect on the next boot under `/corpus/<mount>`. The system image must support `corpus.mount` and the harness must support the corpus mount point.

Creating, reviewing and publishing require `corpus:manage`. Metadata reads use `corpus:read`. A try also requires `agent:manage`. Listing an agent's bindings requires `agent:read` and replacing them requires `agent:manage`, both with `corpus:read`. The API returns 404 for a resource in another organization. [Authorization matrix](rbac.md)

Cancel a build with `POST /v1/corpus-builds/{id}/cancel`. Cancellation or expiry removes the review bundle and trial bindings. Builds have a 24-hour deadline and reviews expire after 30 days. Deprecating a release prevents new bindings while existing ones continue to pin the image. The API exposes the complete request and response schemas in its [OpenAPI contract](../../openapi/openapi.yaml).

[Build, review and publish with the CLI](../cli.md#build-and-publish-a-corpus)

### Enrichment

An organization owner or administrator with `corpus:manage` authorizes a signed
OCI release of guest base 2 with `POST /v1/corpus-enrichers`. The request holds
`name` and `harness` (its published name and version). The response includes the
immutable artifact digest and the signing key verified at import.
`GET /v1/corpus-enrichers` lists the organization's authorizations.

While a build is in `REVIEW`, post `{"enricher_id":"cen_…"}` to
`/v1/corpus-builds/{id}/extensions`. The receipt links the job through its
`id`. Read it with `GET /v1/corpus-extensions/{id}`, or list the build's
extensions with `GET /v1/corpus-builds/{id}/extensions`.
The worker provisions a separate private guest for this authorization, with
the reviewed base at `/corpus/base` and a private output at
`/dev/corpus/output`. Instructions and results use the regular harness JSON
content part and the schema `agentcapsule.corpus-enricher/v1`:

```json
{"schema":"agentcapsule.corpus-enricher/v1","build_id":"cbd_…","name":"references","mount":"/corpus/base","uuid":"…","output":{"bytes":67108864}}
```

The harness writes a clean ext4 image with the supplied UUID and label
`corpus`, then returns its exact byte length in
`{"schema":"agentcapsule.corpus-enricher/v1","image_bytes":5242880}`.
The worker stops the guest, inspects the image and checks storage quotas.
A failed job can be retried with a fresh idempotency key. Publication requires
every requested extension to be `READY` and snapshots their names, digests,
UUIDs and sizes. A conflicting snapshot under an existing version returns 409.
A release can contain up to four extensions per base. The system image used
by enrichment and by consumers of enriched releases must declare both
`corpus.mount` and `corpus.extensions`. At boot the guest checks disk order
and UUIDs, then mounts each extension read-only at
`/corpus/<mount>/ext/<name>/`.
