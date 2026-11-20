# Corpora

An organization can build a GitHub or GitLab repository into a read-only corpus, review its contents and mount a published version in an agent. These operations use the same HTTPS API from any programming language. Each mutation requires an `Idempotency-Key`. Repeating a request with its original key returns its receipt.

1. Declare the repository with `POST /v1/corpora`. Supply a name and a source containing `kind`, `url` and `ref`. To use a private repository, create a source credential for that forge first and supply its `credential_id`. A relative `path` selects a subtree.
2. Send `POST /v1/corpora/{id}/builds` with `{}`, a single `ref` or a 40-character lowercase `commit`. The response is HTTP 202 with a build ID. Poll `GET /v1/corpus-builds/{id}` until it reaches `REVIEW` or a terminal state. Each organization runs one build at a time.
3. List review files with `GET /v1/corpus-builds/{id}/review`. Read the index at `GET /v1/corpus-builds/{id}/review-file?path=INDEX.md`. The listing includes the size and SHA-256 of each file and a `truncated` flag. To try the image on an agent, send its `agent_id` and an optional `mount` to `POST /v1/corpus-builds/{id}/try`.
4. Publish with `POST /v1/corpus-builds/{id}/publish` and a positive integer `version`. A new version returns 201. An existing version with the same image digest returns 200. A different digest at that version returns 409 with `version_conflict`.
5. Replace an agent's corpus list with `POST /v1/agents/{id}/corpora`. The body contains `corpora`, an ordered array of up to four objects with `name`, `version` and optional `mount`. An empty array removes all mounts. The bindings take effect on the next boot under `/corpus/<mount>`. The system image must support `corpus.mount` and the harness must support the corpus mount point.

Creating, reviewing and publishing require `corpus:manage`. Metadata reads use `corpus:read`. A try also requires `agent:manage`. Listing an agent's bindings requires `agent:read` and replacing them requires `agent:manage`, both with `corpus:read`. The API returns 404 for a resource in another organization. [Authorization matrix](rbac.md)

Cancel a build with `POST /v1/corpus-builds/{id}/cancel`. Cancellation or expiry removes the review bundle and trial bindings. Builds have a 24-hour deadline and reviews expire after 30 days. Deprecating a release prevents new bindings while existing ones continue to pin the image. The API exposes the complete request and response schemas in its [OpenAPI contract](../../openapi/openapi.yaml).
